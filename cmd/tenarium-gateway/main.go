// Command tenarium-gateway is a forward-auth service for Envoy (ext_authz,
// HTTP service mode), NGINX (auth_request) and Traefik (ForwardAuth). It
// resolves the tenant of each request with pkg/tenantmw, enforces its
// status, features and rate limit, and answers with X-Tenant-* headers the
// proxy uses to route to the tenant's cell. See docs/gateway.md.
//
//	tenarium-gateway -config /etc/tenarium/gateway.yaml
//
// Endpoints: /check, /envoy, /nginx and /traefik (and paths below them),
// /healthz, /readyz and /metrics.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AimTune/tenarium/pkg/gateway"
	"github.com/AimTune/tenarium/pkg/tenantmw"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tenarium-gateway:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("tenarium-gateway", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("TENARIUM_GATEWAY_CONFIG"), "YAML configuration file")
	listen := fs.String("listen", "", "listen address (overrides listen)")
	tenariumURL := fs.String("tenarium-url", "", "Tenarium base URL (overrides tenarium.url)")
	redisAddr := fs.String("redis-addr", "", "Redis address (overrides redis.addr)")
	source := fs.String("source", "", "tenant source: redis or api (overrides source.type)")
	rateBackend := fs.String("rate-limit", "", "rate limit backend: off, local or redis (overrides rate_limit.backend)")
	logLevel := fs.String("log-level", "", "debug, info, warn or error (overrides log.level)")
	check := fs.Bool("check-config", false, "validate the configuration and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&cfg.Listen, *listen)
	set(&cfg.Tenarium.URL, *tenariumURL)
	set(&cfg.Redis.Addr, *redisAddr)
	set(&cfg.Source.Type, *source)
	set(&cfg.RateLimit.Backend, *rateBackend)
	set(&cfg.Log.Level, *logLevel)
	if err := cfg.finish(); err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	if *check {
		fmt.Println("configuration ok")
		return nil
	}
	logger := newLogger(cfg.Log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	app, err := build(ctx, cfg, logger, reg)
	if err != nil {
		return err
	}
	defer app.close()

	metrics := promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", app.ready)
	if cfg.MetricsListen == "" {
		mux.Handle("GET /metrics", metrics)
	}
	// The gateway endpoints bypass ServeMux: it would redirect the
	// unclean paths Envoy appends to the check prefix.
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gateway.Match(r.URL.EscapedPath()) {
			app.gw.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})

	servers := []*http.Server{{Addr: cfg.Listen, Handler: root, ReadHeaderTimeout: cfg.Timeouts.ReadHeader, IdleTimeout: cfg.Timeouts.Idle}}
	if cfg.MetricsListen != "" {
		mm := http.NewServeMux()
		mm.Handle("GET /metrics", metrics)
		servers = append(servers, &http.Server{Addr: cfg.MetricsListen, Handler: mm, ReadHeaderTimeout: cfg.Timeouts.ReadHeader})
	}
	errc := make(chan error, len(servers))
	for _, s := range servers {
		logger.Info("listening", "addr", s.Addr)
		go func() {
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), cfg.Timeouts.Shutdown)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(sctx)
	}
	return nil
}

type app struct {
	gw    *gateway.Gateway
	redis *redis.Client
}

func (a *app) close() {
	if a.redis != nil {
		_ = a.redis.Close()
	}
}

// ready reports 503 while Redis (when used) does not answer.
func (a *app) ready(w http.ResponseWriter, r *http.Request) {
	if a.redis != nil {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if err := a.redis.Ping(ctx).Err(); err != nil {
			http.Error(w, "redis unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	_, _ = w.Write([]byte("ok\n"))
}

// build wires the gateway from the configuration.
func build(ctx context.Context, cfg *Config, logger *slog.Logger, reg prometheus.Registerer) (*app, error) {
	a := &app{}
	if cfg.Redis.Addr != "" {
		opts := &redis.Options{Addr: cfg.Redis.Addr, Username: cfg.Redis.Username, Password: cfg.Redis.Password, DB: cfg.Redis.DB}
		if cfg.Redis.TLS {
			opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		a.redis = redis.NewClient(opts)
	}
	httpClient := &http.Client{Timeout: cfg.Tenarium.Timeout}
	var api *tenantmw.Client
	if cfg.Tenarium.URL != "" {
		api = tenantmw.NewClient(cfg.Tenarium.URL, cfg.Tenarium.APIKey, tenantmw.WithHTTPClient(httpClient))
	}

	var src tenantmw.Source
	switch cfg.Source.Type {
	case "redis":
		src = tenantmw.RedisSource(a.redis, cfg.Redis.Prefix)
	default:
		src = api
	}
	if cfg.Source.CacheTTL > 0 {
		cs := tenantmw.CachingSource(src, cfg.Source.CacheTTL).SetNegativeTTL(max(cfg.Source.NegativeTTL, 0))
		if cfg.Source.MaxEntries > 0 {
			cs.SetMaxEntries(cfg.Source.MaxEntries)
		}
		src = cs
	}

	var ropts []tenantmw.ResolverOption
	for _, r := range cfg.Resolve {
		k, _ := r.kind()
		switch k {
		case "token":
			v, err := verifier(ctx, cfg, httpClient, logger)
			if err != nil {
				return nil, err
			}
			ropts = append(ropts, tenantmw.FromToken(v))
		case "subdomain":
			ropts = append(ropts, tenantmw.FromSubdomain(r.Subdomain))
		case "header":
			ropts = append(ropts, tenantmw.FromHeader(r.Header))
		case "path":
			ropts = append(ropts, tenantmw.FromPath(r.Path))
		case "custom_domain":
			ropts = append(ropts, tenantmw.FromCustomDomain(tenantmw.CachingDomains(api, cfg.Source.DomainCacheTTL)))
		}
	}

	statuses := make([]tenantmw.Status, 0, len(cfg.AllowedStatuses))
	for _, s := range cfg.AllowedStatuses {
		statuses = append(statuses, tenantmw.Status(strings.ToLower(s)))
	}
	features := make([]gateway.FeatureRule, 0, len(cfg.Features))
	for _, f := range cfg.Features {
		features = append(features, gateway.FeatureRule(f))
	}
	rl := gateway.RateLimitOptions{
		Metric: cfg.RateLimit.Metric, BurstMetric: cfg.RateLimit.BurstMetric, Period: cfg.RateLimit.Period,
		DefaultRate: cfg.RateLimit.DefaultRate, DefaultBurst: cfg.RateLimit.DefaultBurst, FailOpen: *cfg.RateLimit.FailOpen,
	}
	switch cfg.RateLimit.Backend {
	case "local":
		rl.Limiter = gateway.NewLocalLimiter()
	case "redis":
		rl.Limiter = gateway.NewRedisLimiter(a.redis, cfg.RateLimit.Prefix)
	}

	gw, err := gateway.New(gateway.Options{
		Resolver:        tenantmw.NewResolver(ropts...),
		Source:          src,
		AllowedStatuses: statuses,
		Optional:        cfg.Optional,
		Cell:            gateway.CellOptions{Label: cfg.Cell.Label, Default: cfg.Cell.Default, Plans: cfg.Cell.Plans},
		ExposeFeatures:  cfg.ExposeFeatures,
		Features:        features,
		RateLimit:       rl,
		Metrics:         gateway.NewMetrics(reg),
		Logger:          logger,
	})
	if err != nil {
		return nil, err
	}
	a.gw = gw
	logger.Info("gateway configured", "source", cfg.Source.Type, "resolve_rules", len(cfg.Resolve),
		"rate_limit", cmpOr(cfg.RateLimit.Backend, "off"), "cell_label", cmpOr(cfg.Cell.Label, "cell"))
	return a, nil
}

// verifier builds the token verifier: from jwks_url/issuer when set
// (no network at startup), else through OpenID discovery, retried until
// Tenarium answers or ctx ends.
func verifier(ctx context.Context, cfg *Config, client *http.Client, logger *slog.Logger) (*tenantmw.Verifier, error) {
	t := cfg.Tenarium
	if t.JWKSURL != "" || t.Audience != "" {
		return tenantmw.NewVerifier(tenantmw.VerifierConfig{
			JWKSURL:    cmpOr(t.JWKSURL, t.URL+"/.well-known/jwks.json"),
			Issuer:     cmpOr(t.Issuer, t.URL),
			Audience:   t.Audience,
			HTTPClient: client,
		})
	}
	backoff := time.Second
	for {
		v, err := tenantmw.DiscoverVerifier(ctx, t.URL, client)
		if err == nil {
			return v, nil
		}
		logger.Warn("token discovery failed, retrying", "url", t.URL, "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
}

func newLogger(c LogConfig) *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(cmpOr(c.Level, "info")))
	o := &slog.HandlerOptions{Level: lvl}
	if strings.EqualFold(c.Format, "text") {
		return slog.New(slog.NewTextHandler(os.Stderr, o))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, o))
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
