// Package server assembles and runs a Tenarium server.
//
// Custom distributions embed their own plugins by blank-importing them next
// to the built-in ones and calling Main (or use cmd/tenarium-build):
//
//	package main
//
//	import (
//		"github.com/AimTune/tenarium/pkg/server"
//		_ "github.com/AimTune/tenarium/plugins/all"
//		_ "example.com/acme/tenarium-billing"
//	)
//
//	func main() { server.Main() }
package server

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AimTune/tenarium/internal/api"
	"github.com/AimTune/tenarium/internal/authz"
	"github.com/AimTune/tenarium/internal/certs"
	"github.com/AimTune/tenarium/internal/events"
	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/metrics"
	"github.com/AimTune/tenarium/internal/oidcprovider"
	"github.com/AimTune/tenarium/internal/plugin"
	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/internal/secrets"
	"github.com/AimTune/tenarium/internal/social"
	"github.com/AimTune/tenarium/internal/sso"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/encrypted"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/internal/store/postgres"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/internal/ui"
	"github.com/AimTune/tenarium/internal/webhooks"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Version is set at build time via -ldflags "-X .../pkg/server.Version=v1.2.3".
var Version = "dev"

// Main parses flags, loads configuration and runs until SIGINT/SIGTERM.
func Main() {
	configPath := flag.String("config", os.Getenv("TENARIUM_CONFIG"), "path to YAML config file (env TENARIUM_CONFIG)")
	listPlugins := flag.Bool("list-plugins", false, "print compiled-in plugins and exit")
	version := flag.Bool("version", false, "print version and exit")
	reencrypt := flag.Bool("reencrypt", false, "re-encrypt every stored secret under the current secrets key, print a report and exit")
	flag.Parse()

	switch {
	case *version:
		fmt.Println(Version)
		return
	case *listPlugins:
		fmt.Println(strings.Join(sdk.Registered(), "\n"))
		return
	}
	run := runMain
	if *reencrypt {
		run = reencryptMain
	}
	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runMain(configPath string) error {
	cfg := DefaultConfig()
	if configPath != "" {
		var err error
		if cfg, err = LoadConfig(configPath); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, cfg, configPath)
}

// App is a fully wired, not yet running server.
type App struct {
	cfg        Config
	log        *slog.Logger
	store      store.Store
	metrics    *metrics.Metrics
	plugins    *plugin.Manager
	dispatcher *events.Dispatcher
	tenants    *tenant.Service
	issuer     *identity.Issuer
	webhooks   *webhooks.Service
	// stopTracing flushes traces on shutdown.
	stopTracing func(context.Context) error
	certs       *certs.Manager
	handler     http.Handler
	// configPath and level support configuration reloads.
	configPath string
	level      *slog.LevelVar
	reloadMu   sync.Mutex
	api        *api.Server
}

// New wires all components and initialises plugins.
// Option customises New, mainly for tests.
type Option func(*options)

type options struct {
	lookupTXT  func(ctx context.Context, name string) ([]string, error)
	configPath string
	level      *slog.LevelVar
}

// WithTXTResolver replaces DNS TXT lookups used for domain verification.
func WithTXTResolver(fn func(ctx context.Context, name string) ([]string, error)) Option {
	return func(o *options) { o.lookupTXT = fn }
}

func New(ctx context.Context, cfg Config, log *slog.Logger, opts ...Option) (app *App, err error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	cfg.Server.APIKeys = slices.DeleteFunc(slices.Clone(cfg.Server.APIKeys), func(k string) bool { return k == "" })
	st, err := openStore(ctx, cfg.Store)
	if err != nil {
		return nil, err
	}
	if cfg.Store.ReadDSN != "" {
		pg, ok := st.(*postgres.Store)
		if !ok {
			_ = st.Close()
			return nil, errors.New("store.read_dsn needs the postgres driver")
		}
		if err := pg.UseReadReplica(ctx, cfg.Store.ReadDSN); err != nil {
			_ = st.Close()
			return nil, err
		}
	}
	if cfg.Secrets.Provider != "" && cfg.Secrets.Provider != "none" {
		kr, err := secrets.New(ctx, cfg.Secrets)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("secrets: %w", err)
		}
		st = encrypted.Wrap(st, kr)
	}
	a := &App{cfg: cfg, log: log, store: st, metrics: metrics.New(), configPath: o.configPath, level: o.level}
	a.cfg.Plugins = slices.Clone(cfg.Plugins)
	defer func() {
		if err != nil {
			if a.plugins != nil {
				_ = a.plugins.Stop(ctx)
			}
			_ = st.Close()
			if a.stopTracing != nil {
				_ = a.stopTracing(ctx)
			}
		}
	}()

	if a.stopTracing, err = setupTracing(ctx, cfg.Tracing); err != nil {
		return nil, err
	}

	if err := tenant.ValidateMetricPolicies(cfg.Usage.Metrics); err != nil {
		return nil, err
	}
	settingsSchema, err := loadSettingsSchema(cfg.Tenants)
	if err != nil {
		return nil, err
	}

	host := &plugin.StoreHost{Store: st}
	a.plugins = plugin.NewManager(log, host, a.metrics)
	if err := a.plugins.Load(ctx, cfg.Plugins); err != nil {
		return nil, err
	}

	a.dispatcher = events.NewDispatcher(st, log.With("component", "dispatcher"), a.metrics, events.Config{
		PollInterval:   cfg.Events.PollInterval,
		BatchSize:      cfg.Events.BatchSize,
		HandlerTimeout: cfg.Events.HandlerTimeout,
		LeaseTTL:       cfg.Events.LeaseTTL,
		InstanceID:     cfg.Events.InstanceID,
		Region:         cfg.Events.Region,
	})
	provisioners := a.plugins.Provisioners()
	userOpts, issuer, err := a.userOptions(ctx)
	a.issuer = issuer
	if err != nil {
		return nil, err
	}
	if d := cfg.Tenants.DefaultRegion; d != "" && len(cfg.Tenants.Regions) > 0 && !slices.Contains(cfg.Tenants.Regions, d) {
		return nil, fmt.Errorf("tenants.default_region %q is not in tenants.regions", d)
	}
	a.tenants = tenant.NewService(st, tenant.Options{
		Hooks:               a.plugins,
		HasProvisioners:     len(provisioners) > 0,
		RequireKnownPlans:   cfg.Tenants.RequireKnownPlans,
		SettingsSchema:      settingsSchema,
		MemberRoles:         cfg.Tenants.MemberRoles,
		ReservedDomains:     cfg.Tenants.ReservedDomains,
		DeletionGracePeriod: cfg.Tenants.DeletionGracePeriod,
		Metrics:             cfg.Usage.Metrics,
		PurgeDeletedAfter:   cfg.Tenants.PurgeAfter,
		Regions:             cfg.Tenants.Regions,
		DefaultRegion:       cfg.Tenants.DefaultRegion,
		LookupTXT:           o.lookupTXT,
		Notify:              a.dispatcher.Notify,
		Users:               userOpts,
	})
	subs := a.plugins.Subscriptions()
	if len(provisioners) > 0 {
		runner := tenant.NewRunner(a.tenants, provisioners, log.With("component", "provisioning"), a.metrics)
		subs = append([]events.Subscription{runner.Subscription()}, subs...)
	}
	if cfg.Webhooks.Enabled {
		wh := cfg.Webhooks
		a.webhooks = webhooks.New(st, a.tenants, webhooks.Config{
			Timeout: wh.Timeout, Attempts: wh.Attempts, MaxFailures: wh.MaxFailures, MaxPerTenant: wh.MaxPerTenant,
			AllowHTTP: wh.AllowHTTP, AllowPrivateNetworks: wh.AllowPrivateNetworks, DeliveryRetention: wh.DeliveryRetention,
		}, log.With("component", "webhooks"))
		subs = append(subs, a.webhooks.Subscription())
	}
	for _, sub := range subs {
		if err := a.dispatcher.Add(sub); err != nil {
			return nil, err
		}
	}
	if err := a.bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	engine := authz.New(a.plugins.Authorizers(), func(ctx context.Context, id string) (string, error) {
		t, err := st.GetTenant(ctx, id)
		return t.ParentID, err
	}, log)
	if r := cfg.Auth.Roles; r != nil {
		engine.WithUserRoles(authz.UserRoles{Platform: r.Platform, Tenant: r.Tenant})
	}
	var ssoHandler *sso.Handler
	if issuer != nil && cfg.Auth.SSO.Enabled {
		a.tenants.AllowPrivateSSOIssuers(cfg.Auth.SSO.AllowPrivateIssuers)
		ssoHandler = sso.New(a.tenants, issuer, sso.Config{
			PublicURL: cfg.Users.PublicURL, AllowedRedirects: cfg.Auth.SSO.AllowedRedirects,
			AllowPrivateIssuers: cfg.Auth.SSO.AllowPrivateIssuers,
		}, log.With("component", "sso"))
	}
	var socialHandler *social.Handler
	if sc := cfg.Auth.Social; len(sc.Providers) > 0 {
		if issuer == nil {
			return nil, errors.New("auth.social needs auth.tokens.enabled")
		}
		sc.PublicURL = cmp.Or(sc.PublicURL, cfg.Users.PublicURL)
		socialHandler, err = social.New(sc, issuer, func(ctx context.Context, id social.Identity, tenantRef string) (tenant.TokenPair, error) {
			return a.tenants.SocialSession(ctx, tenant.SocialIdentity{Provider: id.Provider, Subject: id.Subject,
				Email: id.Email, Name: id.Name, AutoCreate: id.AutoCreate}, tenantRef)
		}, log.With("component", "social"))
		if err != nil {
			return nil, fmt.Errorf("auth.social: %w", err)
		}
	}
	var oidcHandler *oidcprovider.Handler
	if issuer != nil && cfg.Auth.Provider.Enabled {
		issuer.EnableProvider()
		oidcHandler = oidcprovider.New(a.tenants, issuer, oidcprovider.Config{
			PublicURL: cfg.Users.PublicURL, ProductName: cfg.Users.ProductName, SessionTTL: cfg.Auth.Provider.SessionTTL,
		}, log.With("component", "oidc-provider"))
	}

	engine.WithCustomRoles(a.tenants.RoleActions)
	host.Authz = engine.Authorize
	host.Actions = a.tenants
	srv := &api.Server{
		Tenants:         a.tenants,
		Store:           st,
		Plugins:         a.plugins,
		Dispatcher:      a.dispatcher,
		Authz:           engine,
		Metrics:         a.metrics,
		Log:             log,
		APIKeys:         cfg.Server.APIKeys,
		AllowAnonymous:  cfg.Server.AllowAnonymous,
		OpenAPI:         api.OpenAPISpec,
		Issuer:          issuer,
		AuthRateLimit:   cfg.Auth.RateLimit,
		SharedRateLimit: cfg.Auth.RateLimitShared,
		Webhooks:        a.webhooks,
		SSO:             ssoHandler,
		Social:          socialHandler,
		Reload:          a.reloadFunc(),
		OIDC:            oidcHandler,
	}
	if cfg.UI.Enabled {
		srv.UI = ui.Handler()
	}
	if cfg.Server.TLS.ACME.Enabled {
		if a.certs, err = newCertManager(cfg.Server.TLS, st, a.tenants, log.With("component", "acme")); err != nil {
			return nil, fmt.Errorf("acme: %w", err)
		}
		srv.Certs = a.certs
	}
	a.handler = srv.Handler()
	a.api = srv
	if cfg.Tracing.Enabled {
		a.handler = traceHandler(a.handler)
	}
	return a, nil
}

// userOptions resolves the user directory and mailer plugins and sets up
// token signing.
func (a *App) userOptions(ctx context.Context) (*tenant.UserOptions, *identity.Issuer, error) {
	uc := a.cfg.Users
	o := &tenant.UserOptions{
		DirectoryName:  cmp.Or(uc.Directory, tenant.InternalDirectory),
		PublicURL:      uc.PublicURL,
		ProductName:    uc.ProductName,
		Policy:         identity.Policy{MinLength: uc.PasswordMinLength},
		InvitationTTL:  uc.InvitationTTL,
		ResetTTL:       uc.ResetTTL,
		MaxFailures:    uc.Lockout.MaxFailures,
		LockFor:        uc.Lockout.Duration,
		RefreshTTL:     a.cfg.Auth.Tokens.RefreshTTL,
		Templates:      uc.Templates,
		Log:            a.log.With("component", "users"),
		MagicLinkTTL:   uc.MagicLinkTTL,
		EmailChangeTTL: uc.EmailChangeTTL,
	}
	if uc.BreachedPasswordCheck {
		o.BreachCheck = identity.PwnedPasswords{}.Breached
	}
	if o.DirectoryName != tenant.InternalDirectory {
		d, ok := a.plugins.UserDirectories()[o.DirectoryName]
		if !ok {
			return nil, nil, fmt.Errorf("users.directory: no plugin instance %q provides a user directory", o.DirectoryName)
		}
		o.Directory = d
	}
	mailers := a.plugins.Mailers()
	switch {
	case uc.Mailer != "":
		m, ok := mailers[uc.Mailer]
		if !ok {
			return nil, nil, fmt.Errorf("users.mailer: no plugin instance %q provides a mailer", uc.Mailer)
		}
		o.Mailer = m
	case len(mailers) == 1:
		for _, m := range mailers {
			o.Mailer = m
		}
	case len(mailers) > 1:
		return nil, nil, errors.New("several mailer plugins are configured; choose one with users.mailer")
	default:
		a.log.Warn("no mailer plugin configured: invitation and password-reset emails are only logged")
	}

	t := a.cfg.Auth.Tokens
	if !t.Enabled {
		return o, nil, nil
	}
	issuer := identity.NewIssuer(a.store, cmp.Or(t.Issuer, uc.PublicURL), cmp.Or(t.Audience, "tenarium"), cmp.Or(t.AccessTTL, 15*time.Minute))
	if err := issuer.Init(ctx); err != nil {
		return nil, nil, fmt.Errorf("token signing keys: %w", err)
	}
	o.Issuer = issuer
	ic := a.cfg.Auth.Impersonation
	o.Impersonation = tenant.ImpersonationOptions{RequireConsent: ic.RequireConsent == nil || *ic.RequireConsent, MaxTTL: ic.MaxTTL}
	pu, perr := url.Parse(uc.PublicURL)
	if wc := a.cfg.Auth.WebAuthn; wc.Enabled && wc.RPID == "" && (perr != nil || net.ParseIP(pu.Hostname()) != nil) {
		// Passkeys are bound to a domain; an IP address cannot be one.
		a.log.Warn("passkeys disabled: users.public_url has no domain name; set auth.webauthn.rp_id", "public_url", uc.PublicURL)
	} else if wc.Enabled {
		if perr != nil || pu.Host == "" {
			return nil, nil, fmt.Errorf("webauthn: users.public_url %q is not a URL", uc.PublicURL)
		}
		origins := wc.Origins
		if len(origins) == 0 {
			origins = []string{pu.Scheme + "://" + pu.Host}
		}
		wa, err := webauthn.New(&webauthn.Config{
			RPID: cmp.Or(wc.RPID, pu.Hostname()), RPDisplayName: cmp.Or(uc.ProductName, "Tenarium"), RPOrigins: origins,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("webauthn: %w", err)
		}
		o.WebAuthn = wa
	}
	return o, issuer, nil
}

func loadSettingsSchema(cfg TenantsConfig) (*schema.Schema, error) {
	var raw []byte
	switch {
	case cfg.SettingsSchemaFile != "":
		b, err := os.ReadFile(cfg.SettingsSchemaFile)
		if err != nil {
			return nil, fmt.Errorf("settings schema: %w", err)
		}
		raw = b
	case cfg.SettingsSchema != nil:
		b, err := json.Marshal(cfg.SettingsSchema)
		if err != nil {
			return nil, fmt.Errorf("settings schema: %w", err)
		}
		raw = b
	default:
		return nil, nil
	}
	s, err := schema.Compile(raw)
	if err != nil {
		return nil, fmt.Errorf("settings schema: %w", err)
	}
	return s, nil
}

// bootstrap creates configured plans that don't exist yet.
func (a *App) bootstrap(ctx context.Context) error {
	ctx = sdk.WithPrincipal(ctx, &sdk.Principal{Subject: "bootstrap", Kind: "service", Authenticator: "core"})
	for _, p := range a.cfg.Bootstrap.Plans {
		_, err := a.tenants.GetPlan(ctx, p.ID)
		if err == nil {
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		_, err = a.tenants.CreatePlan(ctx, tenant.PlanInput{
			ID: p.ID, Name: cmp.Or(p.Name, p.ID), Description: p.Description, Features: p.Features, Limits: p.Limits,
		})
		if err != nil && !errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("plan %q: %w", p.ID, err)
		}
	}
	for _, u := range a.cfg.Bootstrap.Users {
		_, err := a.tenants.GetUser(ctx, u.Email)
		if err == nil {
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		_, err = a.tenants.CreateUser(ctx, tenant.UserInput{Email: u.Email, Name: u.Name, Roles: u.Roles, Password: u.Password})
		if err != nil && !errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("user %q: %w", u.Email, err)
		}
	}
	return nil
}

func (a *App) Handler() http.Handler          { return a.handler }
func (a *App) Tenants() *tenant.Service       { return a.tenants }
func (a *App) Dispatcher() *events.Dispatcher { return a.dispatcher }

// Serve runs the HTTP server and event dispatcher on ln until ctx is done,
// then shuts down gracefully.
func (a *App) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{Handler: a.handler, ReadHeaderTimeout: 10 * time.Second}
	tlsCfg, challenge, err := a.serverTLS()
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	if challenge != nil {
		go func() {
			if err := challenge.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				a.log.Error("acme http-01 listener failed", "addr", challenge.Addr, "err", err)
			}
		}()
		defer func() { _ = challenge.Close() }()
	}
	dispatchCtx, stopDispatch := context.WithCancel(context.WithoutCancel(ctx))
	defer stopDispatch()

	var wg sync.WaitGroup
	wg.Go(func() { _ = a.dispatcher.Run(dispatchCtx) })
	if ev := a.cfg.Events; ev.Retention > 0 {
		wg.Go(func() {
			a.dispatcher.RunRetention(dispatchCtx, ev.Retention, cmp.Or(ev.PruneInterval, time.Hour), a.log.With("component", "retention"))
		})
	}
	if a.webhooks != nil {
		wg.Go(func() { a.webhooks.RunPruner(dispatchCtx) })
	}
	if a.issuer != nil {
		wg.Go(func() { a.maintainKeys(dispatchCtx) })
	}
	a.reloadOnSignal(dispatchCtx, &wg)
	if a.cfg.Scheduler.Interval > 0 {
		wg.Go(func() {
			a.tenants.RunScheduler(dispatchCtx, a.cfg.Scheduler.Interval, a.log.With("component", "scheduler"))
		})
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	a.log.Info("tenarium listening", "addr", ln.Addr().String(), "version", Version, "store", cmp.Or(a.cfg.Store.Driver, "memory"))

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.cfg.Server.ShutdownTimeout)
	defer cancel()
	var errs []error
	if err := srv.Shutdown(shutdownCtx); err != nil {
		errs = append(errs, err)
	}
	stopDispatch()
	wg.Wait()
	errs = append(errs, a.plugins.Stop(shutdownCtx), a.store.Close(), a.stopTracing(shutdownCtx))
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		errs = append(errs, serveErr)
	}
	return errors.Join(errs...)
}

// Run builds an App from cfg and serves it on cfg.Server.Addr.
func Run(ctx context.Context, cfg Config) error { return run(ctx, cfg, "") }

// run is Run with an optional configuration file to reload from.
func run(ctx context.Context, cfg Config, configPath string) error {
	lv := new(slog.LevelVar)
	log, err := newLogger(cfg.Log, lv)
	if err != nil {
		return err
	}
	app, err := New(ctx, cfg, log, WithLevelVar(lv), WithConfigPath(configPath))
	if err != nil {
		return err
	}
	if len(app.cfg.Server.APIKeys) == 0 && len(app.plugins.Authenticators()) == 0 {
		if cfg.Server.AllowAnonymous {
			log.Warn("no authentication configured and allow_anonymous is set: the API is open")
		} else {
			log.Warn("no API keys or authenticator plugins configured: every API request will be rejected")
		}
	}
	ln, err := net.Listen("tcp", cfg.Server.Addr)
	if err != nil {
		return err
	}
	return app.Serve(ctx, ln)
}

func openStore(ctx context.Context, cfg StoreConfig) (store.Store, error) {
	switch cfg.Driver {
	case "", "memory":
		return memory.New(), nil
	case "postgres":
		if cfg.DSN == "" {
			return nil, errors.New("store.dsn is required for the postgres driver")
		}
		return postgres.Open(ctx, cfg.DSN)
	default:
		return nil, fmt.Errorf("unknown store driver %q", cfg.Driver)
	}
}

func newLogger(cfg LogConfig, lv *slog.LevelVar) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cmp.Or(cfg.Level, "info"))); err != nil {
		return nil, fmt.Errorf("log level: %w", err)
	}
	lv.Set(level)
	opts := &slog.HandlerOptions{Level: lv}
	switch cfg.Format {
	case "", "text":
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	default:
		return nil, fmt.Errorf("unknown log format %q", cfg.Format)
	}
}

// maintainKeys keeps the token signing keys in sync across replicas,
// rotates them on schedule and retires expired ones.
func (a *App) maintainKeys(ctx context.Context) {
	log := a.log.With("component", "signing-keys")
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if err := a.issuer.Maintain(ctx, a.cfg.Auth.Tokens.RotationPeriod); err != nil && ctx.Err() == nil {
			log.Error("signing key maintenance failed", "err", err)
		}
	}
}
