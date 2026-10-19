// Package gateway is a forward-auth service for API gateways built on
// tenantmw. Envoy (ext_authz, HTTP service mode), NGINX (auth_request) and
// Traefik (ForwardAuth) send it a check request that describes the
// original request. The gateway resolves the tenant, enforces its status,
// required features and a per-tenant rate limit, and answers either 200
// with headers to add upstream (X-Tenant-Id, X-Tenant-Slug, X-Tenant-Plan,
// X-Tenant-Cell and optionally X-Tenant-Features) or a denial. The proxy
// routes allowed requests on X-Tenant-Cell to the tenant's cell.
//
//	gw, err := gateway.New(gateway.Options{
//		Resolver: tenantmw.NewResolver(tenantmw.FromSubdomain("app.example.com")),
//		Source:   tenantmw.CachingSource(tenantmw.RedisSource(rdb, ""), 30*time.Second),
//		Cell:     gateway.CellOptions{Label: "cell", Default: "default"},
//		RateLimit: gateway.RateLimitOptions{
//			Limiter: gateway.NewLocalLimiter(), Metric: "rps", DefaultRate: 20,
//		},
//	})
//	http.ListenAndServe(":8090", gw) // serves /check, /envoy, /nginx and /traefik
//
// See docs/gateway.md for the proxy configurations.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/tenantmw"
)

// Headers set on allowed requests. Configure the proxy to copy them to the
// upstream request (Envoy allowed_upstream_headers, Traefik
// authResponseHeaders, NGINX auth_request_set + proxy_set_header).
const (
	HeaderTenantID       = "X-Tenant-Id"
	HeaderTenantSlug     = "X-Tenant-Slug"
	HeaderTenantPlan     = "X-Tenant-Plan"
	HeaderTenantCell     = "X-Tenant-Cell"
	HeaderTenantFeatures = "X-Tenant-Features"
)

// Headers set on denials. HeaderStatus carries the real status code, which
// matters in NGINX mode where every denial other than 401 is sent as 403.
const (
	HeaderStatus = "X-Tenarium-Status"
	HeaderError  = "X-Tenarium-Error"
)

// Rate limit response headers (draft-ietf-httpapi-ratelimit-headers) plus
// Retry-After on 429.
const (
	HeaderRateLimitLimit     = "RateLimit-Limit"
	HeaderRateLimitRemaining = "RateLimit-Remaining"
	HeaderRateLimitReset     = "RateLimit-Reset"
	HeaderRateLimitPolicy    = "RateLimit-Policy"
	HeaderRetryAfter         = "Retry-After"
)

// UpstreamHeaders lists the headers an allowed check may set for the
// upstream request.
var UpstreamHeaders = []string{HeaderTenantID, HeaderTenantSlug, HeaderTenantPlan, HeaderTenantCell, HeaderTenantFeatures}

// ClientHeaders lists the headers meant for the client (rate limit state).
var ClientHeaders = []string{HeaderRateLimitLimit, HeaderRateLimitRemaining, HeaderRateLimitReset, HeaderRateLimitPolicy, HeaderRetryAfter}

// DefaultCell is the cell of tenants without a cell label when
// CellOptions.Default is empty.
const DefaultCell = "default"

// CellOptions choose a tenant's cell, sent as X-Tenant-Cell. The first
// non-empty answer wins: Func, the Label label, the Plans entry of the
// tenant's plan, then Default. Cell names are restricted to
// [A-Za-z0-9._-] (at most 63 characters) because proxies use them in
// routing decisions; other values fall back to Default.
type CellOptions struct {
	// Label is the tenant label holding the cell (default "cell").
	Label string
	// Plans maps plan IDs to cells, e.g. {"enterprise": "dedicated"}.
	Plans map[string]string
	// Default is the cell of everything else (default "default").
	Default string
	// Func overrides the lookup; return "" to fall through.
	Func func(*tenantmw.Tenant) string
}

// FeatureRule requires a feature for matching requests (403
// feature_disabled otherwise). Empty fields match everything.
type FeatureRule struct {
	// Host is an exact (case-insensitive) host to match.
	Host string
	// PathPrefix matches the original request path.
	PathPrefix string
	// Methods restricts the rule to these methods.
	Methods []string
	// Feature is the required feature.
	Feature string
}

func (fr FeatureRule) matches(method, host, path string) bool {
	if fr.Host != "" && !strings.EqualFold(fr.Host, host) {
		return false
	}
	if fr.PathPrefix != "" && !strings.HasPrefix(path, fr.PathPrefix) {
		return false
	}
	if len(fr.Methods) > 0 && !slices.ContainsFunc(fr.Methods, func(m string) bool { return strings.EqualFold(m, method) }) {
		return false
	}
	return true
}

// RateLimitOptions configure per-tenant rate limiting. It is off when
// Limiter is nil.
//
// The tenant's rate is the entitlement limit named Metric, in requests per
// Period: a negative value means unlimited, 0 blocks every request.
// Tenants without that limit get DefaultRate, where 0 means unlimited. The
// bucket size (burst) is the BurstMetric limit, else DefaultBurst, else one
// Period worth of requests.
type RateLimitOptions struct {
	Limiter Limiter
	// Metric is the entitlement limit holding the rate, e.g. "rps".
	Metric string
	// BurstMetric is the entitlement limit holding the burst, optional.
	BurstMetric string
	// Period is the unit of the rate (default 1s): "rpm" uses 1m.
	Period time.Duration
	// DefaultRate applies to tenants without the Metric limit.
	DefaultRate int64
	// DefaultBurst applies to tenants without the BurstMetric limit.
	DefaultBurst int64
	// FailOpen allows requests when the limiter fails (e.g. Redis is
	// down) instead of answering 503.
	FailOpen bool
}

// Options configure a Gateway.
type Options struct {
	// Resolver finds the tenant reference in the original request.
	Resolver *tenantmw.Resolver
	// Source loads tenants; wrap it in tenantmw.CachingSource.
	Source tenantmw.Source
	// AllowedStatuses default to active (see tenantmw.Options).
	AllowedStatuses []tenantmw.Status
	// Optional allows requests without a tenant reference. They get
	// X-Tenant-Cell with the default cell and empty tenant headers.
	Optional bool
	// Cell chooses the X-Tenant-Cell value.
	Cell CellOptions
	// ExposeFeatures adds X-Tenant-Features: the enabled features, sorted
	// and comma separated (the header is sent empty otherwise).
	ExposeFeatures bool
	// Features are feature requirements per host, path and method.
	Features []FeatureRule
	// RateLimit configures per-tenant rate limiting.
	RateLimit RateLimitOptions
	// Metrics records decisions and latency; nil disables metrics.
	Metrics *Metrics
	// Logger reports limiter and source failures (default slog.Default()).
	Logger *slog.Logger
}

// Gateway answers forward-auth checks. It is an http.Handler serving the
// protocol endpoints (see ServeHTTP).
type Gateway struct {
	opts   Options
	mw     http.Handler
	logger *slog.Logger
}

// New returns a Gateway.
func New(opts Options) (*Gateway, error) {
	if opts.Resolver == nil || opts.Source == nil {
		return nil, errors.New("gateway: Resolver and Source are required")
	}
	if opts.Cell.Label == "" {
		opts.Cell.Label = "cell"
	}
	if opts.Cell.Default == "" {
		opts.Cell.Default = DefaultCell
	}
	if !validCell(opts.Cell.Default) {
		return nil, fmt.Errorf("gateway: invalid default cell %q", opts.Cell.Default)
	}
	rl := &opts.RateLimit
	if rl.Period <= 0 {
		rl.Period = time.Second
	}
	if rl.Limiter != nil && rl.Metric == "" && rl.DefaultRate == 0 {
		return nil, errors.New("gateway: rate limiting needs a Metric or a DefaultRate")
	}
	for _, fr := range opts.Features {
		if fr.Feature == "" {
			return nil, errors.New("gateway: feature rule without feature")
		}
	}
	g := &Gateway{opts: opts, logger: opts.Logger}
	if g.logger == nil {
		g.logger = slog.Default()
	}
	g.mw = tenantmw.Middleware(opts.Resolver, opts.Source, tenantmw.Options{
		AllowedStatuses: opts.AllowedStatuses,
		Optional:        opts.Optional,
		ErrorHandler: func(_ http.ResponseWriter, r *http.Request, err error) {
			stateFrom(r.Context()).err = err
		},
	})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		st := stateFrom(r.Context())
		st.passed = true
		st.tenant = tenantmw.FromContext(r.Context())
		st.claims = tenantmw.ClaimsFromContext(r.Context())
	}))
	return g, nil
}

// Request describes the original request a proxy asks about.
type Request struct {
	Method string
	// Scheme is "http" or "https" (default "http").
	Scheme string
	// Host is the original host, optionally with a port.
	Host string
	// URI is the original request URI: path and optional query.
	URI string
	// Header holds the original request headers (Authorization, the
	// tenant header, ...).
	Header http.Header
}

// Result is the outcome of a check.
type Result struct {
	// Allowed reports whether the request may proceed.
	Allowed bool
	// Status is 200 when allowed, else the denial status (400, 401, 403,
	// 404, 429 or 503).
	Status int
	// Code is "ok" or an error code such as "tenant_not_found" or
	// "rate_limited".
	Code string
	// Message is a human readable reason for denials.
	Message string
	// Err is the underlying error of a denial, if any.
	Err error
	// Tenant is the resolved tenant (nil for optional anonymous requests
	// and most denials).
	Tenant *tenantmw.Tenant
	// Claims are the verified token claims when a Tenarium token was used.
	Claims *tenantmw.Claims
	// Cell is the tenant's cell when allowed.
	Cell string
	// Headers are the response headers: upstream headers when allowed and
	// rate limit headers in both cases.
	Headers http.Header
	// RateLimit is the limiter's decision when one was taken.
	RateLimit *Decision
}

type stateKey struct{}

type checkState struct {
	passed bool
	err    error
	tenant *tenantmw.Tenant
	claims *tenantmw.Claims
}

func stateFrom(ctx context.Context) *checkState {
	st, _ := ctx.Value(stateKey{}).(*checkState)
	if st == nil {
		return &checkState{} // only reached if the middleware is misused
	}
	return st
}

// nopWriter swallows the middleware's output; Check reads its state.
type nopWriter struct{ h http.Header }

func (w *nopWriter) Header() http.Header         { return w.h }
func (w *nopWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *nopWriter) WriteHeader(int)             {}

// Check decides on an original request.
func (g *Gateway) Check(ctx context.Context, req Request) Result {
	hr, err := req.httpRequest(ctx)
	if err != nil {
		return deny(http.StatusBadRequest, "bad_request", err.Error(), err)
	}
	st := &checkState{}
	hr = hr.WithContext(context.WithValue(hr.Context(), stateKey{}, st))
	g.mw.ServeHTTP(&nopWriter{h: http.Header{}}, hr)
	if st.err != nil {
		code := tenantmw.StatusCode(st.err)
		msg := st.err.Error()
		if code == http.StatusServiceUnavailable {
			g.logger.WarnContext(ctx, "gateway: tenant lookup failed", "err", st.err)
			msg = "tenant state unavailable"
		}
		return deny(code, errorCode(st.err), msg, st.err)
	}
	if !st.passed {
		return deny(http.StatusInternalServerError, "internal", "check did not complete", nil)
	}
	t := st.tenant
	res := Result{Allowed: true, Status: http.StatusOK, Code: "ok", Tenant: t, Claims: st.claims, Headers: http.Header{}}
	if t == nil { // Options.Optional and no tenant reference
		res.Cell = g.opts.Cell.Default
		setUpstream(res.Headers, "", "", "", res.Cell, "")
		return res
	}
	for _, fr := range g.opts.Features {
		if fr.matches(hr.Method, hostOnly(hr.Host), hr.URL.Path) && !t.HasFeature(fr.Feature) {
			r := deny(http.StatusForbidden, "feature_disabled", "feature "+fr.Feature+" is not enabled for the tenant", tenantmw.ErrFeatureDisabled)
			r.Tenant, r.Claims = t, st.claims
			return r
		}
	}
	if r, ok := g.rateLimit(ctx, t, &res); !ok {
		r.Tenant, r.Claims = t, st.claims
		return r
	}
	res.Cell = g.cell(t)
	features := ""
	if g.opts.ExposeFeatures {
		features = featureList(t)
	}
	setUpstream(res.Headers, t.ID, t.Slug, t.Plan, res.Cell, features)
	return res
}

// setUpstream sets every upstream header, empty ones included: proxies
// that copy auth response headers over the request's (Envoy) then also
// clear values a client sent itself.
func setUpstream(h http.Header, id, slug, plan, cell, features string) {
	h.Set(HeaderTenantID, id)
	h.Set(HeaderTenantSlug, slug)
	h.Set(HeaderTenantPlan, plan)
	h.Set(HeaderTenantCell, cell)
	h.Set(HeaderTenantFeatures, features)
}

func deny(status int, code, msg string, err error) Result {
	return Result{Status: status, Code: code, Message: msg, Err: err, Headers: http.Header{}}
}

// rateLimit applies the tenant's rate limit. It returns the denial and
// false when the request must be refused, else it adds the rate limit
// headers to res.
func (g *Gateway) rateLimit(ctx context.Context, t *tenantmw.Tenant, res *Result) (Result, bool) {
	o := g.opts.RateLimit
	if o.Limiter == nil {
		return Result{}, true
	}
	perPeriod, ok := t.Limit(o.Metric)
	if o.Metric == "" || !ok {
		perPeriod = o.DefaultRate
		if perPeriod == 0 {
			return Result{}, true
		}
	}
	if perPeriod < 0 {
		return Result{}, true
	}
	if perPeriod == 0 {
		r := deny(http.StatusTooManyRequests, "rate_limited", "requests are not allowed for the tenant", nil)
		r.Headers.Set(HeaderRateLimitLimit, "0")
		r.Headers.Set(HeaderRateLimitRemaining, "0")
		g.opts.Metrics.rateLimited()
		return r, false
	}
	burst, ok := t.Limit(o.BurstMetric)
	if o.BurstMetric == "" || !ok || burst <= 0 {
		burst = o.DefaultBurst
	}
	if burst <= 0 {
		burst = perPeriod
	}
	lim := Limit{Rate: float64(perPeriod) / o.Period.Seconds(), Burst: burst}
	d, err := o.Limiter.Allow(ctx, t.ID, lim)
	if err != nil {
		g.opts.Metrics.limiterError()
		g.logger.WarnContext(ctx, "gateway: rate limiter failed", "tenant", t.ID, "fail_open", o.FailOpen, "err", err)
		if o.FailOpen {
			return Result{}, true
		}
		return deny(http.StatusServiceUnavailable, "rate_limit_unavailable", "rate limiter unavailable", err), false
	}
	policy := strconv.FormatInt(perPeriod, 10) + ";w=" + strconv.FormatInt(int64(math.Ceil(o.Period.Seconds())), 10) +
		";burst=" + strconv.FormatInt(burst, 10)
	if !d.Allowed {
		r := deny(http.StatusTooManyRequests, "rate_limited", "rate limit exceeded", nil)
		r.RateLimit = &d
		setRateHeaders(r.Headers, d, policy)
		r.Headers.Set(HeaderRetryAfter, strconv.FormatInt(max(1, ceilSeconds(d.RetryAfter)), 10))
		g.opts.Metrics.rateLimited()
		return r, false
	}
	res.RateLimit = &d
	setRateHeaders(res.Headers, d, policy)
	return Result{}, true
}

func setRateHeaders(h http.Header, d Decision, policy string) {
	h.Set(HeaderRateLimitLimit, strconv.FormatInt(d.Limit, 10))
	h.Set(HeaderRateLimitRemaining, strconv.FormatInt(max(0, d.Remaining), 10))
	h.Set(HeaderRateLimitReset, strconv.FormatInt(ceilSeconds(d.Reset), 10))
	h.Set(HeaderRateLimitPolicy, policy)
}

func ceilSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64(math.Ceil(d.Seconds()))
}

var cellRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)

func validCell(s string) bool { return cellRE.MatchString(s) }

func (g *Gateway) cell(t *tenantmw.Tenant) string {
	c := g.opts.Cell
	for _, v := range []func() string{
		func() string {
			if c.Func != nil {
				return c.Func(t)
			}
			return ""
		},
		func() string { return t.Labels[c.Label] },
		func() string { return c.Plans[t.Plan] },
	} {
		if s := v(); s != "" {
			if validCell(s) {
				return s
			}
			g.logger.Warn("gateway: ignoring invalid cell", "tenant", t.ID, "cell", s)
		}
	}
	return c.Default
}

func featureList(t *tenantmw.Tenant) string {
	fs := make([]string, 0, len(t.Features))
	for f, on := range t.Features {
		if on {
			fs = append(fs, f)
		}
	}
	sort.Strings(fs)
	return strings.Join(fs, ",")
}

// errorCode mirrors tenantmw's error codes.
func errorCode(err error) string {
	switch {
	case errors.Is(err, tenantmw.ErrNoTenant):
		return "tenant_required"
	case errors.Is(err, tenantmw.ErrNotFound):
		return "tenant_not_found"
	case errors.Is(err, tenantmw.ErrInvalidToken):
		return "unauthorized"
	case errors.Is(err, tenantmw.ErrInactive):
		return "tenant_inactive"
	case errors.Is(err, tenantmw.ErrTenantMismatch):
		return "tenant_mismatch"
	case errors.Is(err, tenantmw.ErrFeatureDisabled):
		return "feature_disabled"
	case errors.Is(err, tenantmw.ErrQuotaExceeded):
		return "quota_exceeded"
	default:
		return "tenant_unavailable"
	}
}

// httpRequest builds the synthetic request the resolver inspects.
func (req Request) httpRequest(ctx context.Context) (*http.Request, error) {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	uri := req.URI
	if uri == "" {
		uri = "/"
	}
	if !strings.HasPrefix(uri, "/") {
		// Absolute-form URIs (e.g. X-Original-URL) keep only path and query.
		if u, err := url.Parse(uri); err == nil && u.IsAbs() {
			uri = u.RequestURI()
		} else {
			return nil, fmt.Errorf("invalid original URI %q", req.URI)
		}
	}
	u, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid original URI %q", req.URI)
	}
	scheme := strings.ToLower(req.Scheme)
	if scheme != "https" {
		scheme = "http"
	}
	u.Scheme, u.Host = scheme, req.Host
	h := req.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	hr := (&http.Request{
		Method:     method,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     h,
		Host:       req.Host,
		RequestURI: uri,
		Body:       http.NoBody,
	}).WithContext(ctx)
	return hr, nil
}

func hostOnly(host string) string {
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
