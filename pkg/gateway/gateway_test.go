package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/gateway"
	"github.com/AimTune/tenarium/pkg/tenantmw"
	"github.com/prometheus/client_golang/prometheus"
)

type fakeSource struct {
	mu      sync.Mutex
	tenants []*tenantmw.Tenant
	err     error
}

func (s *fakeSource) Tenant(_ context.Context, ref string) (*tenantmw.Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	for _, t := range s.tenants {
		if t.ID == ref || t.Slug == ref {
			return t, nil
		}
	}
	return nil, tenantmw.ErrNotFound
}

var (
	acme = &tenantmw.Tenant{
		ID: "11111111-0000-0000-0000-000000000001", Slug: "acme", Status: tenantmw.StatusActive, Plan: "pro",
		Labels:   map[string]string{"cell": "eu-1"},
		Features: map[string]bool{"sso": true, "reports": true, "beta": false},
		Limits:   map[string]int64{"rps": 2},
	}
	globex = &tenantmw.Tenant{
		ID: "22222222-0000-0000-0000-000000000002", Slug: "globex", Status: tenantmw.StatusActive, Plan: "enterprise",
		Features: map[string]bool{}, Limits: map[string]int64{"rps": -1},
	}
	initech = &tenantmw.Tenant{
		ID: "33333333-0000-0000-0000-000000000003", Slug: "initech", Status: tenantmw.StatusActive, Plan: "free",
		Labels: map[string]string{"cell": "bad cell!"}, Limits: map[string]int64{"rps": 0},
	}
	frozen = &tenantmw.Tenant{ID: "44444444-0000-0000-0000-000000000004", Slug: "frozen", Status: tenantmw.StatusSuspended}
	hooli  = &tenantmw.Tenant{ID: "55555555-0000-0000-0000-000000000005", Slug: "hooli", Status: tenantmw.StatusActive}
)

func newSource() *fakeSource {
	return &fakeSource{tenants: []*tenantmw.Tenant{acme, globex, initech, frozen, hooli}}
}

type fixture struct {
	gw      *gateway.Gateway
	clock   *fakeClock
	reg     *prometheus.Registry
	limiter gateway.Limiter
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newFixture(t *testing.T, mutate func(*gateway.Options)) *fixture {
	t.Helper()
	f := &fixture{clock: newFakeClock(), reg: prometheus.NewRegistry()}
	f.limiter = gateway.NewLocalLimiter(gateway.WithClock(f.clock.Now))
	opts := gateway.Options{
		Resolver: tenantmw.NewResolver(
			tenantmw.FromSubdomain("app.example.com"),
			tenantmw.FromHeader("X-Tenant-ID"),
			tenantmw.FromPathPrefix(),
		),
		Source:         newSource(),
		Cell:           gateway.CellOptions{Plans: map[string]string{"enterprise": "dedicated"}},
		ExposeFeatures: true,
		Features:       []gateway.FeatureRule{{PathPrefix: "/reports", Methods: []string{"POST"}, Feature: "reports"}},
		RateLimit:      gateway.RateLimitOptions{Limiter: f.limiter, Metric: "rps", DefaultRate: 100},
		Metrics:        gateway.NewMetrics(f.reg),
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mutate != nil {
		mutate(&opts)
	}
	gw, err := gateway.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	f.gw = gw
	return f
}

// do sends a check request to the gateway.
func (f *fixture) do(method, target string, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		if strings.EqualFold(headers[i], "Host") {
			r.Host = headers[i+1]
			continue
		}
		r.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	f.gw.ServeHTTP(rec, r)
	return rec
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return body.Error.Code
}

func expectAllowed(t *testing.T, rec *httptest.ResponseRecorder, tenant *tenantmw.Tenant, cell string) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	h := rec.Header()
	if got := h.Get(gateway.HeaderTenantID); got != tenant.ID {
		t.Errorf("X-Tenant-Id = %q, want %q", got, tenant.ID)
	}
	if got := h.Get(gateway.HeaderTenantSlug); got != tenant.Slug {
		t.Errorf("X-Tenant-Slug = %q", got)
	}
	if got := h.Get(gateway.HeaderTenantPlan); got != tenant.Plan {
		t.Errorf("X-Tenant-Plan = %q", got)
	}
	if got := h.Get(gateway.HeaderTenantCell); got != cell {
		t.Errorf("X-Tenant-Cell = %q, want %q", got, cell)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("unexpected body %q", rec.Body)
	}
}

func expectDenied(t *testing.T, rec *httptest.ResponseRecorder, status int, code string, realStatus string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d (body %s)", rec.Code, status, rec.Body)
	}
	if got := errCode(t, rec); got != code {
		t.Errorf("code %q, want %q", got, code)
	}
	if got := rec.Header().Get(gateway.HeaderError); got != code {
		t.Errorf("X-Tenarium-Error = %q, want %q", got, code)
	}
	if got := rec.Header().Get(gateway.HeaderStatus); got != realStatus {
		t.Errorf("X-Tenarium-Status = %q, want %q", got, realStatus)
	}
	if rec.Header().Get(gateway.HeaderTenantID) != "" {
		t.Error("denial carries X-Tenant-Id")
	}
}

func TestEnvoyShape(t *testing.T) {
	f := newFixture(t, nil)

	// Host header and the path after /envoy are the original request.
	rec := f.do("GET", "/envoy/api/items?x=1", "Host", "acme.app.example.com")
	expectAllowed(t, rec, acme, "eu-1")
	if got := rec.Header().Get(gateway.HeaderTenantFeatures); got != "reports,sso" {
		t.Errorf("X-Tenant-Features = %q", got)
	}

	// Tenant from the original path, below the prefix.
	expectAllowed(t, f.do("GET", "/envoy/t/globex/dashboard", "Host", "api.example.com"), globex, "dedicated")

	// Original method feeds feature rules.
	expectDenied(t, f.do("POST", "/envoy/reports", "Host", "globex.app.example.com"), 403, "feature_disabled", "403")
	expectAllowed(t, f.do("GET", "/envoy/reports", "Host", "globex.app.example.com"), globex, "dedicated")

	// Forwarding headers are not trusted in Envoy mode.
	rec = f.do("GET", "/envoy/", "Host", "www.example.com", "X-Forwarded-Host", "acme.app.example.com", "X-Forwarded-Uri", "/t/acme/")
	expectDenied(t, rec, 404, "tenant_required", "404")

	// Paths are not cleaned: Envoy may send "//" or "..".
	expectAllowed(t, f.do("GET", "/envoy//t/../x", "Host", "acme.app.example.com"), acme, "eu-1")

	// Unknown tenant and inactive tenant keep their real status.
	expectDenied(t, f.do("GET", "/envoy/", "Host", "nope.app.example.com"), 404, "tenant_not_found", "404")
	expectDenied(t, f.do("GET", "/envoy/", "Host", "frozen.app.example.com"), 403, "tenant_inactive", "403")
}

func TestTraefikShape(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.do("GET", "http://gateway:8090/traefik",
		"X-Forwarded-Method", "POST", "X-Forwarded-Proto", "https",
		"X-Forwarded-Host", "acme.app.example.com", "X-Forwarded-Uri", "/reports/new?draft=1")
	expectAllowed(t, rec, acme, "eu-1")
	if rec.Header().Get(gateway.HeaderRateLimitLimit) != "2" || rec.Header().Get(gateway.HeaderRateLimitRemaining) != "1" {
		t.Errorf("rate limit headers: %v", rec.Header())
	}

	// Method from X-Forwarded-Method, not the check request's GET.
	rec = f.do("GET", "http://gateway:8090/traefik",
		"X-Forwarded-Method", "POST", "X-Forwarded-Host", "hooli.app.example.com", "X-Forwarded-Uri", "/reports")
	expectDenied(t, rec, 403, "feature_disabled", "403")

	// Tenant in X-Forwarded-Uri's path; header source passes through.
	expectAllowed(t, f.do("GET", "/traefik", "X-Forwarded-Host", "api.example.com", "X-Forwarded-Uri", "/t/globex/x"), globex, "dedicated")
	expectAllowed(t, f.do("GET", "/traefik", "X-Forwarded-Host", "api.example.com", "X-Forwarded-Uri", "/", "X-Tenant-ID", "globex"), globex, "dedicated")

	// Denials keep their status: Traefik relays it to the client.
	expectDenied(t, f.do("GET", "/traefik", "X-Forwarded-Host", "nope.app.example.com", "X-Forwarded-Uri", "/"), 404, "tenant_not_found", "404")
}

func TestNGINXShape(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.do("GET", "http://127.0.0.1:8090/nginx", "Host", "127.0.0.1:8090",
		"X-Original-URI", "/api?q=1", "X-Original-Method", "GET", "X-Original-Host", "acme.app.example.com")
	expectAllowed(t, rec, acme, "eu-1")

	// X-Forwarded-Host works as well.
	expectAllowed(t, f.do("GET", "/nginx", "X-Original-URI", "/", "X-Forwarded-Host", "globex.app.example.com"), globex, "dedicated")

	// NGINX only accepts 2xx, 401 and 403: 404 becomes 403 with the real
	// status in X-Tenarium-Status.
	expectDenied(t, f.do("GET", "/nginx", "X-Original-URI", "/", "X-Original-Host", "nope.app.example.com"), 403, "tenant_not_found", "404")
	expectDenied(t, f.do("GET", "/nginx", "X-Original-URI", "/", "X-Original-Host", "frozen.app.example.com"), 403, "tenant_inactive", "403")

	// 429 becomes 403 too, keeping Retry-After for auth_request_set.
	for range 2 {
		f.do("GET", "/nginx", "X-Original-URI", "/", "X-Original-Host", "acme.app.example.com")
	}
	rec = f.do("GET", "/nginx", "X-Original-URI", "/", "X-Original-Host", "acme.app.example.com")
	expectDenied(t, rec, 403, "rate_limited", "429")
	if rec.Header().Get("Retry-After") != "1" {
		t.Errorf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
}

func TestAutoShape(t *testing.T) {
	f := newFixture(t, nil)
	// Traefik style.
	expectAllowed(t, f.do("GET", "/check", "X-Forwarded-Host", "acme.app.example.com", "X-Forwarded-Uri", "/x"), acme, "eu-1")
	// NGINX style.
	expectAllowed(t, f.do("GET", "/check", "X-Original-Host", "globex.app.example.com", "X-Original-URI", "/x"), globex, "dedicated")
	// Envoy style.
	expectAllowed(t, f.do("GET", "/check/t/globex/x", "Host", "api.example.com"), globex, "dedicated")
	// Real status codes.
	expectDenied(t, f.do("GET", "/check", "X-Original-Host", "nope.app.example.com", "X-Original-URI", "/"), 404, "tenant_not_found", "404")
	// Malformed original URI.
	expectDenied(t, f.do("GET", "/check", "X-Original-Host", "acme.app.example.com", "X-Original-URI", "%zz"), 400, "bad_request", "400")
	// Unknown endpoints.
	if rec := f.do("GET", "/other"); rec.Code != 404 || rec.Header().Get(gateway.HeaderError) != "" {
		t.Errorf("unexpected %d", rec.Code)
	}
}

func TestCells(t *testing.T) {
	f := newFixture(t, func(o *gateway.Options) {
		o.Cell.Default = "shared"
		o.RateLimit = gateway.RateLimitOptions{}
	})
	expectAllowed(t, f.do("GET", "/check/", "Host", "acme.app.example.com"), acme, "eu-1")          // label
	expectAllowed(t, f.do("GET", "/check/", "Host", "globex.app.example.com"), globex, "dedicated") // plan
	expectAllowed(t, f.do("GET", "/check/", "Host", "hooli.app.example.com"), hooli, "shared")      // default
	expectAllowed(t, f.do("GET", "/check/", "Host", "initech.app.example.com"), initech, "shared")  // invalid label

	f = newFixture(t, func(o *gateway.Options) {
		o.Cell.Label = "region"
		o.Cell.Func = func(t *tenantmw.Tenant) string {
			if t.Slug == "hooli" {
				return "custom"
			}
			return ""
		}
	})
	expectAllowed(t, f.do("GET", "/check/", "Host", "hooli.app.example.com"), hooli, "custom")
	expectAllowed(t, f.do("GET", "/check/", "Host", "acme.app.example.com"), acme, gateway.DefaultCell)

	if _, err := gateway.New(gateway.Options{Resolver: tenantmw.NewResolver(), Source: newSource(), Cell: gateway.CellOptions{Default: "a b"}}); err == nil {
		t.Error("invalid default cell accepted")
	}
}

func TestOptionalAndStatuses(t *testing.T) {
	f := newFixture(t, func(o *gateway.Options) {
		o.Optional = true
		o.AllowedStatuses = []tenantmw.Status{tenantmw.StatusActive, tenantmw.StatusSuspended}
	})
	rec := f.do("GET", "/check/", "Host", "www.example.com")
	if rec.Code != 200 || rec.Header().Get(gateway.HeaderTenantCell) != gateway.DefaultCell || rec.Header().Get(gateway.HeaderTenantID) != "" {
		t.Fatalf("optional: %d %v", rec.Code, rec.Header())
	}
	expectAllowed(t, f.do("GET", "/check/", "Host", "frozen.app.example.com"), frozen, gateway.DefaultCell)
}

func TestSourceFailure(t *testing.T) {
	src := newSource()
	src.err = errors.New("redis down")
	f := newFixture(t, func(o *gateway.Options) { o.Source = src })
	rec := f.do("GET", "/check/", "Host", "acme.app.example.com")
	expectDenied(t, rec, 503, "tenant_unavailable", "503")
	if strings.Contains(rec.Body.String(), "redis") {
		t.Errorf("leaks upstream error: %s", rec.Body)
	}
	expectDenied(t, f.do("GET", "/nginx", "X-Original-Host", "acme.app.example.com", "X-Original-URI", "/"), 403, "tenant_unavailable", "503")
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t, func(o *gateway.Options) { o.RateLimit.DefaultRate = 3 })
	acmeReq := func() *httptest.ResponseRecorder { return f.do("GET", "/check/", "Host", "acme.app.example.com") }

	// acme: rps=2, burst 2.
	for i, want := range []string{"1", "0"} {
		rec := acmeReq()
		expectAllowed(t, rec, acme, "eu-1")
		if got := rec.Header().Get(gateway.HeaderRateLimitRemaining); got != want {
			t.Errorf("request %d remaining %q, want %q", i, got, want)
		}
		if got := rec.Header().Get(gateway.HeaderRateLimitPolicy); got != "2;w=1;burst=2" {
			t.Errorf("policy %q", got)
		}
	}
	rec := acmeReq()
	expectDenied(t, rec, 429, "rate_limited", "429")
	if rec.Header().Get("Retry-After") != "1" || rec.Header().Get(gateway.HeaderRateLimitRemaining) != "0" || rec.Header().Get(gateway.HeaderRateLimitReset) != "1" {
		t.Errorf("headers %v", rec.Header())
	}
	f.clock.Advance(500 * time.Millisecond) // one token back
	expectAllowed(t, acmeReq(), acme, "eu-1")
	expectDenied(t, acmeReq(), 429, "rate_limited", "429")

	// globex: rps=-1 means unlimited, no headers.
	for range 10 {
		rec := f.do("GET", "/check/", "Host", "globex.app.example.com")
		expectAllowed(t, rec, globex, "dedicated")
		if rec.Header().Get(gateway.HeaderRateLimitLimit) != "" {
			t.Fatal("unlimited tenant got rate limit headers")
		}
	}

	// initech: rps=0 blocks everything.
	rec = f.do("GET", "/check/", "Host", "initech.app.example.com")
	expectDenied(t, rec, 429, "rate_limited", "429")
	if rec.Header().Get("Retry-After") != "" {
		t.Error("blocked tenant got Retry-After")
	}

	// hooli: no rps limit, DefaultRate 3.
	for range 3 {
		expectAllowed(t, f.do("GET", "/check/", "Host", "hooli.app.example.com"), hooli, gateway.DefaultCell)
	}
	expectDenied(t, f.do("GET", "/check/", "Host", "hooli.app.example.com"), 429, "rate_limited", "429")

	if got := counterValue(t, f.reg, "tenarium_gateway_rate_limited_total", nil); got != 4 {
		t.Errorf("rate_limited_total = %v", got)
	}
	if got := counterValue(t, f.reg, "tenarium_gateway_decisions_total", map[string]string{"mode": "check", "decision": "deny", "code": "rate_limited"}); got != 4 {
		t.Errorf("decisions deny/rate_limited = %v", got)
	}
	if got := counterValue(t, f.reg, "tenarium_gateway_decisions_total", map[string]string{"mode": "check", "decision": "allow", "code": "ok"}); got != 16 {
		t.Errorf("decisions allow = %v", got)
	}
	if n := histogramCount(t, f.reg, "tenarium_gateway_check_duration_seconds"); n != 20 {
		t.Errorf("histogram count = %d", n)
	}
}

func TestRateLimitPeriodAndBurst(t *testing.T) {
	src := &fakeSource{tenants: []*tenantmw.Tenant{{
		ID: "t1", Slug: "t1", Status: tenantmw.StatusActive, Limits: map[string]int64{"rpm": 60, "rpm_burst": 5},
	}}}
	f := newFixture(t, func(o *gateway.Options) {
		o.Source = src
		o.RateLimit.Metric, o.RateLimit.BurstMetric, o.RateLimit.Period = "rpm", "rpm_burst", time.Minute
	})
	for range 5 {
		if rec := f.do("GET", "/check/", "X-Tenant-ID", "t1"); rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
	}
	rec := f.do("GET", "/check/", "X-Tenant-ID", "t1")
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "1" || rec.Header().Get(gateway.HeaderRateLimitPolicy) != "60;w=60;burst=5" {
		t.Fatalf("got %d %v", rec.Code, rec.Header())
	}
}

type failingLimiter struct{}

func (failingLimiter) Allow(context.Context, string, gateway.Limit) (gateway.Decision, error) {
	return gateway.Decision{}, errors.New("boom")
}

func TestLimiterFailure(t *testing.T) {
	for _, open := range []bool{true, false} {
		f := newFixture(t, func(o *gateway.Options) {
			o.RateLimit.Limiter = failingLimiter{}
			o.RateLimit.FailOpen = open
		})
		rec := f.do("GET", "/check/", "Host", "acme.app.example.com")
		if open {
			expectAllowed(t, rec, acme, "eu-1")
		} else {
			expectDenied(t, rec, 503, "rate_limit_unavailable", "503")
		}
		if got := counterValue(t, f.reg, "tenarium_gateway_limiter_errors_total", nil); got != 1 {
			t.Errorf("limiter errors = %v", got)
		}
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := gateway.New(gateway.Options{}); err == nil {
		t.Error("missing resolver accepted")
	}
	_, err := gateway.New(gateway.Options{Resolver: tenantmw.NewResolver(), Source: newSource(),
		RateLimit: gateway.RateLimitOptions{Limiter: gateway.NewLocalLimiter()}})
	if err == nil {
		t.Error("rate limit without metric or default accepted")
	}
}

func TestOriginalRequest(t *testing.T) {
	r := httptest.NewRequest("HEAD", "http://auth/envoy/a%2Fb/c?x=1&y=2", nil)
	r.Header.Set("X-Forwarded-Proto", "https, http")
	or := gateway.OriginalRequest(r, gateway.ModeEnvoy, "/envoy")
	if or.Method != "HEAD" || or.Host != "auth" || or.URI != "/a%2Fb/c?x=1&y=2" || or.Scheme != "https" {
		t.Errorf("envoy: %+v", or)
	}
	r = httptest.NewRequest("GET", "http://auth/traefik", nil)
	r.Header.Set("X-Forwarded-Host", "a.example.com, b.example.com")
	or = gateway.OriginalRequest(r, gateway.ModeTraefik, "/traefik")
	if or.Host != "a.example.com" || or.URI != "/" || or.Method != "" {
		t.Errorf("traefik: %+v", or)
	}
	r = httptest.NewRequest("GET", "http://auth/nginx", nil)
	r.Header.Set("X-Original-URL", "https://acme.example.com/p?q")
	or = gateway.OriginalRequest(r, gateway.ModeNGINX, "/nginx")
	if or.URI != "https://acme.example.com/p?q" || or.Method != "GET" {
		t.Errorf("nginx: %+v", or)
	}
}
