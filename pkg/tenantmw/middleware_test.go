package tenantmw_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/tenantmw"
)

func TestResolverSources(t *testing.T) {
	src := newFakeSource(acme, globex)
	cases := []struct {
		name string
		opt  tenantmw.ResolverOption
		req  *http.Request
		want string // slug, "" = 404
	}{
		{"subdomain", tenantmw.FromSubdomain("app.example.com"), request("acme.app.example.com:8443", "/"), "acme"},
		{"subdomain case and trailing dot", tenantmw.FromSubdomain(".App.Example.com."), request("ACME.app.example.com.", "/"), "acme"},
		{"subdomain base itself", tenantmw.FromSubdomain("app.example.com"), request("app.example.com", "/"), ""},
		{"subdomain nested", tenantmw.FromSubdomain("app.example.com"), request("x.acme.app.example.com", "/"), ""},
		{"subdomain other domain", tenantmw.FromSubdomain("app.example.com"), request("acme.evil.com", "/"), ""},
		{"header slug", tenantmw.FromHeader("X-Tenant-ID"), request("h", "/", "X-Tenant-ID", "globex"), "globex"},
		{"header id", tenantmw.FromHeader("X-Tenant-ID"), request("h", "/", "X-Tenant-ID", acme.ID), "acme"},
		{"header missing", tenantmw.FromHeader("X-Tenant-ID"), request("h", "/"), ""},
		{"path", tenantmw.FromPathPrefix(), request("h", "/t/acme/projects/1"), "acme"},
		{"path bare", tenantmw.FromPathPrefix(), request("h", "/t/globex"), "globex"},
		{"path empty", tenantmw.FromPathPrefix(), request("h", "/t//x"), ""},
		{"path other", tenantmw.FromPathPrefix(), request("h", "/api/acme"), ""},
		{"unknown tenant", tenantmw.FromHeader("X-Tenant-ID"), request("h", "/", "X-Tenant-ID", "nope"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mw := tenantmw.Middleware(tenantmw.NewResolver(c.opt), src, tenantmw.Options{})
			res := serve(mw, c.req)
			if c.want == "" {
				if res.code != 404 {
					t.Fatalf("code %d, want 404 (%s)", res.code, res.body)
				}
				return
			}
			if res.code != 200 || res.tenant == nil || res.tenant.Slug != c.want {
				t.Fatalf("code %d tenant %+v body %s, want %s", res.code, res.tenant, res.body, c.want)
			}
		})
	}
}

func TestResolverPrecedence(t *testing.T) {
	src := newFakeSource(acme, globex)
	req := request("acme.app.example.com", "/t/globex/x", "X-Tenant-ID", "globex")

	headerFirst := tenantmw.NewResolver(tenantmw.FromHeader("X-Tenant-ID"), tenantmw.FromSubdomain("app.example.com"))
	if res := serve(tenantmw.Middleware(headerFirst, src, tenantmw.Options{}), req); res.tenant.Slug != "globex" {
		t.Fatalf("header first: %+v", res)
	}
	subFirst := tenantmw.NewResolver(tenantmw.FromSubdomain("app.example.com"), tenantmw.FromHeader("X-Tenant-ID"), tenantmw.FromPathPrefix())
	if res := serve(tenantmw.Middleware(subFirst, src, tenantmw.Options{}), req); res.tenant.Slug != "acme" {
		t.Fatalf("subdomain first: %+v", res)
	}

	// Later sources are not consulted once one matched (no token involved).
	var calls atomic.Int64
	counting := tenantmw.With(tenantmw.ExtractorFunc(func(*http.Request) (tenantmw.Match, bool, error) {
		calls.Add(1)
		return tenantmw.Match{}, false, nil
	}))
	r := tenantmw.NewResolver(tenantmw.FromSubdomain("app.example.com"), counting)
	if _, err := r.Resolve(req); err != nil || calls.Load() != 0 {
		t.Fatalf("later source consulted: %v %d", err, calls.Load())
	}
	if _, err := r.Resolve(request("other.host", "/")); !errors.Is(err, tenantmw.ErrNoTenant) || calls.Load() != 1 {
		t.Fatalf("fallthrough: %v %d", err, calls.Load())
	}
}

func TestMiddlewareStatusAndOptional(t *testing.T) {
	src := newFakeSource(acme, frozen)
	r := tenantmw.NewResolver(tenantmw.FromHeader("X-Tenant"))
	mw := tenantmw.Middleware(r, src, tenantmw.Options{})

	res := serve(mw, request("h", "/", "X-Tenant", "frozen"))
	if res.code != 403 || !strings.Contains(res.body, "tenant_inactive") || res.tenant != nil {
		t.Fatalf("suspended: %+v", res)
	}
	if res := serve(mw, request("h", "/")); res.code != 404 || !strings.Contains(res.body, "tenant_required") {
		t.Fatalf("no tenant: %+v", res)
	}

	lenient := tenantmw.Middleware(r, src, tenantmw.Options{
		AllowedStatuses: []tenantmw.Status{tenantmw.StatusActive, tenantmw.StatusSuspended},
		Optional:        true,
	})
	if res := serve(lenient, request("h", "/", "X-Tenant", "frozen")); res.code != 200 || res.tenant.Slug != "frozen" {
		t.Fatalf("allowed suspended: %+v", res)
	}
	if res := serve(lenient, request("h", "/")); res.code != 200 || res.tenant != nil {
		t.Fatalf("optional: %+v", res)
	}

	deleted := newFakeSource(&tenantmw.Tenant{ID: "d", Slug: "gone", Status: tenantmw.StatusDeleted})
	if res := serve(tenantmw.Middleware(r, deleted, tenantmw.Options{}), request("h", "/", "X-Tenant", "gone")); res.code != 404 {
		t.Fatalf("deleted: %+v", res)
	}

	failing := tenantmw.SourceFunc(func(context.Context, string) (*tenantmw.Tenant, error) {
		return nil, errors.New("redis down: secret detail")
	})
	res = serve(tenantmw.Middleware(r, failing, tenantmw.Options{}), request("h", "/", "X-Tenant", "acme"))
	if res.code != 503 || strings.Contains(res.body, "secret") {
		t.Fatalf("source failure: %+v", res)
	}
}

func TestRequireFeature(t *testing.T) {
	src := newFakeSource(acme, globex)
	mw := tenantmw.Middleware(tenantmw.NewResolver(tenantmw.FromHeader("X-Tenant")), src, tenantmw.Options{})
	chain := func(next http.Handler) http.Handler { return mw(tenantmw.RequireFeature("sso")(next)) }

	if res := serve(chain, request("h", "/", "X-Tenant", "acme")); res.code != 200 {
		t.Fatalf("acme has sso: %+v", res)
	}
	if res := serve(chain, request("h", "/", "X-Tenant", "globex")); res.code != 403 || !strings.Contains(res.body, "feature_disabled") {
		t.Fatalf("globex lacks sso: %+v", res)
	}
	if res := serve(tenantmw.RequireFeature("sso"), request("h", "/")); res.code != 404 {
		t.Fatalf("no tenant: %+v", res)
	}

	if !acme.HasFeature("sso") || acme.HasFeature("nope") {
		t.Fatal("HasFeature")
	}
	if v, ok := acme.Limit("seats"); !ok || v != 10 {
		t.Fatal("Limit seats")
	}
	if _, ok := acme.Limit("storage"); ok {
		t.Fatal("absent limit must be unlimited")
	}
	var nilTenant *tenantmw.Tenant
	if nilTenant.HasFeature("sso") {
		t.Fatal("nil tenant")
	}
}

func TestTokenResolutionAndMismatch(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier(0)
	src := newFakeSource(acme, globex)

	for _, tokenFirst := range []bool{true, false} {
		opts := []tenantmw.ResolverOption{tenantmw.FromSubdomain("app.example.com"), tenantmw.FromToken(v)}
		if tokenFirst {
			opts[0], opts[1] = opts[1], opts[0]
		}
		var claims *tenantmw.Claims
		mw := func(next http.Handler) http.Handler {
			return tenantmw.Middleware(tenantmw.NewResolver(opts...), src, tenantmw.Options{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				claims = tenantmw.ClaimsFromContext(r.Context())
				next.ServeHTTP(w, r)
			}))
		}
		acmeTok := "Bearer " + is.token(acme.ID, tokenOpts{})

		// Token alone.
		claims = nil
		res := serve(mw, request("localhost", "/", "Authorization", acmeTok))
		if res.code != 200 || res.tenant.ID != acme.ID || claims == nil || claims.Subject != "user-1" || claims.TenantID != acme.ID {
			t.Fatalf("token only (first=%v): %+v %+v", tokenFirst, res, claims)
		}
		// Token and matching subdomain.
		if res := serve(mw, request("acme.app.example.com", "/", "Authorization", acmeTok)); res.code != 200 || res.tenant.ID != acme.ID {
			t.Fatalf("matching subdomain (first=%v): %+v", tokenFirst, res)
		}
		// Token of acme used on globex's subdomain.
		if res := serve(mw, request("globex.app.example.com", "/", "Authorization", acmeTok)); res.code != 403 || !strings.Contains(res.body, "tenant_mismatch") {
			t.Fatalf("mismatch (first=%v): %+v", tokenFirst, res)
		}
		// Token of acme used on an unknown subdomain.
		if res := serve(mw, request("ghost.app.example.com", "/", "Authorization", acmeTok)); res.code != 403 && res.code != 404 {
			t.Fatalf("unknown subdomain (first=%v): %+v", tokenFirst, res)
		}
	}

	r := tenantmw.NewResolver(tenantmw.FromToken(v), tenantmw.FromHeader("X-Tenant"))
	mw := tenantmw.Middleware(r, src, tenantmw.Options{})
	bad := []struct {
		name, auth string
		code       int
	}{
		{"expired", "Bearer " + is.token(acme.ID, tokenOpts{exp: -time.Hour}), 401},
		{"wrong audience", "Bearer " + is.token(acme.ID, tokenOpts{aud: "other"}), 401},
		{"tampered", "Bearer " + tamper(is.token(acme.ID, tokenOpts{}), globex.ID), 401},
		// Foreign tokens and API keys are ignored: the header decides.
		{"foreign issuer", "Bearer " + is.token(acme.ID, tokenOpts{iss: "https://other"}), 200},
		{"api key", "Bearer some-api-key", 200},
	}
	for _, b := range bad {
		res := serve(mw, request("h", "/", "Authorization", b.auth, "X-Tenant", "globex"))
		if res.code != b.code {
			t.Fatalf("%s: %+v", b.name, res)
		}
	}
}

// tamper swaps the tid in the payload but keeps the signature.
func tamper(tok, tid string) string {
	parts := strings.Split(tok, ".")
	payload, _ := base64URLDecode(parts[1])
	payload = []byte(strings.Replace(string(payload), acme.ID, tid, 1))
	parts[1] = base64URLEncode(payload)
	return strings.Join(parts, ".")
}

func TestVerifierRefreshesOnUnknownKid(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier(time.Millisecond)
	ctx := context.Background()
	if _, err := v.Verify(ctx, is.token(acme.ID, tokenOpts{})); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, is.token(acme.ID, tokenOpts{})); err != nil || is.fetches.Load() != 1 {
		t.Fatalf("keys not cached: %v fetches=%d", err, is.fetches.Load())
	}
	is.rotate()
	time.Sleep(2 * time.Millisecond)
	c, err := v.Verify(ctx, is.token(acme.ID, tokenOpts{}))
	if err != nil || c.TenantID != acme.ID || is.fetches.Load() != 2 {
		t.Fatalf("after rotation: %v fetches=%d", err, is.fetches.Load())
	}

	// Unknown kids refresh at most once per MinRefreshInterval.
	slow := is.verifier(time.Hour)
	if _, err := slow.Verify(ctx, is.token(acme.ID, tokenOpts{})); err != nil {
		t.Fatal(err)
	}
	before := is.fetches.Load()
	is.rotate()
	for range 3 {
		if _, err := slow.Verify(ctx, is.token(acme.ID, tokenOpts{})); !errors.Is(err, tenantmw.ErrInvalidToken) {
			t.Fatalf("unknown kid within interval: %v", err)
		}
	}
	if is.fetches.Load() != before {
		t.Fatalf("refetched within interval: %d -> %d", before, is.fetches.Load())
	}
}

func TestCustomDomain(t *testing.T) {
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/domains/resolve" || r.Header.Get("Authorization") != "Bearer key" {
			http.Error(w, "bad request", 400)
			return
		}
		if r.URL.Query().Get("host") == "shop.acme.com" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tenant_id":"` + acme.ID + `","slug":"acme","hostname":"shop.acme.com"}`))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"no such domain"}}`))
	}))
	defer api.Close()

	domains := tenantmw.CachingDomains(tenantmw.NewClient(api.URL, "key"), time.Minute)
	r := tenantmw.NewResolver(tenantmw.FromSubdomain("app.example.com"), tenantmw.FromCustomDomain(domains))
	mw := tenantmw.Middleware(r, newFakeSource(acme, globex), tenantmw.Options{})

	for range 3 {
		if res := serve(mw, request("Shop.Acme.com:443", "/")); res.code != 200 || res.tenant.ID != acme.ID {
			t.Fatalf("custom domain: %+v", res)
		}
		if res := serve(mw, request("unknown.example.org", "/")); res.code != 404 {
			t.Fatalf("unknown domain: %+v", res)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("domain lookups not cached: %d calls", calls.Load())
	}
	// The subdomain wins without a domain lookup.
	if res := serve(mw, request("globex.app.example.com", "/")); res.tenant.Slug != "globex" || calls.Load() != 2 {
		t.Fatalf("subdomain first: %+v calls=%d", res, calls.Load())
	}
}

func TestCachingSource(t *testing.T) {
	src := newFakeSource(acme)
	cs := tenantmw.CachingSource(src, time.Hour)
	ctx := context.Background()
	for range 5 {
		if tn, err := cs.Tenant(ctx, "acme"); err != nil || tn.ID != acme.ID {
			t.Fatal(tn, err)
		}
	}
	if src.calls.Load() != 1 {
		t.Fatalf("positive cache: %d calls", src.calls.Load())
	}
	for range 5 {
		if _, err := cs.Tenant(ctx, "ghost"); !errors.Is(err, tenantmw.ErrNotFound) {
			t.Fatal(err)
		}
	}
	if src.calls.Load() != 2 {
		t.Fatalf("negative cache: %d calls", src.calls.Load())
	}
	cs.Invalidate("acme")
	_, _ = cs.Tenant(ctx, "acme")
	if src.calls.Load() != 3 {
		t.Fatalf("invalidate: %d calls", src.calls.Load())
	}

	// Without negative caching unknown tenants hit the source each time.
	src2 := newFakeSource()
	noNeg := tenantmw.CachingSource(src2, time.Hour).SetNegativeTTL(0)
	_, _ = noNeg.Tenant(ctx, "ghost")
	_, _ = noNeg.Tenant(ctx, "ghost")
	if src2.calls.Load() != 2 {
		t.Fatalf("negative TTL 0: %d calls", src2.calls.Load())
	}

	// Errors other than not-found are never cached.
	var n atomic.Int64
	flaky := tenantmw.CachingSource(tenantmw.SourceFunc(func(context.Context, string) (*tenantmw.Tenant, error) {
		n.Add(1)
		return nil, errors.New("boom")
	}), time.Hour)
	_, _ = flaky.Tenant(ctx, "x")
	_, _ = flaky.Tenant(ctx, "x")
	if n.Load() != 2 {
		t.Fatalf("errors cached: %d", n.Load())
	}

	// Short TTL expires.
	src3 := newFakeSource(acme)
	short := tenantmw.CachingSource(src3, 5*time.Millisecond)
	_, _ = short.Tenant(ctx, "acme")
	time.Sleep(10 * time.Millisecond)
	_, _ = short.Tenant(ctx, "acme")
	if src3.calls.Load() != 2 {
		t.Fatalf("ttl expiry: %d calls", src3.calls.Load())
	}
}

func TestCachingSourceDedupsConcurrentMisses(t *testing.T) {
	src := newFakeSource(acme)
	src.delay = 50 * time.Millisecond
	cs := tenantmw.CachingSource(src, time.Hour)
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if tn, err := cs.Tenant(context.Background(), "acme"); err != nil || tn.ID != acme.ID {
				t.Error(tn, err)
			}
		})
	}
	wg.Wait()
	if src.calls.Load() != 1 {
		t.Fatalf("concurrent misses: %d calls", src.calls.Load())
	}

	// A canceled waiter returns early without breaking the shared load.
	src.delay = 50 * time.Millisecond
	cs.Invalidate("acme")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if _, err := cs.Tenant(ctx, "acme"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled waiter: %v", err)
	}
	if tn, err := cs.Tenant(context.Background(), "acme"); err != nil || tn.ID != acme.ID || src.calls.Load() != 2 {
		t.Fatalf("after cancel: %v calls=%d", err, src.calls.Load())
	}
}

func TestUsageRecorderQuota(t *testing.T) {
	var value atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tenants/"+acme.ID+"/usage/api_calls" {
			http.Error(w, "unexpected", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if value.Load() >= 2 {
			w.WriteHeader(429)
			_, _ = w.Write([]byte(`{"error":{"code":"quota_exceeded","message":"api_calls limit 2 reached"}}`))
			return
		}
		v := value.Add(1)
		_, _ = w.Write([]byte(`{"metric":"api_calls","value":` + itoa(v) + `,"limit":2}`))
	}))
	defer api.Close()

	rec := tenantmw.NewUsageRecorder(tenantmw.NewClient(api.URL, "key"))
	ctx := tenantmw.NewContext(context.Background(), acme)
	for i := int64(1); i <= 2; i++ {
		u, err := rec.RecordFor(ctx, "api_calls", 1)
		if err != nil || u.Value != i || u.Limit == nil || *u.Limit != 2 {
			t.Fatalf("record %d: %+v %v", i, u, err)
		}
	}
	_, err := rec.Record(ctx, acme.ID, "api_calls", 1)
	var apiErr *tenantmw.APIError
	if !errors.Is(err, tenantmw.ErrQuotaExceeded) || !errors.As(err, &apiErr) || apiErr.Code != "quota_exceeded" {
		t.Fatalf("quota: %v", err)
	}
	if tenantmw.StatusCode(err) != 429 {
		t.Fatalf("status code: %d", tenantmw.StatusCode(err))
	}
	if _, err := rec.RecordFor(context.Background(), "api_calls", 1); !errors.Is(err, tenantmw.ErrNoTenant) {
		t.Fatalf("no tenant: %v", err)
	}
}
