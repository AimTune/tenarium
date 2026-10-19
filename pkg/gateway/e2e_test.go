package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/gateway"
	"github.com/AimTune/tenarium/pkg/tenantmw"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

const e2eKey = "test-api-key"

// fakeTenarium serves the parts of the Tenarium API that APISource and
// the token verifier use: tenants, entitlements and a JWKS.
type fakeTenarium struct {
	srv   *httptest.Server
	key   *ecdsa.PrivateKey
	calls atomic.Int64

	mu      sync.Mutex
	tenants map[string]map[string]any // by ID
	ents    map[string]map[string]any
}

func newFakeTenarium(t *testing.T) *fakeTenarium {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ft := &fakeTenarium{key: key, tenants: map[string]map[string]any{}, ents: map[string]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	})
	mux.HandleFunc("GET /v1/tenants/{ref}", func(w http.ResponseWriter, r *http.Request) {
		if t := ft.find(w, r); t != nil {
			_ = json.NewEncoder(w).Encode(t)
		}
	})
	mux.HandleFunc("GET /v1/tenants/{ref}/entitlements", func(w http.ResponseWriter, r *http.Request) {
		if t := ft.find(w, r); t != nil {
			ft.mu.Lock()
			defer ft.mu.Unlock()
			_ = json.NewEncoder(w).Encode(ft.ents[t["id"].(string)])
		}
	})
	ft.srv = httptest.NewServer(mux)
	t.Cleanup(ft.srv.Close)
	return ft
}

func (ft *fakeTenarium) find(w http.ResponseWriter, r *http.Request) map[string]any {
	ft.calls.Add(1)
	if r.Header.Get("Authorization") != "Bearer "+e2eKey {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"error":{"code":"unauthorized","message":"bad key"}}`)
		return nil
	}
	ref := r.PathValue("ref")
	ft.mu.Lock()
	defer ft.mu.Unlock()
	for id, t := range ft.tenants {
		if id == ref || t["slug"] == ref {
			return t
		}
	}
	w.WriteHeader(404)
	_, _ = io.WriteString(w, `{"error":{"code":"not_found","message":"tenant not found"}}`)
	return nil
}

func (ft *fakeTenarium) add(id, slug, status, plan string, labels map[string]string, features map[string]bool, limits map[string]int64) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.tenants[id] = map[string]any{"id": id, "slug": slug, "name": slug, "status": status, "plan": plan, "labels": labels}
	ft.ents[id] = map[string]any{"tenant_id": id, "plan": plan, "features": features, "limits": limits}
}

func (ft *fakeTenarium) token(t *testing.T, tid string) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: ft.key},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader(jose.HeaderKey("kid"), "k1"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": ft.srv.URL, "sub": "user-1", "aud": []string{"tenarium"}, "tid": tid,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// forwardAuthProxy emulates a proxy: it asks the gateway (Traefik or NGINX
// style) and, when allowed, routes to the cell named by X-Tenant-Cell,
// copying the tenant headers upstream and replacing client supplied ones.
func forwardAuthProxy(t *testing.T, authURL string, mode gateway.Mode, cells map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		areq, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, authURL, nil)
		areq.Header = r.Header.Clone()
		switch mode {
		case gateway.ModeTraefik:
			areq.Header.Set("X-Forwarded-Method", r.Method)
			areq.Header.Set("X-Forwarded-Host", r.Host)
			areq.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
		case gateway.ModeNGINX:
			areq.Header.Set("X-Original-Method", r.Method)
			areq.Header.Set("X-Original-Host", r.Host)
			areq.Header.Set("X-Original-URI", r.URL.RequestURI())
		}
		resp, err := http.DefaultClient.Do(areq)
		if err != nil {
			t.Errorf("auth call: %v", err)
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			for _, h := range []string{"Content-Type", "Retry-After", gateway.HeaderStatus, gateway.HeaderError} {
				if v := resp.Header.Get(h); v != "" {
					w.Header().Set(h, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			return
		}
		up := r.Clone(r.Context())
		for _, h := range gateway.UpstreamHeaders {
			up.Header.Del(h)
			if v := resp.Header.Get(h); v != "" {
				up.Header.Set(h, v)
			}
		}
		target, ok := cells[resp.Header.Get(gateway.HeaderTenantCell)]
		if !ok {
			w.WriteHeader(502)
			return
		}
		u, _ := url.Parse(target + r.URL.RequestURI())
		up.URL, up.RequestURI, up.Host = u, "", u.Host
		uresp, err := http.DefaultTransport.RoundTrip(up)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer uresp.Body.Close()
		w.WriteHeader(uresp.StatusCode)
		_, _ = io.Copy(w, uresp.Body)
	})
}

func cellServer(t *testing.T, name string) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, name+" "+r.Header.Get(gateway.HeaderTenantSlug)+" "+r.Header.Get(gateway.HeaderTenantPlan)+" "+r.Header.Get(gateway.HeaderTenantFeatures))
	}))
	t.Cleanup(s.Close)
	return s
}

func TestE2EWithTenariumAPI(t *testing.T) {
	ft := newFakeTenarium(t)
	ft.add("aaaaaaaa-0000-0000-0000-000000000001", "acme", "active", "pro", map[string]string{"cell": "eu-1"},
		map[string]bool{"sso": true}, map[string]int64{"rps": 5})
	ft.add("bbbbbbbb-0000-0000-0000-000000000002", "globex", "active", "free", nil,
		map[string]bool{}, map[string]int64{})
	ft.add("cccccccc-0000-0000-0000-000000000003", "frozen", "suspended", "free", nil, nil, nil)

	verifier, err := tenantmw.NewVerifier(tenantmw.VerifierConfig{JWKSURL: ft.srv.URL + "/.well-known/jwks.json", Issuer: ft.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	source := tenantmw.CachingSource(tenantmw.APISource(ft.srv.URL, e2eKey), time.Minute)
	reg := prometheus.NewRegistry()
	gw, err := gateway.New(gateway.Options{
		Resolver: tenantmw.NewResolver(
			tenantmw.FromToken(verifier),
			tenantmw.FromSubdomain("app.example.com"),
		),
		Source:         source,
		ExposeFeatures: true,
		RateLimit:      gateway.RateLimitOptions{Limiter: gateway.NewLocalLimiter(), Metric: "rps", DefaultRate: 1000},
		Metrics:        gateway.NewMetrics(reg),
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := httptest.NewServer(gw)
	t.Cleanup(auth.Close)

	cells := map[string]string{"eu-1": cellServer(t, "eu-1").URL, gateway.DefaultCell: cellServer(t, "default").URL}

	for _, mode := range []gateway.Mode{gateway.ModeTraefik, gateway.ModeNGINX} {
		t.Run(string(mode), func(t *testing.T) {
			proxy := httptest.NewServer(forwardAuthProxy(t, auth.URL+"/"+string(mode), mode, cells))
			t.Cleanup(proxy.Close)
			get := func(host string, hdr ...string) (int, string, http.Header) {
				req, _ := http.NewRequest("GET", proxy.URL+"/api/items", nil)
				req.Host = host
				for i := 0; i+1 < len(hdr); i += 2 {
					req.Header.Set(hdr[i], hdr[i+1])
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				return resp.StatusCode, string(b), resp.Header
			}

			// Routed to the tenant's cell; a spoofed X-Tenant-Slug is replaced.
			if code, body, _ := get("acme.app.example.com", gateway.HeaderTenantSlug, "evil"); code != 200 || body != "eu-1 acme pro sso" {
				t.Fatalf("acme: %d %q", code, body)
			}
			if code, body, _ := get("globex.app.example.com"); code != 200 || body != "default globex free " {
				t.Fatalf("globex: %d %q", code, body)
			}

			wantDenied := func(status, errCode string, hdr http.Header) {
				t.Helper()
				if hdr.Get(gateway.HeaderStatus) != status || hdr.Get(gateway.HeaderError) != errCode {
					t.Errorf("denial headers %v", hdr)
				}
			}
			code, _, hdr := get("nope.app.example.com")
			if mode == gateway.ModeNGINX && code != 403 || mode == gateway.ModeTraefik && code != 404 {
				t.Errorf("unknown tenant: %d", code)
			}
			wantDenied("404", "tenant_not_found", hdr)
			code, _, hdr = get("frozen.app.example.com")
			if code != 403 {
				t.Errorf("suspended: %d", code)
			}
			wantDenied("403", "tenant_inactive", hdr)

			// Tokens: the right tenant passes, another tenant's host is refused,
			// a forged token is 401 in both modes.
			if code, body, _ := get("acme.app.example.com", "Authorization", "Bearer "+ft.token(t, "aaaaaaaa-0000-0000-0000-000000000001")); code != 200 || !strings.HasPrefix(body, "eu-1 acme") {
				t.Errorf("token: %d %q", code, body)
			}
			code, _, hdr = get("globex.app.example.com", "Authorization", "Bearer "+ft.token(t, "aaaaaaaa-0000-0000-0000-000000000001"))
			if code != 403 || hdr.Get(gateway.HeaderError) != "tenant_mismatch" {
				t.Errorf("mismatch: %d %v", code, hdr)
			}
			tok := ft.token(t, "aaaaaaaa-0000-0000-0000-000000000001")
			code, _, _ = get("acme.app.example.com", "Authorization", "Bearer "+tok[:len(tok)-4]+"AAAA")
			if code != 401 {
				t.Errorf("forged token: %d", code)
			}
		})
	}

	// acme has rps=5: within a few checks the bucket is empty
	// (the subtests above already spent some tokens).
	limited := false
	for range 10 {
		req, _ := http.NewRequest("GET", auth.URL+"/check/x", nil)
		req.Host = "acme.app.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 429 {
			limited = true
			if resp.Header.Get("Retry-After") == "" || resp.Header.Get(gateway.HeaderRateLimitLimit) != "5" {
				t.Errorf("429 headers: %v", resp.Header)
			}
			break
		}
	}
	if !limited {
		t.Error("acme was never rate limited")
	}

	// The cache keeps API traffic low: each tenant reference loads once
	// (two calls each: tenant and entitlements).
	if n := ft.calls.Load(); n > 12 {
		t.Errorf("%d API calls, caching ineffective", n)
	}
	if counterValue(t, reg, "tenarium_gateway_decisions_total", map[string]string{"mode": "traefik", "decision": "allow"}) == 0 {
		t.Error("no allow decisions recorded")
	}
}

func TestRedisLimiter(t *testing.T) {
	addr := os.Getenv("TENARIUM_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TENARIUM_TEST_REDIS_ADDR not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	prefix := "tenarium-test:gw:" + time.Now().Format("150405.000000") + ":"
	// Two limiters (two replicas) share one bucket.
	a, b := gateway.NewRedisLimiter(rdb, prefix), gateway.NewRedisLimiter(rdb, prefix)
	lim := gateway.Limit{Rate: 1, Burst: 4}
	for i := range 4 {
		l := a
		if i%2 == 1 {
			l = b
		}
		d, err := l.Allow(ctx, "t1", lim)
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allowed || d.Remaining != int64(3-i) || d.Limit != 4 {
			t.Fatalf("request %d: %+v", i, d)
		}
	}
	d, err := b.Allow(ctx, "t1", lim)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed || d.RetryAfter <= 0 || d.RetryAfter > time.Second || d.Reset <= 3*time.Second || d.Reset > 4*time.Second {
		t.Fatalf("over limit: %+v", d)
	}
	ttl, err := rdb.PTTL(ctx, prefix+"t1").Result()
	if err != nil || ttl <= 0 || ttl > 5*time.Second {
		t.Fatalf("ttl %v %v", ttl, err)
	}
	// Other tenants are independent.
	if d, _ := a.Allow(ctx, "t2", lim); !d.Allowed {
		t.Fatal("t2 denied")
	}
	// The limiter runs on Redis server time; poll instead of trusting the
	// local clock to agree with it (VM clocks drift).
	time.Sleep(d.RetryAfter)
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		d, err := a.Allow(ctx, "t1", lim)
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("token never came back: %+v", d)
		}
	}

	// Through the gateway.
	reg := prometheus.NewRegistry()
	gw, err := gateway.New(gateway.Options{
		Resolver:  tenantmw.NewResolver(tenantmw.FromHeader("X-Tenant-ID")),
		Source:    newSource(),
		RateLimit: gateway.RateLimitOptions{Limiter: gateway.NewRedisLimiter(rdb, prefix+"gw:"), Metric: "rps"},
		Metrics:   gateway.NewMetrics(reg),
	})
	if err != nil {
		t.Fatal(err)
	}
	codes := []int{}
	for range 3 {
		r := httptest.NewRequest("GET", "/check/", nil)
		r.Header.Set("X-Tenant-ID", "acme")
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, r)
		codes = append(codes, rec.Code)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Fatalf("codes %v", codes)
	}
	_ = rdb.Del(ctx, prefix+"t1", prefix+"t2", prefix+"gw:"+acme.ID).Err()
}
