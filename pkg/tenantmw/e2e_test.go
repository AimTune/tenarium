package tenantmw_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/server"
	"github.com/AimTune/tenarium/pkg/tenantmw"
	redisplugin "github.com/AimTune/tenarium/plugins/redis"
	"github.com/redis/go-redis/v9"
)

const e2eKey = "e2e-api-key"

// startTenarium runs a real in-process Tenarium whose token issuer is its
// own URL, so discovery and JWKS work end to end.
func startTenarium(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	cfg := server.DefaultConfig()
	cfg.Server.APIKeys = []string{e2eKey}
	cfg.Users.PublicURL = base
	cfg.Auth.RateLimit = 0
	cfg.Bootstrap.Users = []server.BootstrapUser{{Email: "ada@example.com", Name: "Ada", Password: "ada's long passphrase"}}
	cfg.Bootstrap.Plans = []server.BootstrapPlan{{
		ID: "pro", Name: "Pro",
		Features: map[string]bool{"sso": true, "beta": false},
		Limits:   map[string]int64{"api_calls": 2},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	app, err := server.New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return base
}

func call(t *testing.T, method, url, auth string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rd)
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAgainstRealTenarium(t *testing.T) {
	base := startTenarium(t)
	ctx := context.Background()

	// Two tenants; Ada is a member of acme only.
	code, acmeT := call(t, "POST", base+"/v1/tenants", e2eKey, map[string]any{"slug": "acme", "name": "Acme", "plan": "pro"})
	if code != 201 {
		t.Fatalf("create acme: %d %v", code, acmeT)
	}
	acmeID := acmeT["id"].(string)
	if code, out := call(t, "POST", base+"/v1/tenants", e2eKey, map[string]any{"slug": "globex", "name": "Globex"}); code != 201 {
		t.Fatalf("create globex: %d %v", code, out)
	}
	if code, m := call(t, "POST", base+"/v1/tenants/acme/members", e2eKey, map[string]any{"email": "ada@example.com", "role": "viewer"}); code != 201 || m["status"] != "active" {
		t.Fatalf("add member: %d %v", code, m)
	}
	code, tok := call(t, "POST", base+"/v1/auth/token", "", map[string]any{
		"grant_type": "password", "email": "ada@example.com", "password": "ada's long passphrase", "tenant": "acme",
	})
	if code != 200 {
		t.Fatalf("token: %d %v", code, tok)
	}
	access := tok["access_token"].(string)

	verifier, err := tenantmw.DiscoverVerifier(ctx, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := tenantmw.CachingSource(tenantmw.APISource(base, e2eKey), time.Minute)
	resolver := tenantmw.NewResolver(tenantmw.FromToken(verifier), tenantmw.FromSubdomain("app.example.com"))
	var claims *tenantmw.Claims
	mw := func(next http.Handler) http.Handler {
		return tenantmw.Middleware(resolver, source, tenantmw.Options{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims = tenantmw.ClaimsFromContext(r.Context())
			next.ServeHTTP(w, r)
		}))
	}

	// A real Tenarium token resolves its tenant with effective entitlements.
	res := serve(mw, request("localhost", "/", "Authorization", "Bearer "+access))
	if res.code != 200 || res.tenant.ID != acmeID || res.tenant.Slug != "acme" || res.tenant.Plan != "pro" {
		t.Fatalf("token: %+v", res)
	}
	if !res.tenant.HasFeature("sso") || res.tenant.HasFeature("beta") {
		t.Fatalf("features: %v", res.tenant.Features)
	}
	if l, ok := res.tenant.Limit("api_calls"); !ok || l != 2 {
		t.Fatalf("limits: %v", res.tenant.Limits)
	}
	if claims == nil || claims.Email != "ada@example.com" || len(claims.Roles) == 0 {
		t.Fatalf("claims: %+v", claims)
	}
	if res := serve(mw, request("acme.app.example.com", "/", "Authorization", "Bearer "+access)); res.code != 200 {
		t.Fatalf("own subdomain: %+v", res)
	}
	if res := serve(mw, request("globex.app.example.com", "/", "Authorization", "Bearer "+access)); res.code != 403 {
		t.Fatalf("token for acme on globex: %+v", res)
	}
	tampered := access[:len(access)-4] + "AAAA"
	if res := serve(mw, request("localhost", "/", "Authorization", "Bearer "+tampered)); res.code != 401 {
		t.Fatalf("tampered token: %+v", res)
	}

	// APISource: unknown tenants are 404; suspension shows after the
	// cache entry is dropped.
	if res := serve(mw, request("nobody.app.example.com", "/")); res.code != 404 {
		t.Fatalf("unknown: %+v", res)
	}
	if code, _ := call(t, "POST", base+"/v1/tenants/acme/suspend", e2eKey, map[string]any{"reason": "unpaid"}); code != 200 {
		t.Fatalf("suspend: %d", code)
	}
	source.Purge()
	if res := serve(mw, request("acme.app.example.com", "/")); res.code != 403 {
		t.Fatalf("suspended: %+v", res)
	}
	if code, _ := call(t, "POST", base+"/v1/tenants/acme/resume", e2eKey, nil); code != 200 {
		t.Fatalf("resume: %d", code)
	}
	source.Purge()

	// Usage against the real quota: limit 2, the third call is refused.
	rec := tenantmw.NewUsageRecorder(tenantmw.NewClient(base, e2eKey))
	for i := int64(1); i <= 2; i++ {
		if u, err := rec.Record(ctx, acmeID, "api_calls", 1); err != nil || u.Value != i {
			t.Fatalf("usage %d: %+v %v", i, u, err)
		}
	}
	if _, err := rec.Record(ctx, acmeID, "api_calls", 1); !errors.Is(err, tenantmw.ErrQuotaExceeded) {
		t.Fatalf("quota: %v", err)
	}
}

func TestRedisSource(t *testing.T) {
	addr := os.Getenv("TENARIUM_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TENARIUM_TEST_REDIS_ADDR not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	defer rdb.Close()
	ctx := context.Background()
	prefix := "tenantmw-test-" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "") + ":"
	t.Cleanup(func() {
		keys, _ := rdb.Keys(ctx, prefix+"*").Result()
		if len(keys) > 0 {
			rdb.Del(ctx, keys...)
		}
	})

	// Write keys exactly as the redis plugin does.
	cached := redisplugin.CachedTenant{
		ID: acme.ID, Slug: "acme", Name: "Acme", Status: "active", Plan: "pro",
		Labels:   map[string]string{"region": "eu"},
		Features: map[string]bool{"sso": true}, Limits: map[string]int64{"seats": 5},
		Version: 3, UpdatedAt: time.Now().UTC(),
	}
	raw, _ := json.Marshal(cached)
	if err := rdb.Set(ctx, prefix+"tenant:"+acme.ID, raw, 0).Err(); err != nil {
		t.Fatal(err)
	}
	rdb.Set(ctx, prefix+"tenant-slug:acme", acme.ID, 0)

	src := tenantmw.RedisSource(rdb, prefix)
	for _, ref := range []string{acme.ID, "acme"} {
		tn, err := src.Tenant(ctx, ref)
		if err != nil || tn.ID != acme.ID || tn.Slug != "acme" || tn.Status != tenantmw.StatusActive ||
			!tn.HasFeature("sso") || tn.Limits["seats"] != 5 || tn.Labels["region"] != "eu" || tn.Version != 3 {
			t.Fatalf("%s: %+v %v", ref, tn, err)
		}
	}
	if _, err := src.Tenant(ctx, "ghost"); !errors.Is(err, tenantmw.ErrNotFound) {
		t.Fatalf("ghost: %v", err)
	}

	// The plugin's own reader agrees with ours.
	if ct, err := redisplugin.ReadTenant(ctx, rdb, prefix, "acme"); err != nil || ct.ID != acme.ID {
		t.Fatalf("plugin ReadTenant: %+v %v", ct, err)
	}

	// Through the middleware, with a suspended tenant.
	cached.Status = "suspended"
	raw, _ = json.Marshal(cached)
	rdb.Set(ctx, prefix+"tenant:"+acme.ID, raw, 0)
	mw := tenantmw.Middleware(tenantmw.NewResolver(tenantmw.FromSubdomain("app.example.com")), src, tenantmw.Options{})
	if res := serve(mw, request("acme.app.example.com", "/")); res.code != 403 {
		t.Fatalf("suspended via redis: %+v", res)
	}
}
