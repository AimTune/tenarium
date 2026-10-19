package server_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/server"
)

func baseConfig() server.Config {
	cfg := server.DefaultConfig()
	cfg.Server.APIKeys = []string{apiKey}
	cfg.Events.PollInterval = 20 * time.Millisecond
	cfg.Events.LeaseTTL = time.Second
	return cfg
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPlansMembersUsageAPI(t *testing.T) {
	cfg := baseConfig()
	cfg.Tenants.RequireKnownPlans = true
	cfg.Bootstrap.Plans = []server.BootstrapPlan{
		{ID: "free", Features: map[string]bool{"sso": false}, Limits: map[string]int64{"members": 1, "api_calls": 2}},
	}
	c := client{t: t, base: startServer(t, cfg)}

	code, plans := c.do("GET", "/v1/plans", nil)
	if code != 200 || len(plans["items"].([]any)) != 1 {
		t.Fatalf("bootstrap plans: %d %v", code, plans)
	}
	if code, body := c.do("POST", "/v1/plans", map[string]any{"id": "pro", "name": "Pro", "features": map[string]bool{"sso": true}, "limits": map[string]int{"members": 10}}); code != 201 {
		t.Fatalf("create plan: %d %v", code, body)
	}
	if code, _ := c.do("POST", "/v1/tenants", map[string]any{"slug": "x", "name": "X", "plan": "gold"}); code != 400 {
		t.Fatalf("unknown plan: %d", code)
	}
	code, tn := c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme", "plan": "free"})
	if code != 201 {
		t.Fatalf("create tenant: %d %v", code, tn)
	}

	if code, m := c.do("POST", "/v1/tenants/acme/members", map[string]any{"email": "a@acme.io", "role": "owner"}); code != 201 || m["status"] != "invited" {
		t.Fatalf("add member: %d %v", code, m)
	}
	if code, body := c.do("POST", "/v1/tenants/acme/members", map[string]any{"email": "b@acme.io", "role": "member"}); code != 429 {
		t.Fatalf("members quota: %d %v", code, body)
	}

	for i := range 2 {
		if code, u := c.do("POST", "/v1/tenants/acme/usage/api_calls", map[string]any{"delta": 1}); code != 200 || u["value"] != float64(i+1) {
			t.Fatalf("usage: %d %v", code, u)
		}
	}
	if code, _ := c.do("POST", "/v1/tenants/acme/usage/api_calls", map[string]any{"delta": 1}); code != 429 {
		t.Fatalf("usage quota: %d", code)
	}

	// Upgrade lifts the limit; entitlements reflect the new plan.
	if code, body := c.do("PATCH", "/v1/tenants/acme", map[string]any{"plan": "pro"}); code != 200 {
		t.Fatalf("upgrade: %d %v", code, body)
	}
	_, ent := c.do("GET", "/v1/tenants/acme/entitlements", nil)
	if ent["features"].(map[string]any)["sso"] != true {
		t.Fatalf("entitlements after upgrade: %v", ent)
	}
	if code, _ := c.do("POST", "/v1/tenants/acme/members", map[string]any{"email": "b@acme.io", "role": "member"}); code != 201 {
		t.Fatalf("member after upgrade: %d", code)
	}
	if code, _ := c.do("DELETE", "/v1/plans/pro", nil); code != 409 {
		t.Fatalf("delete plan in use: %d", code)
	}
}

func TestIdempotencyKey(t *testing.T) {
	c := client{t: t, base: startServer(t, baseConfig())}
	h := map[string]string{"Idempotency-Key": "create-acme-1"}
	body := map[string]any{"slug": "acme", "name": "Acme"}

	code1, first, _ := c.doH("POST", "/v1/tenants", body, h)
	code2, second, hdr := c.doH("POST", "/v1/tenants", body, h)
	if code1 != 201 || code2 != 201 || first["id"] != second["id"] || hdr.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay: %d %d %v %v", code1, code2, first["id"], second["id"])
	}
	if code, _, _ := c.doH("POST", "/v1/tenants", map[string]any{"slug": "other", "name": "O"}, h); code != 422 {
		t.Fatalf("key reuse with different body: %d", code)
	}
	if code, _ := c.do("POST", "/v1/tenants", body); code != 409 {
		t.Fatalf("without key the duplicate must conflict: %d", code)
	}
}

func TestTenantScopedPrincipal(t *testing.T) {
	cfg := baseConfig()
	cfg.Plugins = []server.PluginSpec{{Plugin: "e2e"}}
	c := client{t: t, base: startServer(t, cfg)}

	_, org := c.do("POST", "/v1/tenants", map[string]any{"slug": "org", "name": "Org"})
	_, other := c.do("POST", "/v1/tenants", map[string]any{"slug": "other", "name": "Other"})
	waitFor(t, "tenants active", func() bool {
		_, a := c.do("GET", "/v1/tenants/org", nil)
		_, b := c.do("GET", "/v1/tenants/other", nil)
		return a["status"] == "active" && b["status"] == "active"
	})
	admin := map[string]string{"X-E2E-User": "alice", "X-E2E-Tenant": org["id"].(string)}

	if code, _, _ := c.doH("GET", "/v1/tenants/org", nil, admin); code != 200 {
		t.Fatalf("own tenant: %d", code)
	}
	if code, _, _ := c.doH("GET", "/v1/tenants/"+other["id"].(string), nil, admin); code != 403 {
		t.Fatalf("other tenant: %d", code)
	}
	code, ws, _ := c.doH("POST", "/v1/tenants", map[string]any{"slug": "ws", "name": "WS", "parent_id": "org"}, admin)
	if code != 201 {
		t.Fatalf("create child: %d %v", code, ws)
	}
	for _, extra := range []map[string]any{{"plan": "enterprise"}, {"limits": map[string]int{"members": 1000}}} {
		body := map[string]any{"slug": "ws2", "name": "WS2", "parent_id": "org"}
		for k, v := range extra {
			body[k] = v
		}
		if code, _, _ := c.doH("POST", "/v1/tenants", body, admin); code != 403 {
			t.Fatalf("scoped admin set %v on a child: %d", extra, code)
		}
	}
	if code, _, _ := c.doH("POST", "/v1/tenants", map[string]any{"slug": "root2", "name": "R"}, admin); code != 403 {
		t.Fatalf("create root tenant as scoped admin: %d", code)
	}
	if code, _, _ := c.doH("GET", "/v1/tenants/ws", nil, admin); code != 200 {
		t.Fatalf("descendant: %d", code)
	}
	_, list, _ := c.doH("GET", "/v1/tenants", nil, admin)
	if items := list["items"].([]any); len(items) != 1 || items[0].(map[string]any)["slug"] != "org" {
		t.Fatalf("scoped list: %v", list)
	}
	_, kids, _ := c.doH("GET", "/v1/tenants/org/children", nil, admin)
	if len(kids["items"].([]any)) != 1 {
		t.Fatalf("children: %v", kids)
	}
	if code, _, _ := c.doH("GET", "/v1/events", nil, admin); code != 403 {
		t.Fatalf("global events as scoped admin: %d", code)
	}
	if code, _, _ := c.doH("GET", "/v1/plans", nil, admin); code != 200 {
		t.Fatalf("plans as scoped admin: %d", code)
	}
	if code, me, _ := c.doH("GET", "/v1/me", nil, admin); code != 200 || me["tenant_id"] != org["id"] {
		t.Fatalf("me: %v", me)
	}
}

// flaky is a plugin whose subscriber fails until told otherwise.
type flaky struct{}

var flakyFail atomic.Bool

func (flaky) Manifest() sdk.Manifest { return sdk.Manifest{ID: "flaky", Name: "Flaky", Version: "0"} }
func (flaky) Init(_ context.Context, r sdk.Registrar) error {
	r.Subscribe("sink", sdk.EventFilter{Types: []string{"tenant.created"}}, func(context.Context, sdk.Event) error {
		if flakyFail.Load() {
			return errors.New("sink down")
		}
		return nil
	}, sdk.WithMaxAttempts(1))
	return nil
}

func init() { sdk.Register("flaky", func() sdk.Plugin { return flaky{} }) }

func TestDeadLetterReplayAPI(t *testing.T) {
	flakyFail.Store(true)
	cfg := baseConfig()
	cfg.Plugins = []server.PluginSpec{{Plugin: "flaky"}}
	c := client{t: t, base: startServer(t, cfg)}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})

	var dlID string
	waitFor(t, "dead letter", func() bool {
		_, dls := c.do("GET", "/v1/dead-letters?subscription=flaky/sink", nil)
		items := dls["items"].([]any)
		if len(items) == 1 {
			dlID = items[0].(map[string]any)["id"].(string)
		}
		return dlID != ""
	})
	if code, _ := c.do("POST", "/v1/dead-letters/"+dlID+"/replay", nil); code != 502 {
		t.Fatalf("replay while failing: %d", code)
	}
	flakyFail.Store(false)
	if code, body := c.do("POST", "/v1/dead-letters/"+dlID+"/replay", nil); code != 200 {
		t.Fatalf("replay: %d %v", code, body)
	}
	if code, _ := c.do("GET", "/v1/dead-letters/"+dlID, nil); code != 404 {
		t.Fatalf("dead letter still present: %d", code)
	}

	// Replay by time range redelivers without touching the cursor.
	c.do("POST", "/v1/tenants", map[string]any{"slug": "beta", "name": "Beta"})
	since := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if code, _ := c.do("POST", "/v1/events/replay", map[string]any{"subscription": "flaky/sink"}); code != 400 {
		t.Fatalf("replay without since: %d", code)
	}
	if code, _ := c.do("POST", "/v1/events/replay", map[string]any{"subscription": "nope", "since": since}); code != 409 {
		t.Fatalf("unknown subscription: %d", code)
	}
	code, res := c.do("POST", "/v1/events/replay", map[string]any{"subscription": "flaky/sink", "since": since})
	if code != 200 || res["matched"].(float64) != 2 || res["delivered"].(float64) != 2 {
		t.Fatalf("replay range: %d %v", code, res)
	}
	flakyFail.Store(true)
	defer flakyFail.Store(false)
	if _, res := c.do("POST", "/v1/events/replay", map[string]any{"subscription": "flaky/sink", "since": since}); res["dead_lettered"].(float64) != 2 {
		t.Fatalf("failed replay: %v", res)
	}
}

func TestOperationalEndpoints(t *testing.T) {
	base := startServer(t, baseConfig())
	c := client{t: t, base: base}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})

	for path, want := range map[string]string{
		"/metrics":      "tenarium_http_requests_total",
		"/openapi.yaml": "openapi:",
		"/ui/":          "<",
		"/healthz":      "ok",
		"/readyz":       "store",
	} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), want) {
			t.Errorf("%s: %d, body lacks %q", path, resp.StatusCode, want)
		}
	}
	_, _, hdr := c.doH("GET", "/v1/me", nil, map[string]string{"X-Request-ID": "abc"})
	if hdr.Get("X-Request-ID") != "abc" {
		t.Errorf("request id not echoed: %q", hdr.Get("X-Request-ID"))
	}
	resp, _ := http.Get(base + "/v1/tenants")
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("anonymous request: %d", resp.StatusCode)
	}
}

func TestAllowAnonymous(t *testing.T) {
	cfg := baseConfig()
	cfg.Server.APIKeys = nil
	cfg.Server.AllowAnonymous = true
	base := startServer(t, cfg)
	resp, err := http.Get(base + "/v1/tenants")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("anonymous dev mode: %d", resp.StatusCode)
	}
}

// TestPostgresEndToEnd runs the main flow against PostgreSQL with two
// server instances sharing the database.
func TestPostgresEndToEnd(t *testing.T) {
	dsn := os.Getenv("TENARIUM_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TENARIUM_TEST_POSTGRES_DSN not set")
	}
	dsn = freshPostgres(t, dsn)
	secret := []byte("pg-secret")
	hook, sink := newWebhookReceiver(t, secret)
	mk := func(instance string) server.Config {
		cfg := baseConfig()
		cfg.Store = server.StoreConfig{Driver: "postgres", DSN: dsn}
		cfg.Events.InstanceID = instance
		cfg.Plugins = []server.PluginSpec{
			{Plugin: "e2e"},
			{Plugin: "webhook", Config: map[string]any{"url": hook.URL, "secret": string(secret)}},
		}
		return cfg
	}
	a := client{t: t, base: startServer(t, mk("a"))}
	b := client{t: t, base: startServer(t, mk("b"))}

	for i, c := range []client{a, b, a, b} {
		slug := "pg" + string(rune('a'+i))
		if code, body := c.do("POST", "/v1/tenants", map[string]any{"slug": slug, "name": slug}); code != 201 {
			t.Fatalf("create %s: %d %v", slug, code, body)
		}
	}
	waitFor(t, "all tenants active", func() bool {
		_, l := b.do("GET", "/v1/tenants?status=active", nil)
		return len(l["items"].([]any)) == 4
	})
	// Each event reaches the webhook exactly once even with two instances.
	waitFor(t, "webhook deliveries", func() bool { return len(sink.types()) == 8 })
	time.Sleep(200 * time.Millisecond)
	if n := len(sink.types()); n != 8 {
		t.Fatalf("webhook got %d events, want 8 (4 created + 4 provisioned)", n)
	}
}
