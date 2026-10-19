package server_test

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
)

func TestConfigReload(t *testing.T) {
	var first, second atomic.Int32
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body); first.Add(1) }))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body); second.Add(1) }))
	defer b.Close()

	path := filepath.Join(t.TempDir(), "tenarium.yaml")
	write := func(url, level, addr string) {
		t.Helper()
		y := "server:\n  addr: \"" + addr + "\"\n  api_keys: [\"" + apiKey + "\"]\n" +
			"log:\n  level: " + level + "\n" +
			"events:\n  poll_interval: 20ms\n  lease_ttl: 1s\n" +
			"plugins:\n  - plugin: webhook\n    config:\n      url: \"" + url + "\"\n      secret: \"s3cret\"\n      events: [\"tenant.*\"]\n"
		if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(a.URL, "info", ":8080")
	cfg, err := server.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	c := client{t: t, base: startServerWith(t, cfg, server.WithConfigPath(path), server.WithLevelVar(new(slog.LevelVar)))}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "one", "name": "One"})
	waitFor(t, "delivery to the first endpoint", func() bool { return first.Load() > 0 })

	// Rotate the endpoint, raise the log level, and change something that
	// needs a restart.
	write(b.URL, "debug", ":9090")
	code, res := c.do("POST", "/v1/admin/reload", nil)
	if code != 200 {
		t.Fatalf("reload: %d %v", code, res)
	}
	applied, restart := toJSON(res["applied"]), toJSON(res["restart_required"])
	if !strings.Contains(applied, "plugins.webhook") || !strings.Contains(applied, "log.level") || !strings.Contains(restart, "server") {
		t.Fatalf("reload result: %v", res)
	}
	before := first.Load()
	c.do("POST", "/v1/tenants", map[string]any{"slug": "two", "name": "Two"})
	waitFor(t, "delivery to the new endpoint", func() bool { return second.Load() > 0 })
	if first.Load() != before {
		t.Fatal("old endpoint still used after reload")
	}

	// Changes the plugin cannot apply are rejected and reported.
	if err := os.WriteFile(path, []byte(strings.Replace(mustRead(t, path), `events: ["tenant.*"]`, `events: ["plan.*"]`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, res := c.do("POST", "/v1/admin/reload", nil); !strings.Contains(toJSON(res["failed"]), "plugins.webhook") {
		t.Fatalf("filter change: %v", res)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestReloadWithoutConfigFile(t *testing.T) {
	c := client{t: t, base: startServer(t, baseConfig())}
	if code, _ := c.do("POST", "/v1/admin/reload", nil); code != 404 {
		t.Fatalf("reload without file: %d", code)
	}
}

func TestReloadLiveSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tenarium.yaml")
	write := func(regions, limit, period string) {
		t.Helper()
		y := "server:\n  api_keys: [\"" + apiKey + "\"]\n" +
			"auth:\n  rate_limit: " + limit + "\n" +
			"tenants:\n  regions: " + regions + "\n" +
			"usage:\n  metrics:\n    calls: {period: " + period + "}\n"
		if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("[eu]", "0", "day")
	cfg, err := server.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	c := client{t: t, base: startServerWith(t, cfg, server.WithConfigPath(path))}
	if code, _ := c.do("POST", "/v1/tenants", map[string]any{"slug": "us1", "name": "US", "region": "us"}); code != 400 {
		t.Fatalf("region outside the list: %d", code)
	}

	write("[eu, us]", "2", "month")
	_, res := c.do("POST", "/v1/admin/reload", nil)
	applied := toJSON(res["applied"])
	for _, want := range []string{"auth.rate_limit", "tenants.regions", "usage.metrics"} {
		if !strings.Contains(applied, want) {
			t.Fatalf("%s not applied: %v", want, res)
		}
	}
	if r := toJSON(res["restart_required"]); r != "[]" {
		t.Fatalf("restart required: %v", res)
	}
	if code, _ := c.do("POST", "/v1/tenants", map[string]any{"slug": "us1", "name": "US", "region": "us"}); code != 201 {
		t.Fatalf("new region not accepted: %d", code)
	}
	if _, u := c.do("POST", "/v1/tenants/us1/usage/calls", map[string]any{"delta": 1}); !strings.HasPrefix(toJSON(u["period"]), `"20`) || len(toJSON(u["period"])) != 9 {
		t.Fatalf("usage period after reload: %v", u)
	}
	// The new rate limit (2 per minute) applies to the auth endpoints.
	codes := ""
	for range 3 {
		code, _ := c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "password", "email": "x@example.com", "password": "nope"})
		codes += fmt.Sprint(code, " ")
	}
	if !strings.HasSuffix(codes, "429 ") {
		t.Fatalf("rate limit not applied: %s", codes)
	}

	write("[eu, us]", "2", "fortnight")
	if _, res := c.do("POST", "/v1/admin/reload", nil); !strings.Contains(toJSON(res["failed"]), "usage.metrics") {
		t.Fatalf("invalid policy accepted: %v", res)
	}
}
