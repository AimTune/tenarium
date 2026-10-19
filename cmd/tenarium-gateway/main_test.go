package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestExampleConfig(t *testing.T) {
	t.Setenv("TENARIUM_API_KEY", "k123")
	cfg, err := loadConfig(filepath.Join("..", "..", "deploy", "gateway", "gateway.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.finish(); err != nil {
		t.Fatal(err)
	}
	if cfg.Tenarium.APIKey != "k123" || cfg.Source.Type != "redis" || len(cfg.Resolve) != 5 ||
		cfg.RateLimit.Period != time.Second || cfg.Cell.Plans["enterprise"] != "dedicated" || !*cfg.RateLimit.FailOpen {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gw.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfigValidation(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"empty":         {"", "resolve: at least one rule"},
		"two kinds":     {"tenarium: {url: http://x}\nresolve: [{header: X, subdomain: a.b}]", "exactly one"},
		"no url":        {"resolve: [{header: X}]", "needs tenarium.url"},
		"bad path":      {"tenarium: {url: http://x}\nresolve: [{path: /t}]", "start and end with /"},
		"redis limiter": {"tenarium: {url: http://x}\nresolve: [{header: X}]\nrate_limit: {backend: redis, metric: rps}", "needs redis.addr"},
		"no rate":       {"tenarium: {url: http://x}\nresolve: [{header: X}]\nrate_limit: {backend: local}", "metric or a default_rate"},
		"bad source":    {"tenarium: {url: http://x}\nsource: {type: sql}\nresolve: [{header: X}]", "unknown source.type"},
		"feature":       {"tenarium: {url: http://x}\nresolve: [{header: X}]\nfeatures: [{path_prefix: /a}]", "feature is required"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := loadConfig(writeConfig(t, tc.body))
			if err == nil {
				err = cfg.finish()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := loadConfig(writeConfig(t, "listen: :1\nunknown_key: 1\n")); err == nil {
		t.Error("unknown key accepted")
	}
}

// TestBuildAPISource wires the command against a fake Tenarium API.
func TestBuildAPISource(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/tenants/acme", "/v1/tenants/t-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "t-1", "slug": "acme", "status": "active", "plan": "enterprise"})
		case "/v1/tenants/t-1/entitlements":
			_ = json.NewEncoder(w).Encode(map[string]any{"tenant_id": "t-1", "plan": "enterprise", "features": map[string]bool{"x": true}, "limits": map[string]int64{"rps": 1}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer api.Close()
	cfg, err := loadConfig(writeConfig(t, `
tenarium: {url: `+api.URL+`, api_key: k}
resolve: [{subdomain: app.example.com}]
cell: {plans: {enterprise: dedicated}}
rate_limit: {backend: local, metric: rps}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.finish(); err != nil {
		t.Fatal(err)
	}
	a, err := build(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	codes := []int{}
	for range 2 {
		r := httptest.NewRequest("GET", "/traefik", nil)
		r.Header.Set("X-Forwarded-Host", "acme.app.example.com")
		r.Header.Set("X-Forwarded-Uri", "/")
		rec := httptest.NewRecorder()
		a.gw.ServeHTTP(rec, r)
		codes = append(codes, rec.Code)
		if rec.Code == 200 && rec.Header().Get("X-Tenant-Cell") != "dedicated" {
			t.Errorf("cell %q", rec.Header().Get("X-Tenant-Cell"))
		}
	}
	if codes[0] != 200 || codes[1] != 429 {
		t.Fatalf("codes %v", codes)
	}
}
