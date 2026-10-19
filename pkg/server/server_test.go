package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/server"
	_ "github.com/AimTune/tenarium/plugins/all"
	"github.com/AimTune/tenarium/plugins/webhook"
)

const apiKey = "test-key"

// e2ePlugin is a minimal third-party style plugin with a provisioner.
type e2ePlugin struct{}

func (e2ePlugin) Manifest() sdk.Manifest { return sdk.Manifest{ID: "e2e", Name: "E2E", Version: "0"} }
func (e2ePlugin) Init(_ context.Context, r sdk.Registrar) error {
	r.Provisioner(e2eProvisioner{})
	r.Authenticator(headerAuth{})
	return nil
}

// headerAuth stands in for an OIDC/LDAP authenticator.
type headerAuth struct{}

func (headerAuth) Name() string { return "header" }
func (headerAuth) Authenticate(_ context.Context, r *http.Request) (*sdk.Principal, error) {
	u := r.Header.Get("X-E2E-User")
	if u == "" {
		return nil, sdk.ErrNoCredentials
	}
	return &sdk.Principal{Subject: u, Kind: "user", TenantID: r.Header.Get("X-E2E-Tenant")}, nil
}

type e2eProvisioner struct{}

func (e2eProvisioner) Name() string                                  { return "noop" }
func (e2eProvisioner) Provision(context.Context, sdk.Tenant) error   { return nil }
func (e2eProvisioner) Deprovision(context.Context, sdk.Tenant) error { return nil }

func init() { sdk.Register("e2e", func() sdk.Plugin { return e2ePlugin{} }) }

type hookSink struct {
	mu     sync.Mutex
	events []sdk.CloudEvent
}

func newWebhookReceiver(t *testing.T, secret []byte) (*httptest.Server, *hookSink) {
	sink := &hookSink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		want := "v1," + webhook.Sign(secret, r.Header.Get("webhook-id"), r.Header.Get("webhook-timestamp"), body)
		if r.Header.Get("webhook-signature") != want {
			t.Errorf("bad signature %q", r.Header.Get("webhook-signature"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var ce sdk.CloudEvent
		if err := json.Unmarshal(body, &ce); err != nil {
			t.Error(err)
		}
		sink.mu.Lock()
		sink.events = append(sink.events, ce)
		sink.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv, sink
}

func (s *hookSink) types() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.events {
		out = append(out, e.Type)
	}
	return out
}

func startServer(t *testing.T, cfg server.Config) string {
	t.Helper()
	return startServerWith(t, cfg)
}

func startServerWith(t *testing.T, cfg server.Config, opts ...server.Option) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveOn(t, ln, cfg, opts...)
}

// serveOn serves on an existing listener, for tests that need the address
// in the configuration (e.g. users.public_url).
func serveOn(t *testing.T, ln net.Listener, cfg server.Config, opts ...server.Option) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	app, err := server.New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), opts...)
	if err != nil {
		cancel()
		ln.Close()
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
	return "http://" + ln.Addr().String()
}

type client struct {
	t    *testing.T
	base string
}

func (c client) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	code, out, _ := c.doH(method, path, body, nil)
	return code, out
}

// doH sends a request with extra headers. Without an Authorization or
// X-E2E-User header it authenticates with the test API key.
func (c client) doH(method, path string, body any, headers map[string]string) (int, map[string]any, http.Header) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Authorization") == "" && req.Header.Get("X-E2E-User") == "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
}

func TestEndToEnd(t *testing.T) {
	secret := []byte("s3cret")
	hook, sink := newWebhookReceiver(t, secret)

	cfg := server.DefaultConfig()
	cfg.Server.APIKeys = []string{apiKey}
	cfg.Events.PollInterval = 20 * time.Millisecond
	cfg.Plugins = []server.PluginSpec{
		{Plugin: "policy", Config: map[string]any{
			"reserved_slugs": []string{"admin"},
			"default_plan":   "free",
		}},
		{Plugin: "e2e"},
		{Plugin: "webhook", Name: "audit", Config: map[string]any{
			"url":    hook.URL,
			"secret": string(secret),
			"events": []string{"tenant.*"},
		}},
	}
	base := startServer(t, cfg)
	c := client{t: t, base: base}

	// Auth is enforced.
	resp, err := http.Get(base + "/v1/tenants")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}

	// Policy hook rejects reserved slugs.
	if code, body := c.do("POST", "/v1/tenants", map[string]any{"slug": "admin", "name": "x"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d %v", code, body)
	}

	code, created := c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	if code != http.StatusCreated || created["plan"] != "free" || created["status"] != "provisioning" {
		t.Fatalf("create: %d %v", code, created)
	}
	id := created["id"].(string)

	// The provisioner runs asynchronously and activates the tenant.
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, got := c.do("GET", "/v1/tenants/acme", nil)
		if got["status"] == "active" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tenant never became active: %v", got)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if code, body := c.do("POST", "/v1/tenants/"+id+"/suspend", map[string]any{"reason": "unpaid"}); code != http.StatusOK || body["status"] != "suspended" {
		t.Fatalf("suspend: %d %v", code, body)
	}
	if code, _ := c.do("POST", "/v1/tenants/"+id+"/suspend", nil); code != http.StatusConflict {
		t.Fatalf("double suspend: want 409, got %d", code)
	}

	code, list := c.do("GET", "/v1/tenants?status=suspended", nil)
	if items := list["items"].([]any); code != http.StatusOK || len(items) != 1 {
		t.Fatalf("list: %d %v", code, list)
	}

	// Plugin route is mounted under the instance name.
	if code, body := c.do("GET", "/v1/plugins/policy/rules", nil); code != http.StatusOK || body["default_plan"] != "free" {
		t.Fatalf("plugin route: %d %v", code, body)
	}

	want := []string{"tenant.created", "tenant.provisioned", "tenant.suspended"}
	deadline = time.Now().Add(5 * time.Second)
	for len(sink.types()) < len(want) {
		if time.Now().After(deadline) {
			t.Fatalf("webhook got %v, want %v", sink.types(), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for i, typ := range sink.types() {
		if typ != want[i] {
			t.Fatalf("webhook got %v, want %v", sink.types(), want)
		}
	}
}

func TestPluginAuthenticator(t *testing.T) {
	cfg := server.DefaultConfig()
	cfg.Server.APIKeys = []string{apiKey}
	cfg.Plugins = []server.PluginSpec{{Plugin: "e2e"}}
	base := startServer(t, cfg)

	req, _ := http.NewRequest("POST", base+"/v1/tenants", bytes.NewReader([]byte(`{"slug":"globex","name":"Globex"}`)))
	req.Header.Set("X-E2E-User", "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201, got %d", resp.StatusCode)
	}

	_, evts := client{t: t, base: base}.do("GET", "/v1/events", nil)
	first := evts["items"].([]any)[0].(map[string]any)
	if first["actor"] != "e2e/header:alice" {
		t.Fatalf("actor = %v", first["actor"])
	}
}

func TestUnknownPluginFailsStartup(t *testing.T) {
	cfg := server.DefaultConfig()
	cfg.Plugins = []server.PluginSpec{{Plugin: "does-not-exist"}}
	if _, err := server.New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("want error for unknown plugin")
	}
}
