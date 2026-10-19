package external

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/examples/external-go/guard"
	"github.com/AimTune/tenarium/pkg/extplugin"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// exercise checks every proxied extension point against a running guard
// plugin registered into reg.
func exercise(t *testing.T, reg *sdktest.Registrar) {
	t.Helper()
	ctx := context.Background()

	if len(reg.Hooks) != 1 || len(reg.Subscriptions) != 1 || len(reg.Provisioners) != 1 ||
		len(reg.Authorizers) != 1 || len(reg.Routes) != 1 {
		t.Fatalf("registrations: hooks=%d subs=%d provs=%d authz=%d routes=%v",
			len(reg.Hooks), len(reg.Subscriptions), len(reg.Provisioners), len(reg.Authorizers), reg.Routes)
	}

	bad := &sdk.Tenant{Slug: "nope-x", Name: "X"}
	err := reg.RunHooks(ctx, &sdk.HookRequest{Point: sdk.HookBeforeTenantCreate, Tenant: bad})
	if re, ok := sdk.IsReject(err); !ok || re.Reason == "" {
		t.Fatalf("want rejection, got %v", err)
	}
	good := &sdk.Tenant{Slug: "acme", Name: "Acme"}
	if err := reg.RunHooks(ctx, &sdk.HookRequest{Point: sdk.HookBeforeTenantCreate, Tenant: good}); err != nil {
		t.Fatal(err)
	}
	if good.Labels["guarded"] != "true" {
		t.Fatalf("hook mutation lost: %+v", good)
	}

	tn := sdk.Tenant{ID: "t1", Slug: "acme", Name: "Acme"}
	if err := reg.Deliver(ctx, "count", sdktest.TenantEvent(sdk.EventTenantCreated, tn)); err != nil {
		t.Fatal(err)
	}
	if err := reg.Provisioners[0].Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if reg.Provisioners[0].Name() != "noop" {
		t.Fatalf("provisioner name %q", reg.Provisioners[0].Name())
	}

	d, err := reg.Authorizers[0].Authorize(ctx, &sdk.Principal{Subject: "u"}, sdk.ActionTenantsDelete, sdk.Resource{})
	if err != nil || d != sdk.Deny {
		t.Fatalf("authorize: %v %v", d, err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/stats", nil)
	req = req.WithContext(sdk.WithPrincipal(req.Context(), &sdk.Principal{Subject: "alice"}))
	req.Header.Set("Authorization", "Bearer caller-token-must-not-leak")
	reg.Mux.ServeHTTP(rec, req)
	var stats struct {
		Events      map[string]int `json:"events"`
		Provisioned []string       `json:"provisioned"`
		Caller      string         `json:"caller"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("route: %d %s", rec.Code, rec.Body)
	}
	if stats.Events[sdk.EventTenantCreated] != 1 || len(stats.Provisioned) != 1 || stats.Caller != "alice" {
		t.Fatalf("stats: %+v", stats)
	}
}

func TestRemoteMode(t *testing.T) {
	srv := httptest.NewServer(extplugin.NewHandler(&guard.Plugin{}, "s3cret", discard))
	defer srv.Close()

	reg := sdktest.NewRegistrar(map[string]any{
		"url": srv.URL, "secret": "s3cret", "config": map[string]any{"forbidden_prefix": "nope-"},
	})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if p.Manifest().ID != "guard" {
		t.Fatalf("manifest not taken from remote: %+v", p.Manifest())
	}
	exercise(t, reg)

	// Wrong secret is refused by the plugin.
	bad := &Plugin{}
	err := bad.Init(context.Background(), sdktest.NewRegistrar(map[string]any{
		"url": srv.URL, "secret": "wrong", "startup_timeout": "300ms",
	}))
	if err == nil {
		t.Fatal("init with wrong secret succeeded")
	}
}

func TestRemoteErrors(t *testing.T) {
	srv := httptest.NewServer(extplugin.NewHandler(&guard.Plugin{}, "", discard))
	defer srv.Close()
	reg := sdktest.NewRegistrar(map[string]any{"url": srv.URL, "secret": "x", "config": map[string]any{"unknown": 1}})
	if err := (&Plugin{}).Init(context.Background(), reg); err == nil {
		t.Fatal("plugin config error not propagated")
	}
}

// buildGuard compiles the example plugin binary.
func buildGuard(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := filepath.Join(t.TempDir(), "guard")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "github.com/AimTune/tenarium/examples/external-go")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build example: %v\n%s", err, out)
	}
	return bin
}

func TestManagedModeWithRestart(t *testing.T) {
	bin := buildGuard(t)
	reg := sdktest.NewRegistrar(map[string]any{
		"command": []string{bin},
		"config":  map[string]any{"forbidden_prefix": "nope-"},
	})
	p := &Plugin{}
	ctx := context.Background()
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Stop(ctx) }()
	exercise(t, reg)

	// Crash the process; the supervisor restarts and re-initialises it.
	p.proc.mu.Lock()
	_ = p.proc.cmd.Process.Kill()
	p.proc.mu.Unlock()
	deadline := time.Now().Add(15 * time.Second)
	for {
		err := reg.RunHooks(ctx, &sdk.HookRequest{Point: sdk.HookBeforeTenantCreate, Tenant: &sdk.Tenant{Slug: "nope-1", Name: "x"}})
		if _, ok := sdk.IsReject(err); ok {
			break // restarted and re-initialised with the same config
		}
		if time.Now().After(deadline) {
			t.Fatalf("plugin did not come back: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err == nil {
		t.Fatal("process still serving after Stop")
	}
}

func TestRouteProxyStripsCallerCredentials(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(200)
		case "/init":
			_ = json.NewEncoder(w).Encode(extplugin.InitResponse{
				Protocol: extplugin.ProtocolVersion, Manifest: sdk.Manifest{ID: "x"}, Routes: []string{"GET /echo"},
			})
		case "/routes/echo":
			got = r.Header.Clone()
		}
	}))
	defer srv.Close()
	reg := sdktest.NewRegistrar(map[string]any{"url": srv.URL, "secret": "plugin-secret"})
	if err := (&Plugin{}).Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/echo", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	req.Header.Set(extplugin.PrincipalHeader, "forged")
	reg.Mux.ServeHTTP(httptest.NewRecorder(), req)
	if got.Get("Authorization") != "Bearer plugin-secret" || got.Get(extplugin.PrincipalHeader) != "" {
		t.Fatalf("proxied headers: %v", got)
	}
}

// An impostor listening on a managed plugin's address does not know the
// proof key, so Tenarium refuses it.
func TestManagedRequiresProof(t *testing.T) {
	impostor := httptest.NewServer(extplugin.NewHandler(&guard.Plugin{}, "", discard)) // no proof key
	defer impostor.Close()
	base, _ := url.Parse(impostor.URL)
	p := &Plugin{
		base:   base,
		client: http.DefaultClient,
		log:    discard,
		proc:   &process{secret: "s", proofKey: "real-key"},
	}
	if _, err := p.callInit(context.Background()); err == nil || !strings.Contains(err.Error(), "prove") {
		t.Fatalf("impostor accepted: %v", err)
	}
	if p.ready.Load() {
		t.Fatal("plugin marked ready after failed proof")
	}
	if err := p.call(context.Background(), "/events/count", map[string]any{}, nil); !errors.Is(err, errNotReady) {
		t.Fatalf("calls must not reach an unverified plugin: %v", err)
	}
}
