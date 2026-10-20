package opa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// fakeOPA answers with a canned result chosen by a function of the input.
type fakeOPA struct {
	mu      sync.Mutex
	path    string
	inputs  []Input
	answer  func(Input) string // raw JSON response body
	status  int
	slow    time.Duration
	authHdr string
}

// set changes the fake's behaviour under its lock (handlers may still be
// running from a previous request).
func (f *fakeOPA) set(change func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change()
}

func (f *fakeOPA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.authHdr = r.Header.Get("Authorization")
	status, slow := f.status, f.slow
	f.mu.Unlock()
	if slow > 0 {
		time.Sleep(slow)
	}
	if r.URL.Path == "/health" {
		w.WriteHeader(max(status, 200))
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/data/"+f.path {
		http.NotFound(w, r)
		return
	}
	if status != 0 {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"code":"internal_error","message":"boom"}`))
		return
	}
	var body struct {
		Input Input `json:"input"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	f.inputs = append(f.inputs, body.Input)
	f.mu.Unlock()
	_, _ = w.Write([]byte(f.answer(body.Input)))
}

func setup(t *testing.T, cfg map[string]any, answer func(Input) string) (*Plugin, *fakeOPA, *sdktest.Registrar) {
	t.Helper()
	f := &fakeOPA{path: "tenarium/authz", answer: answer}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	if cfg == nil {
		cfg = map[string]any{}
	}
	cfg["url"] = srv.URL
	if _, ok := cfg["path"]; !ok {
		cfg["path"] = "tenarium.authz"
	}
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	var v any
	_ = json.Unmarshal(raw, &v)
	if err := sch.Validate(v); err != nil {
		t.Fatalf("schema: %v", err)
	}
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	return p, f, reg
}

var (
	ann    = &sdk.Principal{Subject: "ann", Kind: "user", Roles: []string{"admin"}}
	tenant = sdk.Resource{Type: "tenant", ID: "t1", TenantID: "t1"}
)

func TestResults(t *testing.T) {
	cases := []struct {
		body       string
		deny       bool // on_not_allowed: deny
		want       sdk.Decision
		reasonPart string
	}{
		{`{"result": true}`, false, sdk.Allow, "allowed"},
		{`{"result": false}`, false, sdk.Abstain, "false"},
		{`{"result": false}`, true, sdk.Deny, "false"},
		{`{}`, true, sdk.Abstain, "undefined"},
		{`{"result": {"allow": true}}`, false, sdk.Allow, ""},
		{`{"result": {"allow": true, "deny": true, "reason": "frozen"}}`, false, sdk.Deny, "frozen"},
		{`{"result": {"deny": ["plan is locked", "tenant suspended"]}}`, false, sdk.Deny, "plan is locked; tenant suspended"},
		{`{"result": {"deny": [], "allow": false, "reason": ["no role"]}}`, true, sdk.Deny, "no role"},
		{`{"result": {"deny": [], "allow": false}}`, false, sdk.Abstain, "not allowed"},
		{`{"result": {"deny": "nope"}}`, false, sdk.Deny, "nope"},
		{`{"result": 42}`, false, sdk.Abstain, "boolean or an object"},
		{`{"result": {"deny": 3}}`, false, sdk.Abstain, "deny"},
	}
	for _, c := range cases {
		cfg := map[string]any{"cache_ttl": "0s"}
		if c.deny {
			cfg["on_not_allowed"] = "deny"
		}
		p, _, _ := setup(t, cfg, func(Input) string { return c.body })
		r := p.Check(context.Background(), ann, sdk.ActionTenantsUpdate, tenant)
		if r.Decision != c.want || !strings.Contains(r.Reason, c.reasonPart) {
			t.Errorf("%s (deny=%v): got %+v, want %v containing %q", c.body, c.deny, r, c.want, c.reasonPart)
		}
	}
}

func TestInput(t *testing.T) {
	p, f, reg := setup(t, map[string]any{"include_tenant": true, "token": "s3cret"}, func(in Input) string {
		return `{"result": true}`
	})
	org := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "org", Plan: "pro"})
	team := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "team", ParentID: org.ID})
	ws := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "ws", ParentID: team.ID, Labels: map[string]string{"env": "prod"}})
	ctx := context.Background()
	if got, err := p.Authorize(ctx, ann, sdk.ActionMembersWrite, sdk.Resource{Type: "member", TenantID: ws.ID}); err != nil || got != sdk.Allow {
		t.Fatalf("got %v %v", got, err)
	}
	in := f.inputs[0]
	if in.Action != sdk.ActionMembersWrite || in.ActionResource != "members" || in.ActionVerb != "write" ||
		in.Principal.Subject != "ann" || in.Resource.TenantID != ws.ID {
		t.Fatalf("input %+v", in)
	}
	if in.Tenant == nil || in.Tenant.Labels["env"] != "prod" {
		t.Fatalf("tenant %+v", in.Tenant)
	}
	if len(in.TenantAncestors) != 2 || in.TenantAncestors[0] != team.ID || in.TenantAncestors[1] != org.ID {
		t.Fatalf("ancestors %v", in.TenantAncestors)
	}
	if f.authHdr != "Bearer s3cret" {
		t.Fatalf("auth %q", f.authHdr)
	}
	// Unknown tenant: no tenant in input, still asked.
	_, _ = p.Authorize(ctx, ann, sdk.ActionTenantsRead, sdk.Resource{Type: "tenant", ID: "gone", TenantID: "gone"})
	if f.inputs[1].Tenant != nil {
		t.Fatal("tenant for unknown id")
	}
}

func TestFailMode(t *testing.T) {
	p, f, _ := setup(t, map[string]any{"timeout": "50ms"}, func(Input) string { return `{"result": true}` })
	ctx := context.Background()
	f.set(func() { f.status = http.StatusInternalServerError })
	if got, err := p.Authorize(ctx, ann, sdk.ActionTenantsRead, tenant); err != nil || got != sdk.Abstain {
		t.Fatalf("got %v %v", got, err)
	}
	if err := p.Health(ctx); err == nil {
		t.Fatal("health should fail")
	}
	p.denyOnError = true
	if r := p.Check(ctx, ann, sdk.ActionTenantsRead, tenant); r.Decision != sdk.Deny || !strings.Contains(r.Reason, "boom") {
		t.Fatalf("got %+v", r)
	}
	f.set(func() { f.status, f.slow = 0, 200*time.Millisecond })
	if r := p.Check(ctx, ann, sdk.ActionTenantsRead, tenant); r.Decision != sdk.Deny {
		t.Fatalf("timeout: %+v", r)
	}
	f.set(func() { f.slow = 0 })
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCache(t *testing.T) {
	p, f, _ := setup(t, map[string]any{"cache_ttl": "1m"}, func(in Input) string {
		if in.Action == sdk.ActionTenantsDelete {
			return `{"result": {"deny": ["never"]}}`
		}
		return `{"result": true}`
	})
	ctx := context.Background()
	for range 3 {
		_, _ = p.Authorize(ctx, ann, sdk.ActionTenantsRead, tenant)
		_, _ = p.Authorize(ctx, ann, sdk.ActionTenantsDelete, tenant)
	}
	if len(f.inputs) != 2 {
		t.Fatalf("queries = %d", len(f.inputs))
	}
	if r := p.Check(ctx, ann, sdk.ActionTenantsDelete, tenant); r.Decision != sdk.Deny || !strings.Contains(r.Reason, "never") {
		t.Fatalf("cached deny lost its reason: %+v", r)
	}
}

func TestInitValidation(t *testing.T) {
	bad := []map[string]any{
		{},
		{"url": "http://x"},
		{"url": "opa:8181", "path": "a"},
		{"url": "http://x", "path": "/"},
		{"url": "http://x", "path": "a?b"},
		{"url": "http://x", "path": "a", "timeout": "fast"},
		{"url": "http://x", "path": "a", "on_not_allowed": "allow"},
		{"url": "http://x", "path": "a", "bundle": "x.tar.gz"},
	}
	for _, cfg := range bad {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("accepted %v", cfg)
		}
	}
	if _, ok := sdk.Lookup("opa"); !ok {
		t.Fatal("not registered")
	}
}

func TestReconfigure(t *testing.T) {
	p, f, _ := setup(t, map[string]any{"cache_ttl": "1m"}, func(Input) string { return `{"result": true}` })
	ctx := context.Background()
	if r := p.Check(ctx, ann, sdk.ActionTenantsRead, tenant); r.Decision != sdk.Allow {
		t.Fatalf("got %+v", r)
	}

	// A new server, path and token apply live; cached decisions are dropped.
	f2 := &fakeOPA{path: "tenarium/v2", answer: func(Input) string { return `{"result": {"deny": "v2 policy"}}` }}
	srv2 := httptest.NewServer(f2)
	t.Cleanup(srv2.Close)
	cfg := map[string]any{"url": srv2.URL, "path": "tenarium/v2", "token": "new", "cache_ttl": "1m"}
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg).Config); err != nil {
		t.Fatal(err)
	}
	if r := p.Check(ctx, ann, sdk.ActionTenantsRead, tenant); r.Decision != sdk.Deny || !strings.Contains(r.Reason, "v2 policy") {
		t.Fatalf("after reconfigure: %+v", r)
	}
	if len(f.inputs) != 1 || len(f2.inputs) != 1 || f2.authHdr != "Bearer new" {
		t.Fatalf("old %d, new %d, auth %q", len(f.inputs), len(f2.inputs), f2.authHdr)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}

	// An invalid config is rejected and the current settings stay.
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(map[string]any{"url": "opa:8181", "path": "x"}).Config); err == nil {
		t.Fatal("invalid url accepted")
	}
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(map[string]any{"url": srv2.URL, "path": "x", "bundle": "b"}).Config); err == nil {
		t.Fatal("unknown field accepted")
	}
	if r := p.Check(ctx, ann, sdk.ActionTenantsUpdate, tenant); r.Decision != sdk.Deny || len(f2.inputs) != 2 {
		t.Fatalf("after rejected reconfigure: %+v (%d queries)", r, len(f2.inputs))
	}
}
