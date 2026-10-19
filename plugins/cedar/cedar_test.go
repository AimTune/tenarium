package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

const policies = `
@id("platform-admins")
permit (principal in Role::"admin", action, resource);

@id("viewers-read")
permit (principal in Role::"viewer", action in Action::"*:read", resource);

@id("members-of-own-tenant")
permit (principal in Tenant::"ORG", action == Action::"members:read", resource is Member)
when { resource.tenant_id == principal.tenant_id };

@id("tenant-scoped-subtree")
permit (principal, action in Action::"tenants:*", resource)
when { principal.roles.contains("tenant-admin") && context.tenant_scoped && resource in Tenant::"ORG" };

@id("no-delete-prod")
forbid (principal, action == Action::"tenants:delete", resource is Tenant)
when { resource.labels has env && resource.labels.env == "prod" };

@id("suspended-readonly")
forbid (principal, action, resource is Tenant)
when { resource.status == "suspended" } unless { action in Action::"*:read" || action == Action::"tenants:resume" };

@id("claims")
permit (principal is Service, action == Action::"usage:write", resource)
when { principal has claims && principal.claims has scope && principal.claims.scope.contains("usage") };
`

func setup(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
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
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	return p, reg
}

func tres(t sdk.Tenant) sdk.Resource { return sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID} }

func TestPolicies(t *testing.T) {
	p, reg := setup(t, map[string]any{"policies": policies})
	h := reg.HostImpl
	org := h.AddTenant(sdk.Tenant{ID: "ORG", Slug: "org"})
	ws := h.AddTenant(sdk.Tenant{ID: "WS", Slug: "ws", ParentID: org.ID})
	prod := h.AddTenant(sdk.Tenant{ID: "PROD", Slug: "prod", ParentID: ws.ID, Labels: map[string]string{"env": "prod"}})
	other := h.AddTenant(sdk.Tenant{ID: "OTHER", Slug: "other"})
	susp := h.AddTenant(sdk.Tenant{ID: "SUSP", Slug: "susp", Status: sdk.StatusSuspended})

	admin := &sdk.Principal{Subject: "root", Kind: "user", Roles: []string{"admin"}}
	viewer := &sdk.Principal{Subject: "v", Kind: "user", Roles: []string{"viewer"}}
	scoped := &sdk.Principal{Subject: "s", Kind: "user", Roles: []string{"tenant-admin"}, TenantID: org.ID}
	svc := &sdk.Principal{Subject: "meter", Kind: "service", Claims: map[string]any{"scope": []any{"usage", "read"}, "n": 1.5}}
	nobody := &sdk.Principal{Subject: "n", Kind: "user"}

	cases := []struct {
		name   string
		p      *sdk.Principal
		action sdk.Action
		res    sdk.Resource
		want   sdk.Decision
		reason string
	}{
		{"admin anything", admin, sdk.ActionPlansWrite, sdk.Resource{Type: "plan", ID: "pro"}, sdk.Allow, "platform-admins"},
		{"viewer reads", viewer, sdk.ActionTenantsRead, tres(org), sdk.Allow, "viewers-read"},
		{"viewer cannot write", viewer, sdk.ActionTenantsUpdate, tres(org), sdk.Abstain, "no policy matched"},
		{"scoped in subtree", scoped, sdk.ActionTenantsUpdate, tres(prod), sdk.Allow, "tenant-scoped-subtree"},
		{"scoped create under ws", scoped, sdk.ActionTenantsCreate, sdk.Resource{Type: "tenant", TenantID: ws.ID}, sdk.Allow, ""},
		{"scoped outside subtree", scoped, sdk.ActionTenantsUpdate, tres(other), sdk.Abstain, ""},
		{"forbid beats permit", admin, sdk.ActionTenantsDelete, tres(prod), sdk.Deny, "no-delete-prod"},
		{"suspended is read-only", admin, sdk.ActionTenantsUpdate, tres(susp), sdk.Deny, "suspended-readonly"},
		{"suspended can resume", admin, sdk.ActionTenantsResume, tres(susp), sdk.Allow, ""},
		{"service claims", svc, sdk.ActionUsageWrite, sdk.Resource{Type: "usage", TenantID: org.ID}, sdk.Allow, "claims"},
		{"principal in its tenant", &sdk.Principal{Subject: "m", TenantID: org.ID}, sdk.ActionMembersRead, sdk.Resource{Type: "member", TenantID: org.ID}, sdk.Allow, "members-of-own-tenant"},
		{"no roles", nobody, sdk.ActionTenantsRead, tres(org), sdk.Abstain, ""},
	}
	for _, c := range cases {
		r := p.Check(context.Background(), c.p, c.action, c.res)
		if r.Decision != c.want || !strings.Contains(r.Reason, c.reason) {
			t.Errorf("%s: got %+v, want %v (%s)", c.name, r, c.want, c.reason)
		}
	}
	// Authorize mirrors Check and never errors.
	if d, err := p.Authorize(context.Background(), admin, sdk.ActionTenantsDelete, tres(prod)); d != sdk.Deny || err != nil {
		t.Fatalf("authorize: %v %v", d, err)
	}
}

func TestOnNoMatchDeny(t *testing.T) {
	p, _ := setup(t, map[string]any{"policies": `permit (principal, action == Action::"plans:read", resource);`, "on_no_match": "deny"})
	ctx := context.Background()
	pr := &sdk.Principal{Subject: "x", Kind: "user"}
	if r := p.Check(ctx, pr, sdk.ActionPlansRead, sdk.Resource{Type: "plan"}); r.Decision != sdk.Allow || !strings.Contains(r.Reason, "inline#0") {
		t.Fatalf("got %+v", r)
	}
	if r := p.Check(ctx, pr, sdk.ActionPlansWrite, sdk.Resource{Type: "plan"}); r.Decision != sdk.Deny || !strings.Contains(r.Reason, "no policy permits") {
		t.Fatalf("got %+v", r)
	}
}

type failingHost struct{ *sdktest.Host }

func (failingHost) GetTenant(context.Context, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, errors.New("db down")
}

func TestFailMode(t *testing.T) {
	for _, mode := range []string{"abstain", "deny"} {
		p, _ := setup(t, map[string]any{"policies": `permit (principal, action, resource);`, "fail_mode": mode, "tenant_cache_ttl": "0s"})
		p.host = failingHost{}
		r := p.Check(context.Background(), &sdk.Principal{Subject: "x"}, sdk.ActionTenantsRead, sdk.Resource{Type: "tenant", ID: "t", TenantID: "t"})
		want := sdk.Abstain
		if mode == "deny" {
			want = sdk.Deny
		}
		if r.Decision != want || !strings.Contains(r.Reason, "db down") {
			t.Errorf("%s: got %+v", mode, r)
		}
		// Requests without tenants still evaluate.
		if r := p.Check(context.Background(), &sdk.Principal{Subject: "x"}, sdk.ActionPlansRead, sdk.Resource{Type: "plan"}); r.Decision != sdk.Allow {
			t.Errorf("%s: plan %+v", mode, r)
		}
	}
}

func TestTypesAndEntitiesFile(t *testing.T) {
	dir := t.TempDir()
	ents := `[{"uid": {"type": "App::Role", "id": "admin"}, "attrs": {}, "parents": [{"type": "App::Role", "id": "viewer"}]}]`
	if err := os.WriteFile(filepath.Join(dir, "entities.json"), []byte(ents), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := `@id("viewers")
permit (principal in App::Role::"viewer", action == App::Act::"signingkeys:read", resource is App::SigningKey);
@id("members")
permit (principal is App::Person, action == App::Act::"members:read", resource is App::Membership) when { resource.tenant_id == "t1" };`
	p, _ := setup(t, map[string]any{
		"policies":        pol,
		"entities_file":   filepath.Join(dir, "entities.json"),
		"principal_types": map[string]any{"user": "App::Person"},
		"role_type":       "App::Role",
		"action_type":     "App::Act",
		"tenant_type":     "App::Org",
		"resource_types":  map[string]any{"member": "App::Membership", "signing_key": "App::SigningKey"},
	})
	ctx := context.Background()
	admin := &sdk.Principal{Subject: "a", Kind: "user", Roles: []string{"admin"}}
	if r := p.Check(ctx, admin, sdk.ActionSigningKeysRead, sdk.Resource{Type: "signing_key"}); r.Decision != sdk.Allow {
		t.Fatalf("role hierarchy from entities file: %+v", r)
	}
	if r := p.Check(ctx, admin, sdk.ActionMembersRead, sdk.Resource{Type: "member", TenantID: "t1"}); r.Decision != sdk.Allow {
		t.Fatalf("member: %+v", r)
	}
	if got := (&Plugin{}).resourceTypeDefault("dead-letter_queue"); got != "DeadLetterQueue" {
		t.Fatalf("camel case: %q", got)
	}
}

// resourceTypeDefault exposes the CamelCase fallback for tests.
func (p *Plugin) resourceTypeDefault(typ string) string { return p.resourceType(typ) }

func TestReload(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "policies.cedar")
	write := func(s string, mod time.Time) {
		t.Helper()
		if err := os.WriteFile(file, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(file, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().Add(-time.Hour)
	write(`@id("read") permit (principal, action == Action::"tenants:read", resource);`, base)
	p, _ := setup(t, map[string]any{"policy_files": []string{file}, "reload_interval": "1h"})
	ctx := context.Background()
	pr := &sdk.Principal{Subject: "x"}
	if p.Check(ctx, pr, sdk.ActionTenantsUpdate, sdk.Resource{Type: "plan"}).Decision != sdk.Abstain {
		t.Fatal("update allowed before reload")
	}
	if p.reloadIfChanged() {
		t.Fatal("reloaded without change")
	}
	write(`permit (principal, action, resource);`, base.Add(time.Minute))
	if !p.reloadIfChanged() {
		t.Fatal("change not detected")
	}
	if r := p.Check(ctx, pr, sdk.ActionTenantsUpdate, sdk.Resource{Type: "plan"}); r.Decision != sdk.Allow || !strings.Contains(r.Reason, "policies.cedar#0") {
		t.Fatalf("after reload: %+v", r)
	}
	// A broken file keeps the previous policies and fails health.
	write(`permit (principal, action, resource`, base.Add(2*time.Minute))
	if p.reloadIfChanged() {
		t.Fatal("broken file loaded")
	}
	if p.Health(ctx) == nil {
		t.Fatal("health should report the failed reload")
	}
	if p.Check(ctx, pr, sdk.ActionTenantsUpdate, sdk.Resource{Type: "plan"}).Decision != sdk.Allow {
		t.Fatal("previous policies lost")
	}
	write(`permit (principal, action, resource);`, base.Add(3*time.Minute))
	p.reloadIfChanged()
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWatchLoop(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "p.cedar")
	if err := os.WriteFile(file, []byte(`forbid (principal, action, resource);`), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(file, old, old)
	p, _ := setup(t, map[string]any{"policy_files": []string{file}, "reload_interval": "10ms"})
	if err := os.WriteFile(file, []byte(`permit (principal, action, resource);`), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p.Check(context.Background(), &sdk.Principal{}, sdk.ActionPlansRead, sdk.Resource{Type: "plan"}).Decision == sdk.Allow {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("watcher did not reload")
}

func TestInitValidation(t *testing.T) {
	bad := []map[string]any{
		{},
		{"policies": "   "},
		{"policies": "permit (principal, action, resource"},
		{"policies": `@id("a") permit (principal, action, resource); @id("a") forbid (principal, action, resource);`},
		{"policy_files": []string{"does-not-exist.cedar"}},
		{"policies": "permit (principal, action, resource);", "role_type": "bad type"},
		{"policies": "permit (principal, action, resource);", "on_no_match": "allow"},
		{"policies": "permit (principal, action, resource);", "reload_interval": "often"},
		{"policies": "permit (principal, action, resource);", "entities_file": "missing.json"},
		{"policies": "permit (principal, action, resource);", "bogus": 1},
	}
	for _, cfg := range bad {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("accepted %v", cfg)
		}
	}
	if _, ok := sdk.Lookup("cedar"); !ok {
		t.Fatal("not registered")
	}
}

func TestReconfigure(t *testing.T) {
	p, _ := setup(t, map[string]any{"policies": `@id("read") permit (principal, action == Action::"plans:read", resource);`})
	ctx := context.Background()
	pr := &sdk.Principal{Subject: "x"}
	plan := sdk.Resource{Type: "plan"}
	if p.Check(ctx, pr, sdk.ActionPlansWrite, plan).Decision != sdk.Abstain {
		t.Fatal("write allowed before reconfigure")
	}

	// New policies and on_no_match apply live.
	err := p.Reconfigure(ctx, sdktest.NewRegistrar(map[string]any{
		"policies":    `@id("write") permit (principal, action == Action::"plans:write", resource);`,
		"on_no_match": "deny",
	}).Config)
	if err != nil {
		t.Fatal(err)
	}
	if r := p.Check(ctx, pr, sdk.ActionPlansWrite, plan); r.Decision != sdk.Allow || !strings.Contains(r.Reason, "write") {
		t.Fatalf("after reconfigure: %+v", r)
	}
	if r := p.Check(ctx, pr, sdk.ActionPlansRead, plan); r.Decision != sdk.Deny {
		t.Fatalf("old policy still applied: %+v", r)
	}

	// Policies that fail to parse keep the current ones.
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(map[string]any{"policies": "permit (principal, action, resource"}).Config); err == nil {
		t.Fatal("broken policies accepted")
	}
	if p.Check(ctx, pr, sdk.ActionPlansWrite, plan).Decision != sdk.Allow {
		t.Fatal("current policies lost")
	}

	// reload_interval is fixed at startup.
	err = p.Reconfigure(ctx, sdktest.NewRegistrar(map[string]any{"policies": `permit (principal, action, resource);`, "reload_interval": "1m"}).Config)
	if err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("reload_interval change: %v", err)
	}
	if p.Check(ctx, pr, sdk.ActionPlansRead, plan).Decision != sdk.Deny {
		t.Fatal("rejected config applied")
	}
}
