package grafanatenant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"tenant-acme":     "tenant-acme",
		"  Acme   Corp  ": "Acme Corp",
		"a/b\\c?d#e%f":    "a-b-c-d-e-f",
		"line\nbreak\tx":  "line break x",
		"ctl\x00x":        "ctl-x",
		"--x--":           "x",
		"Ümlaut (Team)":   "Ümlaut (Team)",
		"":                "",
		"../api":          "..-api",
	} {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderNameLimits(t *testing.T) {
	tmpl, err := parseNameTemplate(DefaultNameTemplate)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("very-long-slug-", 10)
	a := sdk.Tenant{ID: "11111111-1111-1111-1111-111111111111", Slug: long}
	b := sdk.Tenant{ID: "22222222-2222-2222-2222-222222222222", Slug: long}
	na, err := renderName(tmpl, a)
	if err != nil {
		t.Fatal(err)
	}
	nb, _ := renderName(tmpl, b)
	if na == nb {
		t.Fatalf("long names collide: %q", na)
	}
	for _, n := range []string{na, nb} {
		if len(n) > maxNameLen || !strings.HasPrefix(n, "tenant-very-long-slug") {
			t.Errorf("bad shortened name %q", n)
		}
	}
	if again, _ := renderName(tmpl, a); again != na {
		t.Fatalf("name not stable: %q vs %q", again, na)
	}
	// Multi-byte runes are not split by truncation.
	multi, _ := parseNameTemplate("{{.Name}}")
	n, err := renderName(multi, sdk.Tenant{ID: "x", Name: strings.Repeat("é", 80)})
	if err != nil || !strings.HasPrefix(n, "éé") || strings.ContainsRune(n, '�') || len(n) > maxNameLen {
		t.Fatalf("multi-byte name %q, %v", n, err)
	}
}

func baseConfig(c Config) Config {
	if c.URL == "" {
		c.URL = "http://grafana:3000"
	}
	if c.Token == "" && c.Username == "" {
		c.Username, c.Password = "admin", "secret"
	}
	return c
}

func TestConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{baseConfig(Config{}), ""},
		{baseConfig(Config{Token: "glsa_x"}), ""},
		{Config{Username: "a", Password: "b"}, "url is required"},
		{baseConfig(Config{URL: "grafana:3000"}), "absolute http"},
		{baseConfig(Config{URL: "ftp://grafana"}), "absolute http"},
		{baseConfig(Config{URL: "http://grafana/?x=1"}), "query"},
		{Config{URL: "http://g", Username: "a"}, "username and password"},
		{Config{URL: "http://g", Token: "t", Username: "a", Password: "b"}, "not both"},
		{baseConfig(Config{Timeout: "soon"}), "timeout"},
		{baseConfig(Config{Timeout: "-1s"}), "timeout"},
		{baseConfig(Config{OnDeprovision: "archive"}), "on_deprovision"},
		{baseConfig(Config{DefaultRole: "Owner"}), "default_role"},
		{baseConfig(Config{SyncMembers: true, RoleMap: map[string]string{"owner": "Root"}}), "role_map.owner"},
		{baseConfig(Config{RoleMap: map[string]string{"owner": "Admin"}}), "requires sync_members"},
		{baseConfig(Config{CreateUsers: true}), "requires sync_members"},
		{baseConfig(Config{Quota: map[string]string{"panels": "x"}}), "unknown target"},
		{baseConfig(Config{Quota: map[string]string{"dashboard": ""}}), "limit name"},
		{baseConfig(Config{Quota: map[string]string{"dashboard": "dashboards"}}), ""},
		{baseConfig(Config{NameTemplate: "t-{{.Slug"}), "name_template"},
		{baseConfig(Config{NameTemplate: "t-{{.Nope}}"}), "name_template"},
		{baseConfig(Config{NameTemplate: "{{if false}}x{{end}}"}), "empty name"},
		{baseConfig(Config{NameTemplate: "static"}), "must depend on the tenant"},
		{baseConfig(Config{Datasources: []DatasourceConfig{{Name: "x"}}}), "name and type"},
		{baseConfig(Config{Datasources: []DatasourceConfig{{Name: "x", Type: "t"}, {Name: "x", Type: "t"}}}), "duplicate"},
		{baseConfig(Config{Datasources: []DatasourceConfig{{Name: "x", Type: "t", Access: "both"}}}), "access"},
		{baseConfig(Config{Datasources: []DatasourceConfig{{Name: "x", Type: "t", URL: "{{.Nope}}"}}}), "datasources[0]"},
		{baseConfig(Config{Datasources: []DatasourceConfig{{Name: "x", Type: "t", JSONData: map[string]any{"a": "{{.Tenant.Nope}}"}}}}), "datasources[0]"},
		{baseConfig(Config{Datasources: []DatasourceConfig{{Name: "x", Type: "t", URL: "http://p/{{.Tenant.Slug}}"}}}), ""},
	} {
		p := &Plugin{cfg: tc.cfg}
		err := p.validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%+v: unexpected error %v", tc.cfg, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%+v: error %v, want containing %q", tc.cfg, err, tc.wantErr)
		}
	}

	p := &Plugin{cfg: baseConfig(Config{SyncMembers: true, RoleMap: map[string]string{"member": "Viewer", "billing": "None"}})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.cfg.OnDeprovision != DeprovisionDelete || p.cfg.NameTemplate != DefaultNameTemplate || p.cfg.DefaultRole != RoleViewer {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	for in, want := range map[string]string{"owner": "Admin", "admin": "Admin", "member": "Viewer", "billing": "None", "other": "Viewer"} {
		if got := p.RoleFor(in); got != want {
			t.Errorf("RoleFor(%q) = %q, want %q", in, got, want)
		}
	}
	if n, err := p.OrgName(sdk.Tenant{ID: "id", Slug: "acme"}); err != nil || n != "tenant-acme" {
		t.Fatalf("OrgName = %q, %v", n, err)
	}
}

func TestConfigSchemaCompiles(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "grafana-tenant" {
		t.Fatalf("id %q", m.ID)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]any{
		"url": "http://g", "username": "a", "password": "b",
		"role_map": map[string]any{"owner": "Admin"}, "quota": map[string]any{"dashboard": "dashboards"},
		"datasources": []any{map[string]any{"name": "prom", "type": "prometheus", "json_data": map[string]any{"x": 1}}},
	}
	if err := s.Validate(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]any{
		{},
		{"url": "http://g", "extra": true},
		{"url": "http://g", "role_map": map[string]any{"owner": "Root"}},
		{"url": "http://g", "quota": map[string]any{"panels": "x"}},
		{"url": "http://g", "on_deprovision": "archive"},
		{"url": "http://g", "datasources": []any{map[string]any{"name": "x"}}},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("expected schema error for %v", bad)
		}
	}
}

// setup starts a fake Grafana and initializes the plugin against it.
func setup(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar, *fakeGrafana) {
	t.Helper()
	f, srv := newFakeGrafana(t)
	full := map[string]any{"url": srv.URL, "username": "admin", "password": "secret"}
	for k, v := range cfg {
		full[k] = v
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{now: func() time.Time { return time.Unix(1700000000, 0) }}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	return p, reg, f
}

func TestInitRegisters(t *testing.T) {
	_, reg, _ := setup(t, map[string]any{"sync_members": true, "quota": map[string]any{"dashboard": "dashboards"}})
	if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "grafana-org" {
		t.Fatalf("provisioners %v", reg.Provisioners)
	}
	if len(reg.Routes) != 1 || reg.Routes[0] != "GET /tenants/{tenant}" {
		t.Fatalf("routes %v", reg.Routes)
	}
	if len(reg.Subscriptions) != 2 || reg.Subscriptions[0].Name != "members" || reg.Subscriptions[1].Name != "quota" {
		t.Fatalf("subscriptions %+v", reg.Subscriptions)
	}

	_, reg, _ = setup(t, nil)
	if len(reg.Subscriptions) != 0 {
		t.Fatalf("unexpected subscriptions %+v", reg.Subscriptions)
	}
}

func TestHealth(t *testing.T) {
	p, _, _ := setup(t, nil)
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.cfg.Password = "wrong"
	if err := p.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "server admin") {
		t.Fatalf("health with bad credentials: %v", err)
	}
}

func TestProvisionLifecycle(t *testing.T) {
	ctx := context.Background()
	p, reg, f := setup(t, nil)
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme"})
	for range 2 { // idempotent
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	o := f.orgNamed("tenant-acme")
	if o == nil || o.owner() != ten.ID {
		t.Fatalf("org %+v", o)
	}
	if f.role(o.ID, 1) != RoleAdmin {
		t.Fatal("creator should stay without remove_creator")
	}
	for range 2 {
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	if f.orgNamed("tenant-acme") != nil {
		t.Fatal("org not deleted")
	}
}

func TestOwnership(t *testing.T) {
	ctx := context.Background()
	p, reg, f := setup(t, nil)
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	// Another tenant rendering the same name (e.g. a re-created slug) must
	// neither adopt nor delete it.
	b := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, b); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("provision over foreign org: %v", err)
	}
	if err := p.Deprovision(ctx, b); err != nil {
		t.Fatal(err)
	}
	if o := f.orgNamed("tenant-acme"); o == nil || o.owner() != a.ID {
		t.Fatal("foreign deprovision touched the org")
	}

	// Unmarked, empty org (interrupted Provision) is adopted.
	f.mu.Lock()
	f.createOrg("tenant-empty")
	busy := f.createOrg("tenant-busy")
	f.dashboards[busy] = 1
	used := f.createOrg("tenant-users")
	f.members[used][f.nextUser] = RoleViewer
	f.users[f.nextUser] = &user{ID: f.nextUser, Login: "x"}
	f.nextUser++
	f.mu.Unlock()
	if err := p.Provision(ctx, reg.HostImpl.AddTenant(sdk.Tenant{Slug: "empty"})); err != nil {
		t.Fatal(err)
	}
	for _, slug := range []string{"busy", "users"} {
		ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
		if err := p.Provision(ctx, ten); err == nil || !strings.Contains(err.Error(), "not empty") {
			t.Fatalf("%s: provision of unmanaged org: %v", slug, err)
		}
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatal(err)
		}
		if f.orgNamed("tenant-"+slug) == nil {
			t.Fatalf("%s: unmanaged org deleted", slug)
		}
	}

	// The main org is never used.
	main, err := parseNameTemplate("{{if eq .Slug \"main\"}}Main Org.{{else}}t-{{.Slug}}{{end}}")
	if err != nil {
		t.Fatal(err)
	}
	p.name = main
	m := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "main"})
	if err := p.Provision(ctx, m); err == nil || !strings.Contains(err.Error(), "main organization") {
		t.Fatalf("main org: %v", err)
	}
	if err := p.Deprovision(ctx, m); err != nil || f.orgNamed("Main Org.") == nil {
		t.Fatalf("main org deprovision: %v", err)
	}
}

func TestDeprovisionRetainAndKeep(t *testing.T) {
	ctx := context.Background()
	p, reg, f := setup(t, map[string]any{"on_deprovision": "retain"})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	id := f.orgNamed("tenant-acme").ID
	for range 2 {
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	o := f.orgNamed("tenant-acme-deleted-1700000000")
	if o == nil || o.ID != id || o.owner() != "" || o.retainedFrom() != ten.ID ||
		o.Address.Address2 != MarkerDeletedAt+"2023-11-14T22:13:20Z" {
		t.Fatalf("retained org %+v", o)
	}
	// The name is free again for a new tenant.
	again := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, again); err != nil {
		t.Fatal(err)
	}
	if n := f.orgNamed("tenant-acme"); n == nil || n.ID == id {
		t.Fatal("expected a fresh org")
	}

	// An interrupted retain (marker released, not renamed) is finished on
	// retry and refused by Provision.
	f.mu.Lock()
	half := f.createOrg("tenant-half")
	f.orgs[half].Address.Address1 = MarkerDeleted + "t-half"
	f.mu.Unlock()
	half1 := sdk.Tenant{ID: "t-half", Slug: "half"}
	if err := p.Provision(ctx, half1); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("provision over retained: %v", err)
	}
	if err := p.Deprovision(ctx, half1); err != nil {
		t.Fatal(err)
	}
	if f.orgNamed("tenant-half") != nil {
		t.Fatal("interrupted retain not finished")
	}

	p.cfg.OnDeprovision = DeprovisionKeep
	if err := p.Deprovision(ctx, again); err != nil {
		t.Fatal(err)
	}
	if o := f.orgNamed("tenant-acme"); o == nil || o.owner() != again.ID {
		t.Fatal("keep touched the org")
	}
}

func TestQuota(t *testing.T) {
	ctx := context.Background()
	p, reg, f := setup(t, map[string]any{"quota": map[string]any{
		"dashboard": "dashboards", "org_user": "seats",
	}})
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"dashboards": 25}})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	id := f.orgNamed("tenant-acme").ID
	if f.quotas[id]["dashboard"] != 25 || f.quotas[id]["org_user"] != -1 || f.quotas[id]["data_source"] != 10 {
		t.Fatalf("quotas %v", f.quotas[id])
	}
	// Limit changes are applied on tenant.updated.
	ten.Limits = map[string]int64{"seats": 3}
	reg.HostImpl.AddTenant(ten)
	if err := reg.Deliver(ctx, "quota", sdktest.TenantEvent(sdk.EventTenantUpdated, ten)); err != nil {
		t.Fatal(err)
	}
	if f.quotas[id]["org_user"] != 3 {
		t.Fatalf("quotas %v", f.quotas[id])
	}
	f.quotaOff = true
	if err := p.Provision(ctx, ten); err == nil || !strings.Contains(err.Error(), "grafana.ini") {
		t.Fatalf("quota disabled: %v", err)
	}
}

func TestDatasourcesAndRemoveCreator(t *testing.T) {
	ctx := context.Background()
	p, reg, f := setup(t, map[string]any{
		"remove_creator": true,
		"datasources": []any{map[string]any{
			"name": "Metrics", "type": "prometheus", "url": "http://prom/{{.Tenant.Slug}}",
			"json_data":        map[string]any{"httpHeaderName1": "X-Scope-OrgID", "timeout": 30},
			"secure_json_data": map[string]any{"httpHeaderValue1": "{{.Tenant.ID}}"},
		}},
	})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	id := f.orgNamed("tenant-acme").ID
	d := f.ds[id]["Metrics"]
	if d == nil || d["url"] != "http://prom/acme" || d["access"] != "proxy" {
		t.Fatalf("datasource %v", d)
	}
	if sec := d["secureJsonData"].(map[string]any); sec["httpHeaderValue1"] != ten.ID {
		t.Fatalf("secure json %v", sec)
	}
	if jd := d["jsonData"].(map[string]any); jd["timeout"] != float64(30) {
		t.Fatalf("json data %v", jd)
	}
	// The creator is the last admin, so it stays.
	if f.role(id, 1) != RoleAdmin {
		t.Fatal("last admin removed")
	}
	// Once a member is Admin, the creator leaves; re-provisioning
	// temporarily re-joins to update data sources and leaves again.
	owner := f.addUser("owner@example.com", "owner@example.com")
	f.mu.Lock()
	f.members[id][owner] = RoleAdmin
	f.mu.Unlock()
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if f.role(id, 1) != "" {
		t.Fatal("creator still a member")
	}
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if f.role(id, 1) != "" || f.ds[id]["Metrics"] == nil {
		t.Fatal("re-provision without membership failed")
	}
}

func TestSyncMembers(t *testing.T) {
	ctx := context.Background()
	p, reg, f := setup(t, map[string]any{"sync_members": true, "remove_creator": true})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	id := f.orgNamed("tenant-acme").ID
	existing := f.addUser("ann", "ann@example.com")
	deliver := func(typ string, m sdk.Member, prev *sdk.Member) {
		t.Helper()
		e := sdktest.MemberEvent(typ, m)
		if prev != nil {
			e.Data, _ = json.Marshal(sdk.MemberEventData{Member: m, Previous: prev})
		}
		if err := reg.Deliver(ctx, "members", e); err != nil {
			t.Fatal(err)
		}
	}

	ann := sdk.Member{ID: "m1", TenantID: ten.ID, Email: "ann@example.com", Role: "member", Status: sdk.MemberActive}
	deliver(sdk.EventMemberAdded, ann, nil)
	deliver(sdk.EventMemberAdded, ann, nil) // replay
	if f.role(id, existing) != RoleEditor {
		t.Fatalf("ann role %q", f.role(id, existing))
	}
	// Missing users are skipped without create_users.
	bob := sdk.Member{ID: "m2", TenantID: ten.ID, Email: "bob@example.com", Role: "owner", Status: sdk.MemberActive}
	deliver(sdk.EventMemberAdded, bob, nil)
	if u, _ := p.lookupUser(ctx, "bob@example.com"); u != nil {
		t.Fatal("user created without create_users")
	}
	// Promotion to owner makes ann Admin; the creator then leaves.
	prev := ann
	ann.Role = "owner"
	deliver(sdk.EventMemberUpdated, ann, &prev)
	if f.role(id, existing) != RoleAdmin || f.role(id, 1) != "" {
		t.Fatalf("roles ann=%q creator=%q", f.role(id, existing), f.role(id, 1))
	}
	// Removing the last admin is refused by Grafana and only logged.
	deliver(sdk.EventMemberRemoved, ann, nil)
	if f.role(id, existing) != RoleAdmin {
		t.Fatal("last admin removed")
	}
	// The plugin's own account is never managed.
	deliver(sdk.EventMemberRemoved, sdk.Member{TenantID: ten.ID, Email: "admin@localhost", Role: "member"}, nil)

	// create_users creates missing users directly in the org.
	p.cfg.CreateUsers = true
	reg.HostImpl.AddUser(sdk.User{Email: "bob@example.com", Name: "Bob"})
	deliver(sdk.EventMemberAdded, bob, nil)
	u, _ := p.lookupUser(ctx, "bob@example.com")
	if u == nil || f.role(id, u.ID) != RoleAdmin {
		t.Fatalf("bob %+v", u)
	}
	// Email change: old identity leaves, new one joins.
	carl := f.addUser("carl", "carl@example.com")
	prevBob := bob
	bob.Email = "carl@example.com"
	deliver(sdk.EventMemberUpdated, bob, &prevBob)
	if f.role(id, u.ID) != "" || f.role(id, carl) != RoleAdmin {
		t.Fatalf("email change: old=%q new=%q", f.role(id, u.ID), f.role(id, carl))
	}
	// Suspended members lose access; removal is idempotent.
	bob.Status = sdk.MemberSuspended
	deliver(sdk.EventMemberUpdated, bob, nil)
	deliver(sdk.EventMemberRemoved, bob, nil)
	if f.role(id, carl) != "" {
		t.Fatal("suspended member kept")
	}

	// Events for a tenant whose org is still being provisioned are retried.
	pending := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "pending", Status: sdk.StatusProvisioning})
	err := reg.Deliver(ctx, "members", sdktest.MemberEvent(sdk.EventMemberAdded,
		sdk.Member{TenantID: pending.ID, Email: "ann@example.com", Role: "member"}))
	if err == nil {
		t.Fatal("expected retry while provisioning")
	}
	// ... and ignored for active tenants without an org.
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "other"})
	if err := reg.Deliver(ctx, "members", sdktest.MemberEvent(sdk.EventMemberAdded,
		sdk.Member{TenantID: other.ID, Email: "ann@example.com", Role: "member"})); err != nil {
		t.Fatal(err)
	}
}

func TestRoute(t *testing.T) {
	ctx := context.Background()
	p, reg, f := setup(t, nil)
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	fresh := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "fresh"})
	get := func(path string, pr *sdk.Principal) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if pr != nil {
			req = req.WithContext(sdk.WithPrincipal(req.Context(), pr))
		}
		rec := httptest.NewRecorder()
		reg.Mux.ServeHTTP(rec, req)
		return rec
	}
	admin := &sdk.Principal{Subject: "admin"}

	rec := get("/tenants/acme", admin)
	var info TenantInfo
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &info) != nil {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	id := f.orgNamed("tenant-acme").ID
	if !info.Provisioned || info.OrgID != id || info.OrgName != "tenant-acme" || !strings.HasSuffix(info.URL, "/?orgId="+itoa(id)) {
		t.Fatalf("info %+v", info)
	}
	rec = get("/tenants/"+fresh.ID, admin)
	info = TenantInfo{}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &info) != nil || info.Provisioned || info.OrgName != "tenant-fresh" {
		t.Fatalf("fresh: %d %s", rec.Code, rec.Body)
	}
	if rec := get("/tenants/nope", admin); rec.Code != 404 {
		t.Fatalf("missing tenant: %d", rec.Code)
	}
	// Denied callers get 404, not 403.
	if rec := get("/tenants/acme", &sdk.Principal{Subject: "x", TenantID: fresh.ID}); rec.Code != 404 {
		t.Fatalf("other tenant's caller: %d", rec.Code)
	}
	if rec := get("/tenants/acme", &sdk.Principal{Subject: "x", TenantID: acme.ID}); rec.Code != 200 {
		t.Fatalf("own tenant's caller: %d", rec.Code)
	}
	if rec := get("/tenants/acme", nil); rec.Code != 404 {
		t.Fatalf("anonymous: %d", rec.Code)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
