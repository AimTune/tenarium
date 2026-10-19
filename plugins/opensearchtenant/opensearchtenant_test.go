package opensearchtenant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"tenant_acme":             "tenant_acme",
		"Tenant-Acme Corp.":       "tenant_acme_corp",
		"a..b--c__d":              "a_b_c_d",
		"--x--":                   "x",
		"_+-.x":                   "x",
		"ümlaut":                  "mlaut",
		`a\b/c*d?e"f<g>h|i,j#k:l`: "a_b_c_d_e_f_g_h_i_j_k_l",
		"":                        "",
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
		if len(n) > maxPrefixLen || !strings.HasPrefix(n, "tenant_very_long_slug") || strings.Contains(n, "-") {
			t.Errorf("bad shortened name %q", n)
		}
	}
	if again, _ := renderName(tmpl, a); again != na {
		t.Fatalf("name not stable: %q vs %q", again, na)
	}
	// A tenant whose slug extends another's never matches its pattern.
	acme, _ := renderName(tmpl, sdk.Tenant{ID: "1", Slug: "acme"})
	corp, _ := renderName(tmpl, sdk.Tenant{ID: "2", Slug: "acme-corp"})
	if strings.HasPrefix(corp+"-logs", acme+"-") {
		t.Fatalf("%s-* matches indices of %s", acme, corp)
	}
}

func TestTenantPassword(t *testing.T) {
	a := TenantPassword("s3cret", "tenant-1")
	if len(a) != 32 || a == TenantPassword("s3cret", "tenant-2") || a != TenantPassword("s3cret", "tenant-1") {
		t.Fatalf("bad password %q", a)
	}
}

func intp(i int) *int    { return &i }
func boolp(b bool) *bool { return &b }

func TestConfigValidation(t *testing.T) {
	base := func(c Config) Config {
		if c.URL == "" && c.URLs == nil {
			c.URL = "http://localhost:9200"
		}
		return c
	}
	sec := SecurityConfig{Enabled: true}
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{base(Config{}), ""},
		{Config{URLs: []string{"http://a:9200", "https://b:9200/prefix/"}}, ""},
		{Config{}, "url is required"},
		{Config{URL: "http://a", URLs: []string{"http://b"}}, "not both"},
		{base(Config{URL: "localhost:9200"}), "scheme"},
		{base(Config{URL: "http://u:p@host"}), "credentials"},
		{base(Config{URL: "http://host?x=1"}), "query"},
		{base(Config{Username: "u", APIKey: "k"}), "api_key"},
		{base(Config{Password: "p"}), "password requires username"},
		{base(Config{Timeout: "soon"}), "timeout"},
		{base(Config{Flavor: "solr"}), "flavor"},
		{base(Config{OnDeprovision: "archive"}), "on_deprovision"},
		{base(Config{IndexTemplate: IndexTemplateConfig{Priority: intp(-1)}}), "priority"},
		{base(Config{IndexTemplate: IndexTemplateConfig{Shards: intp(0)}}), "shards"},
		{base(Config{IndexTemplate: IndexTemplateConfig{Replicas: intp(-1)}}), "replicas"},
		{base(Config{IndexTemplate: IndexTemplateConfig{Enabled: boolp(false), Shards: intp(1)}, Security: sec}), "enabled is false"},
		{base(Config{IndexTemplate: IndexTemplateConfig{Enabled: boolp(false)}}), "ownership marker"},
		{base(Config{IndexTemplate: IndexTemplateConfig{Enabled: boolp(false)}, Security: sec}), ""},
		{base(Config{IndexTemplate: IndexTemplateConfig{Enabled: boolp(false)}, Security: sec, QuotaFromLimit: "x"}), "quota_from_limit"},
		{base(Config{CreateInitialIndex: "Bad*"}), "create_initial_index"},
		{base(Config{InitialAlias: "write"}), "requires create_initial_index"},
		{base(Config{CreateInitialIndex: "000001", InitialAlias: "000001"}), "must differ"},
		{base(Config{CreateInitialIndex: "000001", InitialAlias: "write"}), ""},
		{base(Config{Security: SecurityConfig{CreateUser: true}}), "security.enabled is false"},
		{base(Config{Security: SecurityConfig{Enabled: true, CreateUser: true}}), "password_secret"},
		{base(Config{Security: SecurityConfig{Enabled: true, IndexPermissions: []string{}}}), "index_permissions"},
		{base(Config{Flavor: FlavorElasticsearch, Security: SecurityConfig{Enabled: true, BackendRoles: []string{"x"}}}), "backend_roles"},
		{base(Config{Security: SecurityConfig{Enabled: true, BackendRoles: []string{"x"}}}), ""},
		{base(Config{NameTemplate: "t-{{.Slug"}), "name_template"},
		{base(Config{NameTemplate: "t-{{.Nope}}"}), "name_template"},
		{base(Config{NameTemplate: "{{if false}}x{{end}}"}), "empty name"},
		{base(Config{NameTemplate: "-+_"}), "empty name"},
		{base(Config{NameTemplate: "static"}), "must depend on the tenant"},
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

	p := &Plugin{cfg: base(Config{Security: SecurityConfig{Enabled: true}})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	c := p.cfg
	if c.Flavor != FlavorOpenSearch || c.OnDeprovision != DeprovisionDelete || c.NameTemplate != DefaultNameTemplate ||
		!*c.IndexTemplate.Enabled || *c.IndexTemplate.Priority != DefaultPriority || p.timeout != 30*time.Second ||
		!slices.Equal(c.Security.IndexPermissions, defaultOpenSearchIndexPermissions) ||
		!slices.Equal(c.Security.ClusterPermissions, defaultOpenSearchClusterPermissions) {
		t.Fatalf("defaults not applied: %+v", c)
	}
	p = &Plugin{cfg: base(Config{Flavor: FlavorElasticsearch, Security: SecurityConfig{Enabled: true}})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.cfg.Security.IndexPermissions, defaultESIndexPrivileges) || p.cfg.Security.ClusterPermissions != nil {
		t.Fatalf("es defaults: %+v", p.cfg.Security)
	}
}

func TestConfigSchemaCompiles(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "opensearch-tenant" {
		t.Fatalf("id %q", m.ID)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]any{
		"urls": []any{"http://a:9200"}, "flavor": "elasticsearch",
		"index_template": map[string]any{"shards": 1, "mappings": map[string]any{"properties": map[string]any{}}},
		"security":       map[string]any{"enabled": true, "index_permissions": []any{"all"}},
		"tls":            map[string]any{"insecure_skip_verify": true},
	}
	if err := s.Validate(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]any{
		{},
		{"url": "http://a", "flavor": "solr"},
		{"url": "http://a", "nope": true},
		{"url": "http://a", "index_template": map[string]any{"shards": 0}},
		{"url": "http://a", "security": map[string]any{"user": "x"}},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("expected schema error for %v", bad)
		}
	}
}

// env is a plugin initialized against a fake cluster.
type env struct {
	p    *Plugin
	reg  *sdktest.Registrar
	fake *fakeCluster
}

func setup(t *testing.T, flavor string, cfg map[string]any) *env {
	t.Helper()
	f, srv := newFake(t, flavor)
	full := map[string]any{"url": srv.URL, "username": "admin", "password": "secret", "flavor": flavor}
	for k, v := range cfg {
		full[k] = v
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) }
	return &env{p: p, reg: reg, fake: f}
}

func fullConfig() map[string]any {
	return map[string]any{
		"index_template": map[string]any{
			"shards": 1, "replicas": 0, "priority": 150,
			"settings": map[string]any{"index.refresh_interval": "5s"},
			"mappings": map[string]any{"properties": map[string]any{"title": map[string]any{"type": "text"}}},
		},
		"create_initial_index": "000001",
		"initial_alias":        "write",
		"quota_from_limit":     "search_shards",
		"security": map[string]any{
			"enabled": true, "create_user": true, "password_secret": "pw-secret",
		},
	}
}

func (e *env) tenant(slug string, limits map[string]int64) sdk.Tenant {
	return e.reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Name: slug, Limits: limits})
}

func TestInitRegisters(t *testing.T) {
	e := setup(t, FlavorOpenSearch, nil)
	if len(e.reg.Provisioners) != 1 || e.reg.Provisioners[0].Name() != "opensearch" {
		t.Fatalf("provisioners %v", e.reg.Provisioners)
	}
	if len(e.reg.Routes) != 1 || e.reg.Routes[0] != "GET /tenants/{tenant}" {
		t.Fatalf("routes %v", e.reg.Routes)
	}
	var _ sdk.HealthChecker = e.p
}

func TestProvisionOpenSearch(t *testing.T) {
	ctx := context.Background()
	e := setup(t, FlavorOpenSearch, fullConfig())
	tn := e.tenant("acme-corp", map[string]int64{"search_shards": 20})
	for range 2 { // idempotent
		if err := e.p.Provision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	f := e.fake
	tmpl := f.templates["tenarium-tenant_acme_corp"]
	if tmpl == nil {
		t.Fatalf("template missing: %v", f.templates)
	}
	meta := tmpl["_meta"].(map[string]any)
	if meta[MetaTenantID] != tn.ID || meta[MetaQuota] != float64(20) || meta[MetaQuotaLimit] != "search_shards" {
		t.Fatalf("meta %v", meta)
	}
	if p := tmpl["index_patterns"].([]any); len(p) != 1 || p[0] != "tenant_acme_corp-*" || tmpl["priority"] != float64(150) {
		t.Fatalf("template %v", tmpl)
	}
	settings := tmpl["template"].(map[string]any)["settings"].(map[string]any)
	if settings["index.number_of_shards"] != float64(1) || settings["index.number_of_replicas"] != float64(0) || settings["index.refresh_interval"] != "5s" {
		t.Fatalf("settings %v", settings)
	}
	if _, ok := tmpl["template"].(map[string]any)["mappings"].(map[string]any)["properties"]; !ok {
		t.Fatalf("mappings missing: %v", tmpl)
	}
	if a := f.indices["tenant_acme_corp-000001"]; !slices.Equal(a, []string{"tenant_acme_corp-write"}) {
		t.Fatalf("indices %v", f.indices)
	}
	role := f.security[osSecurityAPI+"/roles/tenant_acme_corp"]
	if role == nil || !strings.Contains(role["description"].(string), "tenarium-tenant-id="+tn.ID) {
		t.Fatalf("role %v", role)
	}
	perm := role["index_permissions"].([]any)[0].(map[string]any)
	if perm["index_patterns"].([]any)[0] != "tenant_acme_corp-*" || len(perm["allowed_actions"].([]any)) != 3 {
		t.Fatalf("role permissions %v", perm)
	}
	user := f.security[osSecurityAPI+"/internalusers/tenant_acme_corp"]
	if user == nil || user["password"] != TenantPassword("pw-secret", tn.ID) || user["attributes"].(map[string]any)[MetaTenantID] != tn.ID {
		t.Fatalf("user %v", user)
	}
	mapping := f.security[osSecurityAPI+"/rolesmapping/tenant_acme_corp"]
	if mapping == nil || mapping["users"].([]any)[0] != "tenant_acme_corp" {
		t.Fatalf("mapping %v", mapping)
	}
	// The second run updated in place instead of create=true.
	var creates int
	for _, r := range f.reqs() {
		if strings.Contains(r, "create=true") {
			creates++
		}
	}
	if creates != 1 {
		t.Fatalf("template create requests: %d", creates)
	}

	// The tenant writes more indices; delete removes them one by one.
	f.indices["tenant_acme_corp-logs-2026"] = nil
	f.indices["tenant_acme_corp_other-1"] = nil // not matched by the pattern
	f.resetRequests()
	for range 2 {
		if err := e.p.Deprovision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.templates) != 0 || len(f.security) != 0 {
		t.Fatalf("leftovers: %v %v", f.templates, f.security)
	}
	if _, ok := f.indices["tenant_acme_corp_other-1"]; !ok || len(f.indices) != 1 {
		t.Fatalf("indices %v", f.indices)
	}
	var order []string
	for _, r := range f.reqs() {
		if strings.HasPrefix(r, "DELETE") {
			order = append(order, r)
		}
	}
	want := []string{
		"DELETE " + osSecurityAPI + "/internalusers/tenant_acme_corp",
		"DELETE " + osSecurityAPI + "/rolesmapping/tenant_acme_corp",
		"DELETE /tenant_acme_corp-000001",
		"DELETE /tenant_acme_corp-logs-2026",
		"DELETE " + osSecurityAPI + "/roles/tenant_acme_corp",
		"DELETE /_index_template/tenarium-tenant_acme_corp",
	}
	if !slices.Equal(order, want) {
		t.Fatalf("delete order\n got %v\nwant %v", order, want)
	}
}

func TestProvisionElasticsearch(t *testing.T) {
	ctx := context.Background()
	e := setup(t, FlavorElasticsearch, fullConfig())
	tn := e.tenant("acme", nil)
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	f := e.fake
	meta := f.templates["tenarium-tenant_acme"]["_meta"].(map[string]any)
	if meta[MetaTenantID] != tn.ID {
		t.Fatalf("meta %v", meta)
	}
	if _, ok := meta[MetaQuota]; ok {
		t.Fatalf("unlimited tenant has a quota: %v", meta)
	}
	role := f.security[esSecurityAPI+"/role/tenant_acme"]
	if role == nil || role["metadata"].(map[string]any)[MetaTenantID] != tn.ID {
		t.Fatalf("role %v", role)
	}
	idx := role["indices"].([]any)[0].(map[string]any)
	if idx["names"].([]any)[0] != "tenant_acme-*" || len(idx["privileges"].([]any)) != 4 {
		t.Fatalf("role indices %v", idx)
	}
	user := f.security[esSecurityAPI+"/user/tenant_acme"]
	if user == nil || user["password"] != TenantPassword("pw-secret", tn.ID) ||
		user["roles"].([]any)[0] != "tenant_acme" || user["metadata"].(map[string]any)[MetaTenantID] != tn.ID {
		t.Fatalf("user %v", user)
	}
	if len(f.security) != 2 {
		t.Fatalf("security objects %v", f.security)
	}
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if len(f.templates)+len(f.security)+len(f.indices) != 0 {
		t.Fatalf("leftovers: %v %v %v", f.templates, f.security, f.indices)
	}
}

func TestOwnership(t *testing.T) {
	ctx := context.Background()
	for _, flavor := range []string{FlavorOpenSearch, FlavorElasticsearch} {
		t.Run(flavor, func(t *testing.T) {
			e := setup(t, flavor, fullConfig())
			f := e.fake
			a := e.reg.HostImpl.AddTenant(sdk.Tenant{ID: "tenant-a", Slug: "acme"})
			b := e.reg.HostImpl.AddTenant(sdk.Tenant{ID: "tenant-b", Slug: "acme"}) // same prefix
			if err := e.p.Provision(ctx, a); err != nil {
				t.Fatal(err)
			}
			if err := e.p.Provision(ctx, b); err == nil || !strings.Contains(err.Error(), "belongs to another tenant (tenant-a)") {
				t.Fatalf("provision b: %v", err)
			}
			if err := e.p.Deprovision(ctx, b); err != nil {
				t.Fatal(err)
			}
			if len(f.templates) != 1 || len(f.indices) != 1 || len(f.security) == 0 {
				t.Fatalf("b deprovisioned a's objects: %v %v %v", f.templates, f.indices, f.security)
			}

			// A role of another tenant blocks even when the template is free.
			c := e.reg.HostImpl.AddTenant(sdk.Tenant{ID: "tenant-c", Slug: "cee"})
			if err := e.p.Provision(ctx, c); err != nil {
				t.Fatal(err)
			}
			delete(f.templates, "tenarium-tenant_cee")
			d := e.reg.HostImpl.AddTenant(sdk.Tenant{ID: "tenant-d", Slug: "cee"})
			if err := e.p.Provision(ctx, d); err == nil || !strings.Contains(err.Error(), "belongs to another tenant (tenant-c)") {
				t.Fatalf("provision d: %v", err)
			}
		})
	}
}

func TestUnmanagedObjects(t *testing.T) {
	ctx := context.Background()
	e := setup(t, FlavorOpenSearch, fullConfig())
	f := e.fake
	tn := e.reg.HostImpl.AddTenant(sdk.Tenant{ID: "t1", Slug: "acme"})

	// Data without any marker is never claimed.
	f.indices["tenant_acme-old"] = nil
	if err := e.p.Provision(ctx, tn); err == nil || !strings.Contains(err.Error(), "tenant_acme-old") {
		t.Fatalf("provision over unmanaged indices: %v", err)
	}
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.indices["tenant_acme-old"]; !ok {
		t.Fatal("unmanaged index deleted")
	}
	delete(f.indices, "tenant_acme-old")

	// An unmarked template or role is not overwritten.
	f.templates["tenarium-tenant_acme"] = map[string]any{"index_patterns": []any{"tenant_acme-*"}}
	if err := e.p.Provision(ctx, tn); err == nil || !strings.Contains(err.Error(), "not managed by tenarium") {
		t.Fatalf("provision over unmarked template: %v", err)
	}
	delete(f.templates, "tenarium-tenant_acme")
	f.security[osSecurityAPI+"/roles/tenant_acme"] = map[string]any{"description": "hand made"}
	if err := e.p.Provision(ctx, tn); err == nil || !strings.Contains(err.Error(), "role tenant_acme already exists and is not managed") {
		t.Fatalf("provision over unmarked role: %v", err)
	}
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if f.security[osSecurityAPI+"/roles/tenant_acme"]["description"] != "hand made" {
		t.Fatal("unmarked role touched")
	}
	delete(f.security, osSecurityAPI+"/roles/tenant_acme")

	// Once the tenant owns the prefix, existing indices are fine (retry).
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	f.indices["tenant_acme-more"] = nil
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
}

func TestRetainAndKeep(t *testing.T) {
	ctx := context.Background()
	cfg := fullConfig()
	cfg["on_deprovision"] = "retain"
	e := setup(t, FlavorOpenSearch, cfg)
	f := e.fake
	a := e.reg.HostImpl.AddTenant(sdk.Tenant{ID: "tenant-a", Slug: "acme"})
	if err := e.p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := e.p.Deprovision(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.security) != 0 || len(f.indices) != 1 {
		t.Fatalf("after retain: %v %v", f.security, f.indices)
	}
	meta := f.templates["tenarium-tenant_acme"]["_meta"].(map[string]any)
	if _, ok := meta[MetaTenantID]; ok || meta[MetaDeletedTenantID] != "tenant-a" || meta[MetaDeletedAt] != "2026-10-10T12:00:00Z" {
		t.Fatalf("retained meta %v", meta)
	}
	b := e.reg.HostImpl.AddTenant(sdk.Tenant{ID: "tenant-b", Slug: "acme"})
	if err := e.p.Provision(ctx, b); err == nil || !strings.Contains(err.Error(), "retained from deleted tenant tenant-a") {
		t.Fatalf("provision over retained: %v", err)
	}

	cfg["on_deprovision"] = "keep"
	e = setup(t, FlavorOpenSearch, cfg)
	e.reg.HostImpl.AddTenant(a)
	if err := e.p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	e.fake.resetRequests()
	if err := e.p.Deprovision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if r := e.fake.reqs(); len(r) != 0 {
		t.Fatalf("keep sent requests: %v", r)
	}
}

func TestRoleAsMarker(t *testing.T) {
	ctx := context.Background()
	e := setup(t, FlavorOpenSearch, map[string]any{
		"index_template": map[string]any{"enabled": false},
		"security":       map[string]any{"enabled": true, "backend_roles": []any{"acme-admins"}},
	})
	f := e.fake
	tn := e.reg.HostImpl.AddTenant(sdk.Tenant{ID: "t1", Slug: "acme"})
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if len(f.templates) != 0 {
		t.Fatalf("template created: %v", f.templates)
	}
	m := f.security[osSecurityAPI+"/rolesmapping/tenant_acme"]
	if m == nil || m["backend_roles"].([]any)[0] != "acme-admins" || len(m["users"].([]any)) != 0 {
		t.Fatalf("mapping %v", m)
	}
	f.indices["tenant_acme-docs"] = nil
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if len(f.indices)+len(f.security) != 0 {
		t.Fatalf("leftovers %v %v", f.indices, f.security)
	}
}

func TestRoute(t *testing.T) {
	e := setup(t, FlavorOpenSearch, fullConfig())
	tn := e.tenant("acme", nil)
	other := e.tenant("other", nil)
	get := func(p *sdk.Principal, tenant string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/tenants/"+tenant, nil)
		if p != nil {
			req = req.WithContext(sdk.WithPrincipal(req.Context(), p))
		}
		rec := httptest.NewRecorder()
		e.reg.Mux.ServeHTTP(rec, req)
		return rec
	}
	admin := &sdk.Principal{Subject: "admin", Kind: "user"}
	rec := get(admin, "acme")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var info TenantInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Prefix != "tenant_acme" || info.IndexPattern != "tenant_acme-*" || info.IndexTemplate != "tenarium-tenant_acme" ||
		info.Role != "tenant_acme" || info.User != "tenant_acme" || info.InitialIndex != "tenant_acme-000001" ||
		info.Alias != "tenant_acme-write" || info.Flavor != "opensearch" || len(info.URLs) != 1 {
		t.Fatalf("info %+v", info)
	}
	if strings.Contains(rec.Body.String(), TenantPassword("pw-secret", tn.ID)) {
		t.Fatal("password leaked")
	}
	scoped := &sdk.Principal{Subject: "u", Kind: "user", TenantID: other.ID}
	for _, c := range []struct {
		p      *sdk.Principal
		tenant string
	}{{scoped, "acme"}, {nil, "acme"}, {admin, "nope"}} {
		if rec := get(c.p, c.tenant); rec.Code != http.StatusNotFound {
			t.Errorf("%v %s: status %d, want 404", c.p, c.tenant, rec.Code)
		}
	}
	if rec := get(scoped, "other"); rec.Code != http.StatusOK {
		t.Errorf("own tenant: status %d", rec.Code)
	}
}

func TestHealthAndFailover(t *testing.T) {
	ctx := context.Background()
	f, srv := newFake(t, FlavorOpenSearch)
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	reg := sdktest.NewRegistrar(map[string]any{
		"urls": []any{deadURL, srv.URL}, "username": "admin", "password": "secret",
	})
	p := &Plugin{}
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.status = "red"
	f.mu.Unlock()
	if err := p.Health(ctx); err == nil || !strings.Contains(err.Error(), "red") {
		t.Fatalf("health on red: %v", err)
	}

	// Wrong credentials surface the API error.
	reg = sdktest.NewRegistrar(map[string]any{"url": srv.URL, "username": "admin", "password": "wrong"})
	p = &Plugin{}
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); statusOf(err) != http.StatusUnauthorized || !strings.Contains(err.Error(), "security_exception") {
		t.Fatalf("health with bad credentials: %v", err)
	}
}
