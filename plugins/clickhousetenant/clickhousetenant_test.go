package clickhousetenant

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

const testSecret = "0123456789abcdef-secret"

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"tenant_acme":          "tenant_acme",
		"Tenant-Acme Corp.":    "tenant_acme_corp_",
		"1abc":                 "_1abc",
		"ümlaut":               "_mlaut",
		"":                     "",
		"a`b'c":                "a_b_c",
		`x"; DROP DATABASE y;`: "x___drop_database_y_",
	} {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQuote(t *testing.T) {
	if got := quoteIdent("a`b\\c"); got != "`a\\`b\\\\c`" {
		t.Errorf("quoteIdent = %s", got)
	}
	if got := quoteString("it's \\ new\nline"); got != `'it\'s \\ new\nline'` {
		t.Errorf("quoteString = %s", got)
	}
}

func TestTenantPassword(t *testing.T) {
	a := TenantPassword(testSecret, "t1")
	if len(a) != 32 || a != TenantPassword(testSecret, "t1") {
		t.Fatalf("password %q not stable or wrong length", a)
	}
	if a == TenantPassword(testSecret, "t2") || a == TenantPassword(testSecret+"x", "t1") {
		t.Fatal("password must depend on secret and tenant")
	}
}

func TestRenderNameLimits(t *testing.T) {
	tmpl, err := parseNameTemplate("name_template", DefaultNameTemplate, reservedDatabases)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("very-long-slug-", 10)
	na, err := renderName(tmpl, sdk.Tenant{ID: "1", Slug: long}, nil)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := renderName(tmpl, sdk.Tenant{ID: "2", Slug: long}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if na == nb || len(na) != maxNameLen || !strings.HasPrefix(na, "tenant_very_long_slug") {
		t.Fatalf("bad shortened names %q %q", na, nb)
	}
	if _, err := renderName(tmpl, sdk.Tenant{ID: "1", Slug: "x"}, []string{"tenant_x"}); err == nil {
		t.Fatal("reserved name accepted")
	}
}

func baseConfig(c Config) Config {
	if c.URL == "" {
		c.URL = "http://clickhouse:8123"
	}
	if c.PasswordSecret == "" {
		c.PasswordSecret = testSecret
	}
	return c
}

func TestConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{baseConfig(Config{}), ""},
		{baseConfig(Config{Cluster: "main", DatabaseEngine: "Replicated('/clickhouse/db/{uuid}', '{shard}', '{replica}')"}), ""},
		{Config{PasswordSecret: testSecret}, "url is required"},
		{baseConfig(Config{URL: "clickhouse:8123"}), "url must be"},
		{baseConfig(Config{URL: "http://u:p@clickhouse:8123"}), "credentials"},
		{Config{URL: "http://x"}, "password_secret"},
		{baseConfig(Config{PasswordSecret: "short"}), "password_secret"},
		{baseConfig(Config{Cluster: "a'b"}), "cluster"},
		{baseConfig(Config{DatabaseEngine: "Atomic; DROP DATABASE x"}), "database_engine"},
		{baseConfig(Config{DatabaseEngine: "Atomic -- x"}), "database_engine"},
		{baseConfig(Config{OnDeprovision: "archive"}), "on_deprovision"},
		{baseConfig(Config{TimeoutSeconds: -1}), "timeout_seconds"},
		{baseConfig(Config{Grants: []string{}}), "grants must not be empty"},
		{baseConfig(Config{Grants: []string{"SELECT ON *.* TO x; --"}}), "not a privilege"},
		{baseConfig(Config{Grants: []string{"ALL"}}), ""},
		{baseConfig(Config{NameTemplate: "t_{{.Slug"}), "name_template"},
		{baseConfig(Config{NameTemplate: "t_{{.Nope}}"}), "name_template"},
		{baseConfig(Config{NameTemplate: "{{if false}}x{{end}}"}), "empty name"},
		{baseConfig(Config{NameTemplate: "static"}), "must depend on the tenant"},
		{baseConfig(Config{UserTemplate: "static"}), "user_template must depend"},
		{baseConfig(Config{UserTemplate: "u_{{.Slug}}"}), ""},
		{baseConfig(Config{SettingsProfile: &ProfileConfig{Settings: map[string]any{"max memory": 1}}}), "invalid setting name"},
		{baseConfig(Config{SettingsProfile: &ProfileConfig{Settings: map[string]any{"x": []any{1}}}}), "unsupported value"},
		{baseConfig(Config{SettingsProfile: &ProfileConfig{FromLimits: map[string]string{"x;": "l"}}}), "invalid setting name"},
		{baseConfig(Config{SettingsProfile: &ProfileConfig{Settings: map[string]any{"max_memory_usage": 1e9, "readonly": true}}}), ""},
		{baseConfig(Config{Quota: &QuotaConfig{Interval: "1 fortnight"}}), "quota.interval"},
		{baseConfig(Config{Quota: &QuotaConfig{Limits: map[string]int64{"bogus": 1}}}), "unknown key"},
		{baseConfig(Config{Quota: &QuotaConfig{Limits: map[string]int64{"queries": -1}}}), "negative"},
		{baseConfig(Config{Quota: &QuotaConfig{FromLimits: map[string]string{"bogus": "x"}}}), "unknown key"},
		{baseConfig(Config{Quota: &QuotaConfig{Interval: "30 Days", Limits: map[string]int64{"queries": 10}}}), ""},
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

	// A template rendering "default" (reserved database and user) is rejected.
	p := &Plugin{cfg: baseConfig(Config{NameTemplate: "{{if eq .Slug \"example-one\"}}default{{else}}{{.Slug}}{{end}}"})}
	if err := p.validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved user name: %v", err)
	}

	p = &Plugin{cfg: baseConfig(Config{})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.cfg.OnDeprovision != DeprovisionDelete || p.cfg.NameTemplate != DefaultNameTemplate ||
		p.cfg.Username != "default" || p.cfg.TimeoutSeconds != 30 || !slices.Equal(p.cfg.Grants, DefaultGrants) {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	tg, err := p.target(sdk.Tenant{ID: "id", Slug: "acme-corp"})
	if err != nil || tg.Database != "tenant_acme_corp" || tg.User != "tenant_acme_corp" {
		t.Fatalf("target = %+v, %v", tg, err)
	}
}

func TestConfigSchemaCompiles(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "clickhouse-tenant" {
		t.Fatalf("id %q", m.ID)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]any{
		"url": "http://ch:8123", "password_secret": testSecret, "grants": []any{"SELECT"},
		"settings_profile": map[string]any{"settings": map[string]any{"max_memory_usage": 1}, "from_limits": map[string]any{"max_threads": "ch_threads"}},
		"quota":            map[string]any{"interval": "1 hour", "limits": map[string]any{"queries": 5}},
		"on_deprovision":   "retain",
	}
	if err := s.Validate(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]any{
		{"url": "http://ch:8123"},
		{"url": "http://ch:8123", "password_secret": testSecret, "on_deprovision": "drop"},
		{"url": "http://ch:8123", "password_secret": testSecret, "nope": 1},
		{"url": "http://ch:8123", "password_secret": testSecret, "quota": map[string]any{"bogus": 1}},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("expected schema error for %v", bad)
		}
	}
}

// newTestPlugin initializes the plugin against a fake ClickHouse.
func newTestPlugin(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar, *fakeCH) {
	t.Helper()
	f, srv := newFakeCH(t)
	full := map[string]any{"url": srv.URL, "username": "admin", "password": "secret", "password_secret": testSecret}
	for k, v := range cfg {
		full[k] = v
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	return p, reg, f
}

func TestInitRegisters(t *testing.T) {
	p, reg, _ := newTestPlugin(t, nil)
	if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "clickhouse" {
		t.Fatalf("provisioners %v", reg.Provisioners)
	}
	if len(reg.Routes) != 1 || reg.Routes[0] != "GET /tenants/{tenant}" {
		t.Fatalf("routes %v", reg.Routes)
	}
	var _ sdk.HealthChecker = p
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHealthAuthError(t *testing.T) {
	p, _, _ := newTestPlugin(t, nil)
	p.ch.password = "wrong"
	err := p.Health(context.Background())
	var ce *Error
	if !errors.As(err, &ce) || ce.Code != 516 || ce.Status != http.StatusUnauthorized {
		t.Fatalf("err = %v", err)
	}
}

func TestProvisionLifecycle(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newTestPlugin(t, map[string]any{
		"cluster": "main",
		"settings_profile": map[string]any{
			"settings":    map[string]any{"max_memory_usage": 1000000000, "readonly": false, "load_balancing": "random"},
			"from_limits": map[string]any{"max_memory_usage": "ch_memory"},
		},
		"quota": map[string]any{
			"interval":    "1 hour",
			"limits":      map[string]any{"queries": 1000},
			"from_limits": map[string]any{"read_bytes": "ch_read_bytes", "queries": "ch_queries"},
		},
	})
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"ch_memory": 2000000000, "ch_read_bytes": 5000}})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})

	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if got := f.databases["tenant_acme"]; got != "tenarium:tenant="+ten.ID {
		t.Fatalf("database comment %q", got)
	}
	if f.users["tenant_acme"] != "tenant_acme" || f.passwords["tenant_acme"] != TenantPassword(testSecret, ten.ID) {
		t.Fatalf("user %q password %q", f.users["tenant_acme"], f.passwords["tenant_acme"])
	}
	if g := f.grants["tenant_acme"]; !strings.Contains(g, "ON CLUSTER 'main' SELECT, INSERT, ALTER TABLE") || strings.Contains(g, "DROP DATABASE") {
		t.Fatalf("grant %q", g)
	}
	wantProfile := "CREATE SETTINGS PROFILE OR REPLACE `tenant_acme` ON CLUSTER 'main' SETTINGS load_balancing = 'random' READONLY, " +
		"max_memory_usage = 2000000000 READONLY, readonly = 0 READONLY TO `tenant_acme`"
	if got := f.ddl["profile:tenant_acme"]; got != wantProfile {
		t.Fatalf("profile\n got %s\nwant %s", got, wantProfile)
	}
	wantQuota := "CREATE QUOTA OR REPLACE `tenant_acme` ON CLUSTER 'main' FOR INTERVAL 1 hour MAX queries = 1000, read_bytes = 5000 TO `tenant_acme`"
	if got := f.ddl["quota:tenant_acme"]; got != wantQuota {
		t.Fatalf("quota\n got %s\nwant %s", got, wantQuota)
	}
	for _, q := range f.Queries() {
		if strings.HasPrefix(q, "CREATE DATABASE") && !strings.Contains(q, "ON CLUSTER 'main'") {
			t.Fatalf("missing ON CLUSTER: %s", q)
		}
	}

	// Idempotent; a changed secret rotates the password.
	p.cfg.PasswordSecret = testSecret + "-rotated"
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if f.passwords["tenant_acme"] != TenantPassword(testSecret+"-rotated", ten.ID) {
		t.Fatal("password not rotated")
	}

	// Deprovision drops everything, database last.
	f.tables["tenant_acme"] = []string{"events"}
	n := len(f.Queries())
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if len(f.databases) != 0 || len(f.users) != 0 || len(f.profiles) != 0 || len(f.quotas) != 0 {
		t.Fatalf("leftovers: %v %v %v %v", f.databases, f.users, f.profiles, f.quotas)
	}
	var ddl []string
	for _, q := range f.Queries()[n:] {
		if strings.HasPrefix(q, "DROP") {
			ddl = append(ddl, strings.Fields(q)[1])
		}
	}
	if strings.Join(ddl, ",") != "QUOTA,SETTINGS,USER,DATABASE" {
		t.Fatalf("drop order %v", ddl)
	}
	// Again: nothing left, no error.
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
}

func TestQuotaTrackingOnlyWhenUnlimited(t *testing.T) {
	p, reg, f := newTestPlugin(t, map[string]any{"quota": map[string]any{"from_limits": map[string]any{"queries": "ch_queries"}}})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "free"})
	if err := p.Provision(context.Background(), ten); err != nil {
		t.Fatal(err)
	}
	if got := f.ddl["quota:tenant_free"]; !strings.Contains(got, "FOR INTERVAL 1 hour TRACKING ONLY TO") {
		t.Fatalf("quota %s", got)
	}
}

func TestOwnership(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newTestPlugin(t, nil)
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})

	// Another tenant's database is neither adopted nor dropped.
	f.databases["tenant_acme"] = "tenarium:tenant=other"
	if err := p.Provision(ctx, ten); err == nil || !strings.Contains(err.Error(), "belongs to someone else") {
		t.Fatalf("foreign database: %v", err)
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.databases["tenant_acme"]; !ok {
		t.Fatal("foreign database dropped")
	}

	// A database with an arbitrary comment is foreign too.
	f.databases["tenant_acme"] = "analytics"
	if err := p.Provision(ctx, ten); err == nil {
		t.Fatal("database with foreign comment adopted")
	}

	// Unmarked and not empty: refused, and never dropped.
	f.databases["tenant_acme"] = ""
	f.tables["tenant_acme"] = []string{"data"}
	if err := p.Provision(ctx, ten); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("unmarked non-empty database: %v", err)
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.databases["tenant_acme"]; !ok {
		t.Fatal("unmarked database dropped")
	}

	// Unmarked and empty: adopted.
	delete(f.tables, "tenant_acme")
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if f.databases["tenant_acme"] != ownerMark(ten) {
		t.Fatalf("not claimed: %q", f.databases["tenant_acme"])
	}

	// A user with the same name pointing elsewhere is not taken over.
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "beta"})
	f.users["tenant_beta"] = "somewhere_else"
	f.passwords["tenant_beta"] = "theirs"
	if err := p.Provision(ctx, other); err == nil || !strings.Contains(err.Error(), "not taking it over") {
		t.Fatalf("foreign user: %v", err)
	}
	if f.passwords["tenant_beta"] != "theirs" {
		t.Fatal("foreign user's password changed")
	}
	// Deprovision drops beta's database but not the foreign user.
	if err := p.Deprovision(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.users["tenant_beta"]; !ok {
		t.Fatal("foreign user dropped")
	}

	// A quota that applies to other users is not replaced.
	third := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "gamma"})
	p.cfg.Quota = &QuotaConfig{Interval: "1 hour"}
	f.quotas["tenant_gamma"] = []string{"tenant_gamma", "someone"}
	if err := p.Provision(ctx, third); err == nil || !strings.Contains(err.Error(), "quota tenant_gamma already exists") {
		t.Fatalf("shared quota: %v", err)
	}
}

func TestDeprovisionRetainAndKeep(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newTestPlugin(t, map[string]any{"on_deprovision": "retain"})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	f.tables["tenant_acme"] = []string{"events"}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	want := "tenarium:deleted-tenant=" + ten.ID + " deleted-at=2026-01-02T03:04:05Z"
	if f.databases["tenant_acme"] != want {
		t.Fatalf("retained comment %q", f.databases["tenant_acme"])
	}
	if _, ok := f.users["tenant_acme"]; ok {
		t.Fatal("user not dropped on retain")
	}
	// Idempotent.
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	// Retained data blocks re-provisioning, for the same and a new tenant.
	if err := p.Provision(ctx, ten); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("retained: %v", err)
	}
	reuse := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, reuse); err == nil {
		t.Fatal("new tenant adopted retained database")
	}

	// keep touches nothing.
	pk, reg2, f2 := newTestPlugin(t, map[string]any{"on_deprovision": "keep"})
	tk := reg2.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := pk.Provision(ctx, tk); err != nil {
		t.Fatal(err)
	}
	n := len(f2.Queries())
	if err := pk.Deprovision(ctx, tk); err != nil {
		t.Fatal(err)
	}
	if len(f2.Queries()) != n {
		t.Fatalf("keep sent queries: %v", f2.Queries()[n:])
	}
}

func TestProvisionErrors(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newTestPlugin(t, nil)
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	f.fail["GRANT"] = 497
	err := p.Provision(ctx, ten)
	var ce *Error
	if !errors.As(err, &ce) || ce.Code != 497 || !strings.Contains(err.Error(), "grant on tenant_acme") {
		t.Fatalf("err = %v", err)
	}
	delete(f.fail, "GRANT")
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}

	// Old servers without MODIFY COMMENT: a clear hint when adopting.
	f.fail["MODIFY COMMENT"] = codeSyntaxError
	f.databases["tenant_old"] = ""
	err = p.Provision(ctx, reg.HostImpl.AddTenant(sdk.Tenant{Slug: "old"}))
	if err == nil || !strings.Contains(err.Error(), "need a newer server") {
		t.Fatalf("old server: %v", err)
	}
}

func TestTenantRoute(t *testing.T) {
	_, reg, _ := newTestPlugin(t, map[string]any{"quota": map[string]any{"limits": map[string]any{"queries": 1}}})
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	reg.HostImpl.AddTenant(sdk.Tenant{Slug: "beta"})

	get := func(path string, principal *sdk.Principal) (int, string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if principal != nil {
			req = req.WithContext(sdk.WithPrincipal(req.Context(), principal))
		}
		rec := httptest.NewRecorder()
		reg.Mux.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Result().Body)
		return rec.Code, string(body)
	}

	code, body := get("/tenants/acme", &sdk.Principal{Subject: "admin"})
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var info TenantInfo
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		t.Fatal(err)
	}
	if info.Database != "tenant_acme" || info.User != "tenant_acme" || info.Quota != "tenant_acme" ||
		info.SettingsProfile != "" || !strings.HasPrefix(info.URL, "http://") {
		t.Fatalf("info %+v", info)
	}
	if strings.Contains(body, TenantPassword(testSecret, acme.ID)) || strings.Contains(body, "password") {
		t.Fatalf("password leaked: %s", body)
	}
	// By ID, as the tenant's own admin.
	if code, _ := get("/tenants/"+acme.ID, &sdk.Principal{Subject: "u", TenantID: acme.ID}); code != http.StatusOK {
		t.Fatalf("own tenant: %d", code)
	}
	// Another tenant's caller and anonymous callers get 404.
	if code, _ := get("/tenants/beta", &sdk.Principal{Subject: "u", TenantID: acme.ID}); code != http.StatusNotFound {
		t.Fatalf("other tenant: %d", code)
	}
	if code, _ := get("/tenants/acme", nil); code != http.StatusNotFound {
		t.Fatalf("anonymous: %d", code)
	}
	if code, _ := get("/tenants/nope", &sdk.Principal{Subject: "admin"}); code != http.StatusNotFound {
		t.Fatalf("missing: %d", code)
	}
}
