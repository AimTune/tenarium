package mysqltenant

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

const testSecret = "0123456789abcdef-secret"

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"tenant_acme":          "tenant_acme",
		"Tenant-Acme Corp.":    "tenant_acme_corp_",
		"a`b'c\"d\\e":          "a_b_c_d_e",
		"ümlaut":               "_mlaut",
		"":                     "",
		"x`; DROP DATABASE y;": "x___drop_database_y_",
	} {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQuoting(t *testing.T) {
	if got := quoteIdent("a`b"); got != "`a``b`" {
		t.Errorf("quoteIdent = %s", got)
	}
	if got, err := quoteString("it's"); err != nil || got != "'it''s'" {
		t.Errorf("quoteString = %s, %v", got, err)
	}
	for _, bad := range []string{`a\b`, "a\nb", "a\x00b"} {
		if _, err := quoteString(bad); err == nil {
			t.Errorf("quoteString(%q) accepted", bad)
		}
	}
	acct, err := target{User: "u", Host: "%"}.account()
	if err != nil || acct != "'u'@'%'" {
		t.Errorf("account = %s, %v", acct, err)
	}
}

func TestTenantPassword(t *testing.T) {
	m := hmac.New(sha256.New, []byte("s"))
	m.Write([]byte("tenant-1"))
	want := hex.EncodeToString(m.Sum(nil))[:32]
	if got := TenantPassword("s", "tenant-1"); got != want || len(got) != 32 {
		t.Fatalf("TenantPassword = %q, want %q", got, want)
	}
	if TenantPassword("s", "tenant-1") == TenantPassword("s", "tenant-2") ||
		TenantPassword("s", "tenant-1") == TenantPassword("t", "tenant-1") {
		t.Fatal("passwords must depend on secret and tenant")
	}
}

func TestRenderNameLimits(t *testing.T) {
	long := strings.Repeat("very-long-slug-", 10)
	a := sdk.Tenant{ID: "11111111-1111-1111-1111-111111111111", Slug: long}
	b := sdk.Tenant{ID: "22222222-2222-2222-2222-222222222222", Slug: long}
	for _, maxLen := range []int{maxDatabaseLen, maxUserLen} {
		tmpl, err := parseNameTemplate("name_template", DefaultNameTemplate, maxLen)
		if err != nil {
			t.Fatal(err)
		}
		na, err := renderName(tmpl, a, maxLen)
		if err != nil {
			t.Fatal(err)
		}
		nb, err := renderName(tmpl, b, maxLen)
		if err != nil {
			t.Fatal(err)
		}
		if na == nb {
			t.Fatalf("long names collide: %q", na)
		}
		for _, n := range []string{na, nb} {
			if len(n) != maxLen || !strings.HasPrefix(n, "tenant_very_long_slug") {
				t.Errorf("bad shortened name %q (max %d)", n, maxLen)
			}
		}
		if again, _ := renderName(tmpl, a, maxLen); again != na {
			t.Fatalf("name not stable: %q vs %q", again, na)
		}
	}
	tmpl, _ := parseNameTemplate("name_template", "{{.Slug}}", maxDatabaseLen)
	if _, err := renderName(tmpl, sdk.Tenant{ID: "x", Slug: "mysql"}, maxDatabaseLen); err == nil {
		t.Fatal("reserved name accepted")
	}
	if _, err := renderName(tmpl, sdk.Tenant{ID: "x", Slug: "--"}, maxDatabaseLen); err == nil {
		t.Fatal("underscore-only name accepted")
	}
}

func baseConfig(c Config) Config {
	if c.DSN == "" {
		c.DSN = "root:pw@tcp(db.example:3306)/"
	}
	if c.PasswordSecret == "" && (c.CreateUser == nil || *c.CreateUser) {
		c.PasswordSecret = testSecret
	}
	return c
}

func TestConfigValidation(t *testing.T) {
	no := false
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{baseConfig(Config{}), ""},
		{Config{DSN: "root@tcp(x:3306)/", CreateUser: &no}, ""},
		{Config{PasswordSecret: testSecret}, "dsn is required"},
		{baseConfig(Config{DSN: "not a dsn"}), "dsn"},
		{baseConfig(Config{OnDeprovision: "drop"}), "on_deprovision"},
		{Config{DSN: "root@tcp(x:3306)/"}, "password_secret"},
		{Config{DSN: "root@tcp(x:3306)/", PasswordSecret: "short"}, "password_secret"},
		{Config{DSN: "root@tcp(x:3306)/", CreateUser: &no, PasswordSecret: testSecret}, "password_secret requires create_user"},
		{Config{DSN: "root@tcp(x:3306)/", CreateUser: &no, Limits: map[string]string{"max_user_connections": "c"}}, "limits requires create_user"},
		{baseConfig(Config{NameTemplate: "t_{{.Slug"}), "name_template"},
		{baseConfig(Config{NameTemplate: "t_{{.Nope}}"}), "name_template"},
		{baseConfig(Config{NameTemplate: "{{if false}}x{{end}}"}), "empty name"},
		{baseConfig(Config{NameTemplate: "static"}), "name_template must depend on the tenant"},
		{baseConfig(Config{UserTemplate: "app"}), "user_template must depend on the tenant"},
		{baseConfig(Config{UserTemplate: "u_{{.ID}}"}), ""},
		{baseConfig(Config{UserHost: "10.0.0.%"}), ""},
		{baseConfig(Config{UserHost: "x' OR '1"}), "user_host"},
		{baseConfig(Config{Privileges: []string{"select", "insert", "create temporary tables"}}), ""},
		{baseConfig(Config{Privileges: []string{"SELECT; DROP"}}), "privileges"},
		{baseConfig(Config{Charset: "utf8mb4; x"}), "charset"},
		{baseConfig(Config{Collation: "utf8mb4_0900_ai_ci"}), ""},
		{baseConfig(Config{Collation: "a b"}), "collation"},
		{baseConfig(Config{Limits: map[string]string{"max_user_connections": "db_connections"}}), ""},
		{baseConfig(Config{Limits: map[string]string{"max_cpu": "x"}}), "unknown option"},
		{baseConfig(Config{Limits: map[string]string{"max_user_connections": ""}}), "limit name is required"},
		{baseConfig(Config{ConnectAddress: "nohost"}), "connect_address"},
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

	p := &Plugin{cfg: baseConfig(Config{Privileges: []string{"select", " insert "}})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.cfg.OnDeprovision != DeprovisionDelete || p.cfg.NameTemplate != DefaultNameTemplate ||
		!*p.cfg.CreateUser || p.cfg.UserHost != "%" || p.cfg.Charset != "utf8mb4" {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	if p.privs != "SELECT, INSERT" {
		t.Fatalf("privs %q", p.privs)
	}
	tg, err := p.target(sdk.Tenant{ID: "id-1", Slug: "acme-corp"})
	if err != nil || tg.Database != "tenant_acme_corp" || tg.User != "tenant_acme_corp" || tg.Host != "%" {
		t.Fatalf("target = %+v, %v", tg, err)
	}
	if _, err := p.target(sdk.Tenant{ID: "bad'id", Slug: "x"}); err == nil {
		t.Fatal("unsafe tenant ID accepted")
	}

	p = &Plugin{cfg: baseConfig(Config{})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.privs != "ALL PRIVILEGES" {
		t.Fatalf("default privs %q", p.privs)
	}

	// A template rendering the admin user's name is refused.
	p = &Plugin{cfg: baseConfig(Config{DSN: "tenant_root@tcp(x:3306)/", UserTemplate: "tenant_{{.Slug}}"})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.target(sdk.Tenant{ID: "id", Slug: "root"}); err == nil || !strings.Contains(err.Error(), "admin user") {
		t.Fatalf("admin user clash: %v", err)
	}

	// Without create_user there is no user.
	p = &Plugin{cfg: Config{DSN: "root@tcp(x:3306)/", CreateUser: &no}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if tg, err := p.target(sdk.Tenant{ID: "id", Slug: "a"}); err != nil || tg.User != "" {
		t.Fatalf("target = %+v, %v", tg, err)
	}
}

func TestMigrationsDirValidation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "001.sql"), []byte("CREATE TABLE {{.Nope}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMigrations(dir); err == nil {
		t.Fatal("bad template accepted")
	}
	if _, err := loadMigrations(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing dir accepted")
	}
}

func TestConfigSchemaCompiles(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "mysql-tenant" {
		t.Fatalf("id %q", m.ID)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(map[string]any{
		"dsn": "root@tcp(x)/", "password_secret": testSecret, "privileges": []any{"SELECT"},
		"limits": map[string]any{"max_user_connections": "conns"}, "on_deprovision": "retain",
	}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]any{
		{},
		{"dsn": "x", "on_deprovision": "drop"},
		{"dsn": "x", "limits": map[string]any{"max_cpu": "x"}},
		{"dsn": "x", "privileges": []any{"SELECT; DROP"}},
		{"dsn": "x", "unknown": 1},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("expected schema error for %v", bad)
		}
	}
}

func newTestPlugin(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	full := map[string]any{"dsn": "root:pw@tcp(127.0.0.1:1)/", "password_secret": testSecret}
	for k, v := range cfg {
		full[k] = v
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	return p, reg
}

func TestInitRegisters(t *testing.T) {
	p, reg := newTestPlugin(t, nil)
	if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "mysql" {
		t.Fatalf("provisioners %v", reg.Provisioners)
	}
	if len(reg.Routes) != 1 || reg.Routes[0] != "GET /tenants/{tenant}" {
		t.Fatalf("routes %v", reg.Routes)
	}
	var _ sdk.HealthChecker = p
	var _ sdk.Stopper = p
	// Nothing listens on port 1.
	ctx, cancel := context.WithTimeout(context.Background(), 5e9)
	defer cancel()
	if err := p.Health(ctx); err == nil {
		t.Fatal("health succeeded without a server")
	}
}

func TestResourceLimits(t *testing.T) {
	p, reg := newTestPlugin(t, map[string]any{"limits": map[string]any{
		"max_user_connections": "db_connections",
		"max_queries_per_hour": "db_queries",
		"max_updates_per_hour": "db_updates",
	}})
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"db_connections": 10, "db_updates": -1}})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro", Limits: map[string]int64{"db_queries": 1 << 40}})
	got, err := p.resourceLimits(context.Background(), ten)
	if err != nil {
		t.Fatal(err)
	}
	want := " MAX_QUERIES_PER_HOUR 4294967295 MAX_UPDATES_PER_HOUR 0 MAX_USER_CONNECTIONS 10"
	if got != want {
		t.Fatalf("limits %q, want %q", got, want)
	}
	if _, err := p.resourceLimits(context.Background(), sdk.Tenant{ID: "missing"}); err == nil {
		t.Fatal("missing tenant accepted")
	}

	p, _ = newTestPlugin(t, nil)
	if got, err := p.resourceLimits(context.Background(), ten); err != nil || got != "" {
		t.Fatalf("limits without config: %q, %v", got, err)
	}
}

func TestRedact(t *testing.T) {
	err := redact(errors.New("syntax error near 'abc123' at line 1"), "abc123")
	if strings.Contains(err.Error(), "abc123") {
		t.Fatal(err)
	}
	orig := errors.New("x")
	if !errors.Is(redact(orig, "abc"), orig) || redact(nil, "abc") != nil {
		t.Fatal("redact changed unrelated error")
	}
}

func TestRoute(t *testing.T) {
	_, reg := newTestPlugin(t, map[string]any{"connect_address": "mysql.internal:3307"})
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme"})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "other", Name: "Other"})

	// Members of a tenant may read; only "admin" may update.
	reg.HostImpl.AuthorizeFunc = func(_ context.Context, pr *sdk.Principal, action sdk.Action, res sdk.Resource) error {
		if pr.TenantID != "" && pr.TenantID != res.TenantID {
			return sdk.ErrForbidden
		}
		if action == sdk.ActionTenantsUpdate && pr.Subject != "admin" {
			return fmt.Errorf("%w: read-only", sdk.ErrForbidden)
		}
		return nil
	}
	call := func(principal *sdk.Principal, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if principal != nil {
			req = req.WithContext(sdk.WithPrincipal(req.Context(), principal))
		}
		rec := httptest.NewRecorder()
		reg.Mux.ServeHTTP(rec, req)
		return rec
	}
	admin := &sdk.Principal{Subject: "admin"}
	member := &sdk.Principal{Subject: "member", TenantID: acme.ID}

	if rec := call(admin, "/tenants/nope"); rec.Code != http.StatusNotFound {
		t.Fatalf("missing tenant: %d", rec.Code)
	}
	if rec := call(member, "/tenants/"+other.Slug); rec.Code != http.StatusNotFound {
		t.Fatalf("other tenant: %d %s", rec.Code, rec.Body)
	}
	if rec := call(nil, "/tenants/acme"); rec.Code != http.StatusNotFound {
		t.Fatalf("no caller: %d", rec.Code)
	}

	rec := call(member, "/tenants/acme")
	if rec.Code != http.StatusOK {
		t.Fatalf("member: %d %s", rec.Code, rec.Body)
	}
	var info TenantInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	want := TenantInfo{Database: "tenant_acme", User: "tenant_acme", UserHost: "%", Host: "mysql.internal", Port: 3307,
		DSN: "tenant_acme@tcp(mysql.internal:3307)/tenant_acme"}
	if info != want {
		t.Fatalf("info %+v, want %+v", info, want)
	}
	pw := TenantPassword(testSecret, acme.ID)
	if strings.Contains(rec.Body.String(), pw) {
		t.Fatal("password leaked without reveal")
	}

	if rec := call(member, "/tenants/acme?reveal=true"); rec.Code != http.StatusForbidden {
		t.Fatalf("member reveal: %d", rec.Code)
	}
	rec = call(admin, "/tenants/"+acme.ID+"?reveal=true")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin reveal: %d %s", rec.Code, rec.Body)
	}
	info = TenantInfo{}
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Password != pw || info.DSN != "tenant_acme:"+pw+"@tcp(mysql.internal:3307)/tenant_acme" {
		t.Fatalf("revealed info %+v", info)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("revealed credentials must not be cached")
	}
	// Without reveal, admins get the same redacted view.
	if rec := call(admin, "/tenants/acme"); strings.Contains(rec.Body.String(), pw) {
		t.Fatal("password returned without reveal")
	}
}

func TestRouteDefaultAddress(t *testing.T) {
	_, reg := newTestPlugin(t, map[string]any{"dsn": "root:pw@tcp(db.example:3306)/", "create_user": false, "password_secret": nil})
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	req := httptest.NewRequest(http.MethodGet, "/tenants/acme", nil)
	req = req.WithContext(sdk.WithPrincipal(req.Context(), &sdk.Principal{Subject: "admin"}))
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	var info TenantInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err, rec.Body.String())
	}
	if info.Host != "db.example" || info.Port != 3306 || info.User != "" || info.DSN != "tcp(db.example:3306)/tenant_acme" {
		t.Fatalf("info %+v", info)
	}
	req = httptest.NewRequest(http.MethodGet, "/tenants/"+acme.ID+"?reveal=1", nil)
	req = req.WithContext(sdk.WithPrincipal(req.Context(), &sdk.Principal{Subject: "admin"}))
	rec = httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("reveal without users: %d", rec.Code)
	}
}
