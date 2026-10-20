package pgtenant

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/jackc/pgx/v5"
)

// fakeRegistrar captures what the plugin registers.
type fakeRegistrar struct {
	cfg         map[string]any
	host        sdk.Host
	provisioner sdk.Provisioner
	mux         *http.ServeMux
}

func (r *fakeRegistrar) Config(v any) error {
	b, err := json.Marshal(r.cfg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func (r *fakeRegistrar) Logger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func (r *fakeRegistrar) Host() sdk.Host       { return r.host }
func (r *fakeRegistrar) InstanceName() string { return "pg" }
func (r *fakeRegistrar) Subscribe(string, sdk.EventFilter, sdk.EventHandler, ...sdk.SubscribeOption) {
}
func (r *fakeRegistrar) Hook(sdk.HookPoint, sdk.HookHandler, ...sdk.HookOption) {}
func (r *fakeRegistrar) Provisioner(p sdk.Provisioner)                          { r.provisioner = p }
func (r *fakeRegistrar) Route(pattern string, h http.Handler)                   { r.mux.Handle(pattern, h) }
func (r *fakeRegistrar) Authenticator(sdk.Authenticator)                        {}
func (r *fakeRegistrar) Authorizer(sdk.Authorizer)                              {}

// fakeHost serves tenants from a slice.
type fakeHost struct{ tenants []sdk.Tenant }

func (h *fakeHost) GetTenant(_ context.Context, idOrSlug string) (sdk.Tenant, error) {
	for _, t := range h.tenants {
		if t.ID == idOrSlug || t.Slug == idOrSlug {
			return t, nil
		}
	}
	return sdk.Tenant{}, sdk.ErrNotFound
}
func (h *fakeHost) ListTenants(context.Context, string, int) ([]sdk.Tenant, error) {
	return h.tenants, nil
}
func (h *fakeHost) GetPlan(context.Context, string) (sdk.Plan, error) {
	return sdk.Plan{}, sdk.ErrNotFound
}
func (h *fakeHost) Entitlements(_ context.Context, id string) (sdk.Entitlements, error) {
	return sdk.Entitlements{TenantID: id}, nil
}

func TestSanitizeIdent(t *testing.T) {
	long := strings.Repeat("a", 80)
	for in, want := range map[string]string{
		"tenant_acme":       "tenant_acme",
		"tenant_acme-corp":  "tenant_acme_corp",
		"Acme Corp.":        "acme_corp_",
		"9lives":            "_9lives",
		"ümlaut":            "_mlaut",
		"":                  "",
		long:                long[:63],
		`x"; DROP TABLE y;`: "x___drop_table_y_",
	} {
		if got := SanitizeIdent(in); got != want {
			t.Errorf("SanitizeIdent(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{Config{DSN: "postgres://x"}, ""},
		{Config{}, "dsn is required"},
		{Config{DSN: "x", Mode: "cluster"}, "mode"},
		{Config{DSN: "x", OnDeprovision: "archive"}, "on_deprovision"},
		{Config{DSN: "x", NameTemplate: "t_{{.Slug"}, "name_template"},
		{Config{DSN: "x", NameTemplate: "t_{{.Nope}}"}, "name_template"},
		{Config{DSN: "x", NameTemplate: "{{if false}}x{{end}}"}, "empty name"},
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

	p := &Plugin{cfg: Config{DSN: "x"}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.cfg.Mode != ModeSchema || p.cfg.OnDeprovision != DeprovisionDrop || p.cfg.NameTemplate != DefaultNameTemplate {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	tg, err := p.target(sdk.Tenant{ID: "id", Slug: "acme-corp"})
	if err != nil || tg.Name != "tenant_acme_corp" || tg.Role != "" {
		t.Fatalf("target = %+v, %v", tg, err)
	}
}

func TestDeletedNameFits(t *testing.T) {
	p := &Plugin{now: func() time.Time { return time.Unix(1700000000, 0) }}
	if got := p.deletedName("tenant_x"); got != "tenant_x_deleted_1700000000" {
		t.Fatalf("got %q", got)
	}
	if got := p.deletedName(strings.Repeat("a", 63)); len(got) != 63 || !strings.HasSuffix(got, "_deleted_1700000000") {
		t.Fatalf("got %q (%d bytes)", got, len(got))
	}
}

// --- integration tests against a real PostgreSQL ---

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TENARIUM_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TENARIUM_TEST_POSTGRES_DSN not set")
	}
	return dsn
}

func adminConn(t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// freshDB creates a throwaway database and returns its DSN.
func freshDB(t *testing.T, adminDSN string) string {
	t.Helper()
	name := fmt.Sprintf("pgtenant_test_%d", time.Now().UnixNano())
	if _, err := adminConn(t, adminDSN).Exec(context.Background(), "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		c, err := pgx.Connect(ctx, adminDSN)
		if err != nil {
			return
		}
		defer c.Close(ctx)
		_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

// uniqueTenant returns a tenant whose slug contains dashes and is unique
// across runs, since roles and databases are cluster-wide. Leftover roles
// and databases matching it are removed in cleanup, so call it before
// freshDB: cleanups run in reverse and roles owning objects in the fresh
// database can only be dropped once it is gone.
func uniqueTenant(t *testing.T, adminDSN string) sdk.Tenant {
	t.Helper()
	slug := fmt.Sprintf("acme-corp-%d", time.Now().UnixNano())
	name := SanitizeIdent("tenant_" + slug)
	t.Cleanup(func() {
		ctx := context.Background()
		c, err := pgx.Connect(ctx, adminDSN)
		if err != nil {
			return
		}
		defer c.Close(ctx)
		var dbs, roles []string
		_ = c.QueryRow(ctx, `SELECT coalesce(array_agg(datname), '{}') FROM pg_database WHERE datname LIKE $1`, name+"%").Scan(&dbs)
		_ = c.QueryRow(ctx, `SELECT coalesce(array_agg(rolname), '{}') FROM pg_roles WHERE rolname LIKE $1`, name+"%").Scan(&roles)
		for _, d := range dbs {
			_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+quote(d)+" WITH (FORCE)")
		}
		for _, r := range roles {
			_, _ = c.Exec(ctx, "DROP OWNED BY "+quote(r))
			_, _ = c.Exec(ctx, "DROP ROLE IF EXISTS "+quote(r))
		}
	})
	return sdk.Tenant{ID: fmt.Sprintf("id-%d", time.Now().UnixNano()), Slug: slug, Name: "Acme"}
}

func newPlugin(t *testing.T, cfg map[string]any, tenants ...sdk.Tenant) (*Plugin, *fakeRegistrar) {
	t.Helper()
	r := &fakeRegistrar{cfg: cfg, host: &fakeHost{tenants: tenants}, mux: http.NewServeMux()}
	p := &Plugin{}
	if err := p.Init(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	if r.provisioner != p {
		t.Fatal("provisioner not registered")
	}
	return p, r
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func queryBool(t *testing.T, conn *pgx.Conn, sql string, args ...any) bool {
	t.Helper()
	var b bool
	if err := conn.QueryRow(context.Background(), sql, args...).Scan(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

func hasSchema(t *testing.T, c *pgx.Conn, n string) bool { return queryBool(t, c, schemaExists, n) }
func hasRole(t *testing.T, c *pgx.Conn, n string) bool   { return queryBool(t, c, roleExists, n) }
func hasDB(t *testing.T, c *pgx.Conn, n string) bool     { return queryBool(t, c, databaseExists, n) }

func TestSchemaModeProvisionAndDrop(t *testing.T) {
	admin := testDSN(t)
	tenant := uniqueTenant(t, admin)
	dsn := freshDB(t, admin)
	dir := t.TempDir()
	writeFile(t, dir, "001_items.sql", `CREATE TABLE {{.Schema}}.items (id serial PRIMARY KEY, name text);`)
	writeFile(t, dir, "002_seed.sql", `INSERT INTO items (name) VALUES ('{{.Slug}}'); -- search_path is the tenant schema`)

	p, _ := newPlugin(t, map[string]any{"dsn": dsn, "create_role": true, "migrations_dir": dir})
	ctx := context.Background()
	conn := adminConn(t, dsn)
	name := "tenant_" + strings.ReplaceAll(tenant.Slug, "-", "_")

	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := p.Provision(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if !hasSchema(t, conn, name) || !hasRole(t, conn, name) {
		t.Fatalf("schema or role %s missing", name)
	}
	var owner string
	if err := conn.QueryRow(ctx, `SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = $1`, name).Scan(&owner); err != nil || owner != name {
		t.Fatalf("schema owner = %q, %v", owner, err)
	}
	if err := conn.QueryRow(ctx, `SELECT tableowner FROM pg_tables WHERE schemaname = $1 AND tablename = 'items'`, name).Scan(&owner); err != nil || owner != name {
		t.Fatalf("table owner = %q, %v", owner, err)
	}
	countRows := func(table string) int {
		var n int
		if err := conn.QueryRow(ctx, "SELECT count(*) FROM "+quote(name)+"."+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := countRows("items"); n != 1 {
		t.Fatalf("items rows = %d, want 1 (seed applied once)", n)
	}
	if n := countRows(migrationsTable); n != 2 {
		t.Fatalf("applied migrations = %d, want 2", n)
	}

	writeFile(t, dir, "003_more.sql", `ALTER TABLE items ADD COLUMN tenant_id text DEFAULT '{{.TenantID}}';`)
	if err := p.Provision(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if n := countRows("items"); n != 1 {
		t.Fatalf("items rows = %d after 3rd migration, want 1", n)
	}
	if n := countRows(migrationsTable); n != 3 {
		t.Fatalf("applied migrations = %d, want 3", n)
	}
	var tid string
	if err := conn.QueryRow(ctx, "SELECT tenant_id FROM "+quote(name)+".items").Scan(&tid); err != nil || tid != tenant.ID {
		t.Fatalf("tenant_id = %q, %v", tid, err)
	}

	for range 2 {
		if err := p.Deprovision(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if hasSchema(t, conn, name) || hasRole(t, conn, name) {
		t.Fatal("schema or role still exists after drop")
	}
}

func TestFailingMigrationIsRolledBack(t *testing.T) {
	admin := testDSN(t)
	tenant := uniqueTenant(t, admin)
	dsn := freshDB(t, admin)
	dir := t.TempDir()
	writeFile(t, dir, "001_bad.sql", `CREATE TABLE a (id int); SELECT * FROM missing_table;`)
	p, _ := newPlugin(t, map[string]any{"dsn": dsn, "migrations_dir": dir})
	if err := p.Provision(context.Background(), tenant); err == nil {
		t.Fatal("expected error")
	}
	conn := adminConn(t, dsn)
	if queryBool(t, conn, `SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'a')`) {
		t.Fatal("partial migration was committed")
	}
}

func TestDeprovisionNeverProvisioned(t *testing.T) {
	admin := testDSN(t)
	tenant := uniqueTenant(t, admin)
	for _, mode := range []string{ModeSchema, ModeDatabase} {
		for _, action := range []string{DeprovisionDrop, DeprovisionRename, DeprovisionKeep} {
			p, _ := newPlugin(t, map[string]any{"dsn": admin, "mode": mode, "create_role": true, "on_deprovision": action})
			if err := p.Deprovision(context.Background(), tenant); err != nil {
				t.Fatalf("%s/%s: %v", mode, action, err)
			}
		}
	}
}

func TestSchemaModeRename(t *testing.T) {
	admin := testDSN(t)
	tenant := uniqueTenant(t, admin)
	dsn := freshDB(t, admin)
	p, _ := newPlugin(t, map[string]any{"dsn": dsn, "create_role": true, "on_deprovision": "rename"})
	p.now = func() time.Time { return time.Unix(1700000000, 0) }
	ctx := context.Background()
	if err := p.Provision(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	tg, _ := p.target(tenant)
	for range 2 {
		if err := p.Deprovision(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	conn := adminConn(t, dsn)
	renamed := p.deletedName(tg.Name)
	if hasSchema(t, conn, tg.Name) || !hasSchema(t, conn, renamed) {
		t.Fatalf("schema not renamed to %s", renamed)
	}
	if hasRole(t, conn, tg.Role) || !hasRole(t, conn, renamed) {
		t.Fatalf("role not renamed to %s", renamed)
	}
	// The slug can be reused by a new tenant.
	if err := p.Provision(ctx, tenant); err != nil || !hasSchema(t, conn, tg.Name) {
		t.Fatalf("re-provision after rename: %v", err)
	}
}

func TestSchemaModeKeep(t *testing.T) {
	admin := testDSN(t)
	tenant := uniqueTenant(t, admin)
	dsn := freshDB(t, admin)
	p, _ := newPlugin(t, map[string]any{"dsn": dsn, "create_role": true, "on_deprovision": "keep"})
	ctx := context.Background()
	if err := p.Provision(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	tg, _ := p.target(tenant)
	conn := adminConn(t, dsn)
	if !hasSchema(t, conn, tg.Name) || !hasRole(t, conn, tg.Role) {
		t.Fatal("keep removed the schema or role")
	}
}

func TestDatabaseMode(t *testing.T) {
	admin := testDSN(t)
	tenant := uniqueTenant(t, admin)
	dir := t.TempDir()
	writeFile(t, dir, "001_items.sql", `CREATE TABLE {{.Schema}}.items (id int); INSERT INTO items VALUES (1);`)
	p, _ := newPlugin(t, map[string]any{"dsn": admin, "mode": "database", "create_role": true, "migrations_dir": dir})
	ctx := context.Background()
	for range 2 {
		if err := p.Provision(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	tg, _ := p.target(tenant)
	conn := adminConn(t, admin)
	if !hasDB(t, conn, tg.Name) || !hasRole(t, conn, tg.Role) {
		t.Fatal("database or role missing")
	}
	var owner string
	if err := conn.QueryRow(ctx, `SELECT datdba::regrole::text FROM pg_database WHERE datname = $1`, tg.Name).Scan(&owner); err != nil || owner != tg.Role {
		t.Fatalf("database owner = %q, %v", owner, err)
	}
	cc, _ := pgx.ParseConfig(admin)
	cc.Database = tg.Name
	tc, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	err = tc.QueryRow(ctx, "SELECT count(*) FROM items").Scan(&n)
	tc.Close(ctx) // an open session must not block DROP ... WITH (FORCE) anyway
	if err != nil || n != 1 {
		t.Fatalf("items = %d, %v", n, err)
	}

	for range 2 {
		if err := p.Deprovision(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if hasDB(t, conn, tg.Name) || hasRole(t, conn, tg.Role) {
		t.Fatal("database or role still exists after drop")
	}
}

func TestDatabaseModeRename(t *testing.T) {
	admin := testDSN(t)
	tenant := uniqueTenant(t, admin)
	p, _ := newPlugin(t, map[string]any{"dsn": admin, "mode": "database", "on_deprovision": "rename"})
	// The new name carries a timestamp: pin it so the check below computes the same one.
	p.now = func() time.Time { return time.Unix(1700000000, 0) }
	ctx := context.Background()
	if err := p.Provision(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	tg, _ := p.target(tenant)
	if err := p.Deprovision(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	conn := adminConn(t, admin)
	if hasDB(t, conn, tg.Name) || !hasDB(t, conn, p.deletedName(tg.Name)) {
		t.Fatal("database not renamed")
	}
}

func TestRoute(t *testing.T) {
	tenant := sdk.Tenant{ID: "t-1", Slug: "acme-corp"}
	_, r := newPlugin(t, map[string]any{"dsn": "postgres://localhost:1/x", "create_role": true}, tenant)
	for _, ref := range []string{"t-1", "acme-corp"} {
		rec := httptest.NewRecorder()
		r.mux.ServeHTTP(rec, asCaller("", "/tenants/"+ref))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", ref, rec.Code)
		}
		var got map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"mode": "schema", "schema": "tenant_acme_corp", "role": "tenant_acme_corp"}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s: got %v, want %v", ref, got, want)
		}
	}
	rec := httptest.NewRecorder()
	r.mux.ServeHTTP(rec, asCaller("", "/tenants/nope"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing tenant: status %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	r.mux.ServeHTTP(rec, asCaller("other-tenant", "/tenants/acme-corp"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("caller scoped to another tenant: status %d", rec.Code)
	}

	_, r = newPlugin(t, map[string]any{"dsn": "postgres://localhost:1/x", "mode": "database", "name_template": "db_{{.ID}}"}, tenant)
	rec = httptest.NewRecorder()
	r.mux.ServeHTTP(rec, asCaller("", "/tenants/acme-corp"))
	if body := strings.TrimSpace(rec.Body.String()); body != `{"mode":"database","database":"db_t_1"}` {
		t.Fatalf("got %s", body)
	}
}

// asCaller builds a request from a platform caller (tenant "") or one scoped
// to tenant.
func asCaller(tenant, path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	return r.WithContext(sdk.WithPrincipal(r.Context(), &sdk.Principal{Subject: "u", TenantID: tenant}))
}

// Authorize allows platform callers and callers scoped to the tenant itself.
func (h *fakeHost) Authorize(ctx context.Context, _ sdk.Action, res sdk.Resource) error {
	p, ok := sdk.PrincipalFrom(ctx)
	if !ok || (p.TenantID != "" && p.TenantID != res.TenantID) {
		return sdk.ErrForbidden
	}
	return nil
}

// Two tenants must never share a schema or role, and one tenant's
// deprovisioning must never touch another's data.
func TestNameClashesAreRefused(t *testing.T) {
	admin := testDSN(t)
	dsn := freshDB(t, admin)
	ctx := context.Background()

	// Long slugs differing only after the 63-byte cut get distinct names.
	base := uniqueTenant(t, admin)
	long := strings.Repeat("x", 63-len(base.Slug)-1)
	a := sdk.Tenant{ID: base.ID + "-a", Slug: base.Slug + "-" + long[:len(long)-1] + "a"}
	b := sdk.Tenant{ID: base.ID + "-b", Slug: base.Slug + "-" + long[:len(long)-1] + "b"}
	p, _ := newPlugin(t, map[string]any{"dsn": dsn, "create_role": true})
	ta, _ := p.target(a)
	tb, _ := p.target(b)
	if ta.Name == tb.Name || len(ta.Name) > maxIdentLen {
		t.Fatalf("long names clash or overflow: %q %q", ta.Name, tb.Name)
	}

	// A slug reused after "keep" does not adopt the old tenant's data.
	keep, _ := newPlugin(t, map[string]any{"dsn": dsn, "create_role": true, "on_deprovision": "keep"})
	if err := keep.Provision(ctx, base); err != nil {
		t.Fatal(err)
	}
	if err := keep.Deprovision(ctx, base); err != nil {
		t.Fatal(err)
	}
	successor := sdk.Tenant{ID: base.ID + "-new", Slug: base.Slug}
	if err := keep.Provision(ctx, successor); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("successor adopted the old schema: %v", err)
	}

	// Deprovisioning the successor must leave the old tenant's data alone.
	drop, _ := newPlugin(t, map[string]any{"dsn": dsn, "create_role": true})
	if err := drop.Deprovision(ctx, successor); err != nil {
		t.Fatal(err)
	}
	tg, _ := drop.target(base)
	conn := adminConn(t, dsn)
	if !hasSchema(t, conn, tg.Name) || !hasRole(t, conn, tg.Role) {
		t.Fatal("another tenant's schema or role was dropped")
	}
	// The rightful owner can still drop it.
	if err := drop.Deprovision(ctx, base); err != nil {
		t.Fatal(err)
	}
	if hasSchema(t, conn, tg.Name) || hasRole(t, conn, tg.Role) {
		t.Fatal("owner could not drop its schema")
	}
}

func (h *fakeHost) GetUser(context.Context, string) (sdk.User, error) {
	return sdk.User{}, sdk.ErrNotFound
}

func (r *fakeRegistrar) UserDirectory(sdk.UserDirectory) {}
func (r *fakeRegistrar) Mailer(sdk.Mailer)               {}

func (h *fakeHost) SuspendTenant(context.Context, string, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, sdk.ErrUnsupported
}
func (h *fakeHost) ResumeTenant(context.Context, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, sdk.ErrUnsupported
}
func (h *fakeHost) SetTenantPlan(context.Context, string, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, sdk.ErrUnsupported
}
func (h *fakeHost) RecordUsage(context.Context, string, string, int64) (int64, error) {
	return 0, sdk.ErrUnsupported
}

func (r *fakeRegistrar) PublicRoute(string, http.Handler) {}
