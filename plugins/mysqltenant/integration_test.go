package mysqltenant

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/go-sql-driver/mysql"
)

// Integration tests run against a MySQL 8 or MariaDB server whose admin
// DSN (go-sql-driver format) is in TENARIUM_TEST_MYSQL_DSN, e.g.
//
//	docker run -d --name tenarium-test-mysql -e MYSQL_ROOT_PASSWORD=pw -p 47306:3306 mysql:8
//	TENARIUM_TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:47306)/' go test ./plugins/mysqltenant/

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TENARIUM_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TENARIUM_TEST_MYSQL_DSN not set")
	}
	return dsn
}

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// admin opens an admin connection for assertions and cleanup.
func admin(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("mysql", testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newIntegrationPlugin initializes the plugin against the test server with
// cfg merged over defaults.
func newIntegrationPlugin(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	full := map[string]any{"dsn": testDSN(t), "password_secret": testSecret}
	for k, v := range cfg {
		full[k] = v
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("health: %v", err)
	}
	return p, reg
}

// cleanup drops db and user at the end of the test.
func cleanup(t *testing.T, adm *sql.DB, db, user string) {
	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := adm.ExecContext(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(db)); err != nil {
			t.Logf("cleanup %s: %v", db, err)
		}
		if user != "" {
			if _, err := adm.ExecContext(ctx, "DROP USER IF EXISTS '"+user+"'@'%'"); err != nil {
				t.Logf("cleanup %s: %v", user, err)
			}
		}
	})
}

func dbExists(t *testing.T, adm *sql.DB, db string) bool {
	t.Helper()
	var n int
	if err := adm.QueryRow("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?", db).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func userExists(t *testing.T, adm *sql.DB, user string) bool {
	t.Helper()
	var n int
	if err := adm.QueryRow("SELECT COUNT(*) FROM mysql.user WHERE User = ?", user).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// revealed calls the tenant route as an admin with ?reveal=true.
func revealed(t *testing.T, reg *sdktest.Registrar, tenant string) TenantInfo {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/tenants/"+tenant+"?reveal=true", nil)
	req = req.WithContext(sdk.WithPrincipal(req.Context(), &sdk.Principal{Subject: "admin"}))
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("route: %d %s", rec.Code, rec.Body)
	}
	var info TenantInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	return info
}

// connectAs opens a connection with a tenant DSN and pings it.
func connectAs(dsn string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func TestIntegrationLifecycle(t *testing.T) {
	ctx := context.Background()
	adm := admin(t)
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("001_init.sql", `CREATE TABLE IF NOT EXISTS {{.Database}}.notes (id INT PRIMARY KEY, body TEXT);
CREATE TABLE IF NOT EXISTS settings (k VARCHAR(64) PRIMARY KEY, v TEXT);`)
	write("002_seed.sql", `INSERT INTO settings (k, v) VALUES ('tenant', '{{.TenantID}}'), ('db', '{{.Name}}');`)

	p, reg := newIntegrationPlugin(t, map[string]any{
		"migrations_dir": dir,
		"privileges":     []any{"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE"},
		"limits":         map[string]any{"max_user_connections": "db_connections", "max_queries_per_hour": "db_queries"},
	})
	slug := "it-" + randHex(t)
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Name: slug, Limits: map[string]int64{"db_connections": 7}})
	tg, err := p.target(ten)
	if err != nil {
		t.Fatal(err)
	}
	cleanup(t, adm, tg.Database, tg.User)

	for i := range 2 { // idempotent
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatalf("provision #%d: %v", i, err)
		}
	}
	if !dbExists(t, adm, tg.Database) || !userExists(t, adm, tg.User) {
		t.Fatal("database or user missing")
	}
	var owner string
	if err := adm.QueryRow("SELECT tenant_id FROM " + ownerSQL(tg.Database) + " WHERE id = 1").Scan(&owner); err != nil || owner != ten.ID {
		t.Fatalf("owner marker %q, %v", owner, err)
	}
	attrs, err := p.userAttributes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("server supports user attributes: %v", attrs)
	if attrs {
		if mark, err := p.userMark(ctx, tg); err != nil || mark != ten.ID {
			t.Fatalf("user attribute %q, %v", mark, err)
		}
	}
	var maxConns, maxQueries int64
	if err := adm.QueryRow("SELECT max_user_connections, max_questions FROM mysql.user WHERE User = ? AND Host = '%'", tg.User).
		Scan(&maxConns, &maxQueries); err != nil {
		t.Fatal(err)
	}
	if maxConns != 7 || maxQueries != 0 {
		t.Fatalf("resource limits: connections %d, queries %d", maxConns, maxQueries)
	}

	// Migrations ran once.
	var n int
	if err := adm.QueryRow("SELECT COUNT(*) FROM " + quoteIdent(tg.Database) + ".settings").Scan(&n); err != nil || n != 2 {
		t.Fatalf("settings rows %d, %v", n, err)
	}
	if err := adm.QueryRow("SELECT COUNT(*) FROM " + quoteIdent(tg.Database) + "." + migrationsTable).Scan(&n); err != nil || n != 2 {
		t.Fatalf("migration records %d, %v", n, err)
	}

	// The tenant user connects with the derived password, works in its own
	// database and cannot see others.
	info := revealed(t, reg, slug)
	if info.Password != TenantPassword(testSecret, ten.ID) || info.Database != tg.Database {
		t.Fatalf("info %+v", info)
	}
	tdb, err := connectAs(info.DSN)
	if err != nil {
		t.Fatalf("connect as tenant: %v", err)
	}
	if _, err := tdb.Exec("INSERT INTO notes (id, body) VALUES (1, 'hello')"); err != nil {
		t.Fatalf("tenant insert: %v", err)
	}
	if _, err := tdb.Exec("SELECT COUNT(*) FROM mysql.user"); err == nil {
		t.Fatal("tenant user can read mysql.user")
	}
	_ = tdb.Close()

	// Rotating password_secret rotates the password on re-provision.
	p2, reg2 := newIntegrationPlugin(t, map[string]any{"password_secret": "another-secret-0123456789"})
	reg2.HostImpl.AddTenant(ten)
	if err := p2.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if db, err := connectAs(info.DSN); err == nil {
		_ = db.Close()
		t.Fatal("old password still works after rotation")
	}
	tdb, err = connectAs(revealed(t, reg2, ten.ID).DSN)
	if err != nil {
		t.Fatalf("connect with rotated password: %v", err)
	}
	_ = tdb.Close()

	// Delete.
	for i := range 2 {
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatalf("deprovision #%d: %v", i, err)
		}
	}
	if dbExists(t, adm, tg.Database) || userExists(t, adm, tg.User) {
		t.Fatal("database or user left after delete")
	}
}

func TestIntegrationOwnership(t *testing.T) {
	ctx := context.Background()
	adm := admin(t)
	p, reg := newIntegrationPlugin(t, nil)
	slug := "own-" + randHex(t)
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	// Same slug, different tenant (e.g. a slug reused after keep).
	b := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	tg, _ := p.target(a)
	cleanup(t, adm, tg.Database, tg.User)

	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, b); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("provision of clashing tenant: %v", err)
	}
	if err := p.Deprovision(ctx, b); err != nil {
		t.Fatal(err)
	}
	if !dbExists(t, adm, tg.Database) || !userExists(t, adm, tg.User) {
		t.Fatal("another tenant's deprovision removed resources")
	}
	// A's password was not changed by B's attempts.
	if db, err := connectAs(revealed(t, reg, a.ID).DSN); err != nil {
		t.Fatalf("connect as A: %v", err)
	} else {
		_ = db.Close()
	}

	// Unmarked, non-empty database: refused and never dropped.
	c := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "foreign-" + randHex(t)})
	tc, _ := p.target(c)
	cleanup(t, adm, tc.Database, tc.User)
	if _, err := adm.Exec("CREATE DATABASE " + quoteIdent(tc.Database)); err != nil {
		t.Fatal(err)
	}
	if _, err := adm.Exec("CREATE TABLE " + quoteIdent(tc.Database) + ".data (id INT)"); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, c); err == nil || !strings.Contains(err.Error(), "not managed by tenarium") {
		t.Fatalf("provision over unmarked data: %v", err)
	}
	if err := p.Deprovision(ctx, c); err != nil {
		t.Fatal(err)
	}
	if !dbExists(t, adm, tc.Database) {
		t.Fatal("unmarked data dropped")
	}

	// Unmarked, empty database (interrupted Provision): adopted.
	d := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "empty-" + randHex(t)})
	td, _ := p.target(d)
	cleanup(t, adm, td.Database, td.User)
	if _, err := adm.Exec("CREATE DATABASE " + quoteIdent(td.Database)); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, d); err != nil {
		t.Fatalf("adopt empty database: %v", err)
	}

	// Pre-existing, unmarked user: never adopted.
	e := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "user-" + randHex(t)})
	te, _ := p.target(e)
	cleanup(t, adm, te.Database, te.User)
	if _, err := adm.Exec("CREATE USER '" + te.User + "'@'%' IDENTIFIED BY 'theirs-Pw-123'"); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, e); err == nil || !strings.Contains(err.Error(), "not managed by tenarium") {
		t.Fatalf("provision over unmarked user: %v", err)
	}
	if err := p.Deprovision(ctx, e); err != nil {
		t.Fatal(err)
	}
	if !userExists(t, adm, te.User) {
		t.Fatal("unmarked user dropped")
	}
	cfg, _ := mysql.ParseDSN(testDSN(t))
	cfg.User, cfg.Passwd, cfg.DBName = te.User, "theirs-Pw-123", ""
	if db, err := connectAs(cfg.FormatDSN()); err != nil {
		t.Fatalf("unmarked user's password was changed: %v", err)
	} else {
		_ = db.Close()
	}
}

func TestIntegrationRetainAndKeep(t *testing.T) {
	ctx := context.Background()
	adm := admin(t)

	// retain: user dropped, data kept, ownership released.
	p, reg := newIntegrationPlugin(t, map[string]any{"on_deprovision": "retain"})
	slug := "ret-" + randHex(t)
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	tg, _ := p.target(a)
	cleanup(t, adm, tg.Database, tg.User)
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := adm.Exec("CREATE TABLE " + quoteIdent(tg.Database) + ".data (id INT)"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := p.Deprovision(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if !dbExists(t, adm, tg.Database) || userExists(t, adm, tg.User) {
		t.Fatal("retain must keep the database and drop the user")
	}
	var deleted sql.NullString
	if err := adm.QueryRow("SELECT deleted_at FROM " + ownerSQL(tg.Database)).Scan(&deleted); err != nil || !deleted.Valid {
		t.Fatalf("deleted_at %v, %v", deleted, err)
	}
	b := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	if err := p.Provision(ctx, b); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("provision over retained data: %v", err)
	}
	if userExists(t, adm, tg.User) {
		t.Fatal("user created over retained data")
	}

	// keep: nothing is touched.
	pk, regk := newIntegrationPlugin(t, map[string]any{"on_deprovision": "keep"})
	k := regk.HostImpl.AddTenant(sdk.Tenant{Slug: "keep-" + randHex(t)})
	tk, _ := pk.target(k)
	cleanup(t, adm, tk.Database, tk.User)
	if err := pk.Provision(ctx, k); err != nil {
		t.Fatal(err)
	}
	if err := pk.Deprovision(ctx, k); err != nil {
		t.Fatal(err)
	}
	if !dbExists(t, adm, tk.Database) || !userExists(t, adm, tk.User) {
		t.Fatal("keep removed resources")
	}
	// The kept resources stay marked: a new tenant with the same name is
	// refused.
	k2 := regk.HostImpl.AddTenant(sdk.Tenant{Slug: k.Slug})
	if err := pk.Provision(ctx, k2); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("provision over kept data: %v", err)
	}
}

func TestIntegrationNoUser(t *testing.T) {
	ctx := context.Background()
	adm := admin(t)
	p, reg := newIntegrationPlugin(t, map[string]any{"create_user": false, "password_secret": nil, "name_template": "nu_{{.ID}}"})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "nouser"})
	tg, _ := p.target(ten)
	cleanup(t, adm, tg.Database, "")
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if !dbExists(t, adm, tg.Database) {
		t.Fatal("database missing")
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if dbExists(t, adm, tg.Database) {
		t.Fatal("database left")
	}
}
