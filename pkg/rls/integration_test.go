package rls_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/rls"
	"github.com/AimTune/tenarium/pkg/tenantmw"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	tenantA = "aaaaaaaa-0000-0000-0000-00000000000a"
	tenantB = "bbbbbbbb-0000-0000-0000-00000000000b"
)

type pgEnv struct {
	admin              *pgxpool.Pool
	dsn                string
	schema             string
	app, owner, bypass string // roles
}

// setupPostgres creates a schema with a documents table protected by
// rls.Script, owned by a non-superuser owner role, and an application role
// and a bypass role, all dropped at the end of the test.
func setupPostgres(t *testing.T) *pgEnv {
	t.Helper()
	dsn := os.Getenv("TENARIUM_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TENARIUM_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1e12)
	e := &pgEnv{admin: admin, dsn: dsn, schema: "rls_test_" + suffix,
		app: "rls_app_" + suffix, owner: "rls_owner_" + suffix, bypass: "rls_bypass_" + suffix}

	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	t.Cleanup(func() {
		for _, sql := range []string{
			"DROP SCHEMA IF EXISTS " + e.schema + " CASCADE",
			"DROP OWNED BY " + e.app + ", " + e.owner + ", " + e.bypass,
			"DROP ROLE IF EXISTS " + e.app, "DROP ROLE IF EXISTS " + e.owner, "DROP ROLE IF EXISTS " + e.bypass,
		} {
			if _, err := admin.Exec(context.Background(), sql); err != nil {
				t.Logf("cleanup %s: %v", sql, err)
			}
		}
	})
	for _, r := range []string{e.app, e.owner, e.bypass} {
		exec("CREATE ROLE " + r + " LOGIN PASSWORD 'rls-test-pw' NOSUPERUSER NOBYPASSRLS")
	}
	exec("CREATE SCHEMA " + e.schema + " AUTHORIZATION " + e.owner)
	exec("GRANT USAGE ON SCHEMA " + e.schema + " TO " + e.app + ", " + e.bypass)
	exec(`CREATE TABLE ` + e.schema + `.documents (
		id bigserial PRIMARY KEY,
		tenant_id uuid NOT NULL,
		body text NOT NULL
	)`)
	exec("ALTER TABLE " + e.schema + ".documents OWNER TO " + e.owner)
	exec("GRANT SELECT, INSERT, UPDATE, DELETE ON " + e.schema + ".documents TO " + e.app + ", " + e.bypass)
	exec("GRANT USAGE ON ALL SEQUENCES IN SCHEMA " + e.schema + " TO " + e.app + ", " + e.bypass)
	exec(fmt.Sprintf(`INSERT INTO %s.documents (tenant_id, body) VALUES
		('%s', 'a1'), ('%s', 'a2'), ('%s', 'b1')`, e.schema, tenantA, tenantA, tenantB))

	opts := rls.Options{Function: e.schema + ".current_tenant", BypassRoles: []string{e.bypass}, Index: true, SetDefault: true}
	ddl, err := rls.Script([]rls.Table{{Name: e.schema + ".documents"}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	// Applied twice: the script is idempotent.
	for range 2 {
		exec(ddl)
	}
	return e
}

// pool connects as role (a non-superuser: superusers always bypass RLS).
func (e *pgEnv) pool(t *testing.T, role string, maxConns int32, configure func(*pgxpool.Config)) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(e.dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User, cfg.ConnConfig.Password = role, "rls-test-pw"
	cfg.MaxConns = maxConns
	if configure != nil {
		configure(cfg)
	}
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func bodies(t *testing.T, ctx context.Context, q querier, table string) []string {
	t.Helper()
	rows, err := q.Query(ctx, "SELECT body FROM "+table+" ORDER BY body")
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func isRLSViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501" // insufficient_privilege: new row violates row-level security policy
}

func TestPostgresIsolation(t *testing.T) {
	e := setupPostgres(t)
	ctx := context.Background()
	table := e.schema + ".documents"
	// One connection: every statement reuses the same session, so leaks
	// between transactions would show.
	app := e.pool(t, e.app, 1, nil)

	// No tenant: nothing is visible (fail closed), and the helper refuses.
	if got := bodies(t, ctx, app, table); len(got) != 0 {
		t.Fatalf("without tenant: %v", got)
	}
	if err := rls.WithTenant(ctx, app, "", func(pgx.Tx) error { return nil }); !errors.Is(err, rls.ErrNoTenant) {
		t.Fatalf("empty tenant: %v", err)
	}

	err := rls.WithTenant(ctx, app, tenantA, func(tx pgx.Tx) error {
		// Reads: only A's rows, even when asking for B's explicitly.
		if got := bodies(t, ctx, tx, table); fmt.Sprint(got) != "[a1 a2]" {
			t.Errorf("A reads %v", got)
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id = $1", tenantB).Scan(&n); err != nil || n != 0 {
			t.Errorf("A counting B: %d %v", n, err)
		}
		// The helper function sees the transaction's tenant.
		var cur string
		if err := tx.QueryRow(ctx, "SELECT "+e.schema+".current_tenant()::text").Scan(&cur); err != nil || cur != tenantA {
			t.Errorf("current_tenant() = %q %v", cur, err)
		}
		// Writes to B's rows affect nothing.
		tag, err := tx.Exec(ctx, "UPDATE "+table+" SET body = 'hacked' WHERE tenant_id = $1", tenantB)
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("A updating B: %v %v", tag, err)
		}
		tag, err = tx.Exec(ctx, "DELETE FROM "+table+" WHERE body = 'b1'")
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("A deleting B: %v %v", tag, err)
		}
		// The column default fills in the current tenant.
		var tid string
		if err := tx.QueryRow(ctx, "INSERT INTO "+table+" (body) VALUES ('a3') RETURNING tenant_id::text").Scan(&tid); err != nil || tid != tenantA {
			t.Errorf("default tenant %q %v", tid, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// WITH CHECK: A can neither insert B's rows nor move a row to B.
	err = rls.WithTenant(ctx, app, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO "+table+" (tenant_id, body) VALUES ($1, 'planted')", tenantB)
		return err
	})
	if !isRLSViolation(err) {
		t.Fatalf("A inserting a B row: %v", err)
	}
	err = rls.WithTenant(ctx, app, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE "+table+" SET tenant_id = $1 WHERE body = 'a1'", tenantB)
		return err
	})
	if !isRLSViolation(err) {
		t.Fatalf("A moving a row to B: %v", err)
	}

	// The setting is transaction-local: the same session has no tenant now.
	if got := bodies(t, ctx, app, table); len(got) != 0 {
		t.Fatalf("tenant leaked after commit: %v", got)
	}

	// B sees its row untouched.
	err = rls.WithTenant(ctx, app, tenantB, func(tx pgx.Tx) error {
		if got := bodies(t, ctx, tx, table); fmt.Sprint(got) != "[b1]" {
			t.Errorf("B reads %v", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The superuser view confirms nothing crossed over.
	var total, bRows int
	if err := e.admin.QueryRow(ctx, "SELECT count(*), count(*) FILTER (WHERE tenant_id = $1 AND body = 'b1') FROM "+table, tenantB).Scan(&total, &bRows); err != nil {
		t.Fatal(err)
	}
	if total != 4 || bRows != 1 {
		t.Fatalf("admin view: total %d, b1 %d", total, bRows)
	}
}

func TestPostgresOwnerAndBypass(t *testing.T) {
	e := setupPostgres(t)
	ctx := context.Background()
	table := e.schema + ".documents"

	// FORCE ROW LEVEL SECURITY applies the policy to the table owner too.
	owner := e.pool(t, e.owner, 1, nil)
	if got := bodies(t, ctx, owner, table); len(got) != 0 {
		t.Fatalf("owner without tenant: %v", got)
	}
	if err := rls.WithTenant(ctx, owner, tenantB, func(tx pgx.Tx) error {
		if got := bodies(t, ctx, tx, table); fmt.Sprint(got) != "[b1]" {
			t.Errorf("owner as B: %v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The bypass role sees every tenant.
	bypass := e.pool(t, e.bypass, 1, nil)
	if got := bodies(t, ctx, bypass, table); fmt.Sprint(got) != "[a1 a2 b1]" {
		t.Fatalf("bypass role: %v", got)
	}

	// DropScript removes isolation (and the helper function) again.
	drop, err := rls.DropScript([]rls.Table{{Name: table}}, rls.Options{Function: e.schema + ".current_tenant", SetDefault: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, drop); err != nil {
		t.Fatalf("drop script: %v", err)
	}
	if got := bodies(t, ctx, owner, table); fmt.Sprint(got) != "[a1 a2 b1]" {
		t.Fatalf("after drop: %v", got)
	}
}

func TestPostgresRequestTenantAndNesting(t *testing.T) {
	e := setupPostgres(t)
	table := e.schema + ".documents"
	app := e.pool(t, e.app, 2, nil)

	// The tenant tenantmw stored in the request context.
	ctx := tenantmw.NewContext(context.Background(), &tenantmw.Tenant{ID: tenantB, Slug: "b"})
	if err := rls.WithRequestTenant(ctx, app, func(tx pgx.Tx) error {
		if got := bodies(t, ctx, tx, table); fmt.Sprint(got) != "[b1]" {
			t.Errorf("request tenant B: %v", got)
		}
		// A nested WithTenant (savepoint) switches tenant until the outer
		// transaction ends.
		return rls.WithTenant(ctx, tx, tenantA, func(inner pgx.Tx) error {
			if got := bodies(t, ctx, inner, table); fmt.Sprint(got) != "[a1 a2]" {
				t.Errorf("nested A: %v", got)
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	// rls.NewContext wins over tenantmw.
	if err := rls.WithRequestTenant(rls.NewContext(ctx, tenantA), app, func(tx pgx.Tx) error {
		if got := bodies(t, ctx, tx, table); fmt.Sprint(got) != "[a1 a2]" {
			t.Errorf("rls context A: %v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := rls.WithRequestTenant(context.Background(), app, func(pgx.Tx) error { return nil }); !errors.Is(err, rls.ErrNoTenant) {
		t.Fatalf("no request tenant: %v", err)
	}
	// A failing fn rolls back.
	boom := errors.New("boom")
	err := rls.WithTenant(ctx, app, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	_ = rls.WithTenant(ctx, app, tenantA, func(tx pgx.Tx) error {
		if got := bodies(t, ctx, tx, table); fmt.Sprint(got) != "[a1 a2]" {
			t.Errorf("after rollback: %v", got)
		}
		return nil
	})
}

func TestPostgresPoolHooks(t *testing.T) {
	e := setupPostgres(t)
	table := e.schema + ".documents"
	// One connection shared by every tenant: each acquisition must replace
	// the previous tenant.
	pool := e.pool(t, e.app, 1, func(cfg *pgxpool.Config) { rls.ConfigurePool(cfg, rls.PoolOptions{}) })

	ctxA := rls.NewContext(context.Background(), tenantA)
	ctxB := tenantmw.NewContext(context.Background(), &tenantmw.Tenant{ID: tenantB})
	for range 3 {
		if got := bodies(t, ctxA, pool, table); fmt.Sprint(got) != "[a1 a2]" {
			t.Fatalf("pool A: %v", got)
		}
		if got := bodies(t, ctxB, pool, table); fmt.Sprint(got) != "[b1]" {
			t.Fatalf("pool B: %v", got)
		}
		if got := bodies(t, context.Background(), pool, table); len(got) != 0 {
			t.Fatalf("pool without tenant: %v", got)
		}
	}
	// Writes are checked as well.
	if _, err := pool.Exec(ctxA, "INSERT INTO "+table+" (tenant_id, body) VALUES ($1, 'x')", tenantB); !isRLSViolation(err) {
		t.Fatalf("pool A inserting B: %v", err)
	}

	// Concurrent tenants on a small pool never see each other's rows.
	pool2 := e.pool(t, e.app, 2, func(cfg *pgxpool.Config) { rls.ConfigurePool(cfg, rls.PoolOptions{}) })
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, want := ctxA, "[a1 a2]"
			if i%2 == 1 {
				ctx, want = ctxB, "[b1]"
			}
			rows, err := pool2.Query(ctx, "SELECT body FROM "+table+" ORDER BY body")
			if err != nil {
				t.Error(err)
				return
			}
			got, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil || fmt.Sprint(got) != want {
				t.Errorf("concurrent: %v %v, want %s", got, err, want)
			}
		}()
	}
	wg.Wait()

	// RequireTenant fails acquisitions without a tenant.
	strict := e.pool(t, e.app, 1, func(cfg *pgxpool.Config) {
		rls.ConfigurePool(cfg, rls.PoolOptions{RequireTenant: true})
	})
	if _, err := strict.Exec(context.Background(), "SELECT 1"); !errors.Is(err, rls.ErrNoTenant) {
		t.Fatalf("strict pool without tenant: %v", err)
	}
	if got := bodies(t, ctxB, strict, table); fmt.Sprint(got) != "[b1]" {
		t.Fatalf("strict pool B: %v", got)
	}
}
