# PostgreSQL row-level security

With **pooled** (shared-table) multi-tenancy, all tenants' rows live in the same tables, and a
`tenant_id` column says which tenant owns each row. Every query then needs a
`WHERE tenant_id = ...` filter, and one forgotten filter exposes another tenant's data.
PostgreSQL row-level security (RLS) moves that filter into the database. A policy compares
each row's tenant column with a per-transaction setting, so a query sees and writes only the
current tenant's rows whatever its own `WHERE` clause says.

`pkg/rls` provides both halves:

- a **DDL generator** (Go functions and the `tenarium-rls` command) that produces idempotent
  statements to enable RLS and create the policies;
- **runtime helpers** for `github.com/jackc/pgx/v5` that set the tenant for each
  transaction, taking it from `tenantmw` request contexts when there is one.

For tenants that need their own schema or database (the *silo* and *bridge* models), see the
`pgtenant` plugin. RLS is for tables that tenants share.

## Quick start

```sh
# Print the DDL (it never connects to a database), review it, apply it.
tenarium-rls -index -default -bypass-role migrator public.orders billing.invoices:account_id > rls.sql
psql "$DATABASE_URL" -f rls.sql
```

```go
import (
	"github.com/AimTune/tenarium/pkg/rls"
	"github.com/AimTune/tenarium/pkg/tenantmw"
)

// In a handler behind tenantmw.Middleware: the tenant comes from the request.
err := rls.WithRequestTenant(r.Context(), pool, func(tx pgx.Tx) error {
	rows, err := tx.Query(ctx, "SELECT id, total FROM orders") // only this tenant's orders
	...
})

// Anywhere else: name the tenant.
err = rls.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error { ... })
```

## Generated DDL

`rls.Script(tables, opts)` (or `tenarium-rls`) produces, for each table:

```sql
BEGIN;

-- "public"."orders": tenant isolation on "tenant_id"
ALTER TABLE "public"."orders" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."orders" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "tenant_isolation" ON "public"."orders";
CREATE POLICY "tenant_isolation" ON "public"."orders"
    AS PERMISSIVE FOR ALL TO PUBLIC
    USING ("tenant_id" = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK ("tenant_id" = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS "tenant_isolation_bypass" ON "public"."orders";
-- with -bypass-role migrator:
CREATE POLICY "tenant_isolation_bypass" ON "public"."orders"
    AS PERMISSIVE FOR ALL TO "migrator"
    USING (true)
    WITH CHECK (true);
-- with -default:
ALTER TABLE "public"."orders" ALTER COLUMN "tenant_id" SET DEFAULT NULLIF(current_setting('app.tenant_id', true), '')::uuid;
-- with -index:
CREATE INDEX IF NOT EXISTS "orders_tenant_id_idx" ON "public"."orders" ("tenant_id");

COMMIT;
```

The parts of the policy, and why each is there:

- **`USING`** filters the rows that `SELECT`, `UPDATE` and `DELETE` can see. **`WITH CHECK`**
  rejects `INSERT`s and `UPDATE`s that would write a row for another tenant, including moving
  an existing row to another tenant (SQLSTATE `42501`, "new row violates row-level security
  policy").
- **`current_setting(name, true)`**: the second argument returns NULL instead of raising an
  error when the setting was never defined in the session. **`NULLIF(..., '')`**: once a
  transaction-local setting ends, PostgreSQL leaves it as an empty string rather than
  undefined, and `''::uuid` would fail. Either way the result is NULL, `tenant_id = NULL` is
  never true, and **a connection without a tenant sees no rows and cannot write any**. The
  policy fails closed.
- **`FORCE ROW LEVEL SECURITY`**: without it the table owner bypasses the policies, and
  applications often connect as the owner. `-no-force` / `Options.NoForce` turn it off.
- **Bypass policies**: a second permissive policy with `USING (true)` for roles such as
  migrations, support tooling or cross-tenant jobs. Permissive policies are combined with OR.
  This is easier to grant and audit than `ALTER ROLE ... BYPASSRLS`, which needs a superuser.
- **Roles**: the isolation policy applies to `PUBLIC` by default. With `-role app_user`, it
  applies to that role only, and any other role that is not covered by a policy sees nothing.
- **Idempotent**: `ENABLE`/`FORCE` can run again safely, and policies are dropped and
  recreated, so changing options and running the script again updates them. The index uses
  `IF NOT EXISTS` and the function uses `CREATE OR REPLACE`. The whole script runs in one
  transaction, and PostgreSQL DDL is transactional.
- **Names** are always quoted (`"schema"."table"`), so mixed-case names work. Settings must
  look like `prefix.name`, as custom settings do. Types must be plain type names. Control
  characters are refused everywhere. This keeps generated SQL safe to build from command-line
  input.

Options (Go `rls.Options` / CLI flags):

| Option | Flag | Default | |
|---|---|---|---|
| `Column` | `-column`, per table `table:column` | `tenant_id` | |
| `ColumnType` | `-type` | `uuid` | the type the setting is cast to: `text`, `bigint`, ... |
| `Setting` | `-setting` | `app.tenant_id` | |
| `Policy` | `-policy` | `tenant_isolation` | the bypass policy is `<policy>_bypass` |
| `Roles` | `-role` | `PUBLIC` | repeatable or comma separated |
| `BypassRoles` | `-bypass-role` | none | |
| `NoForce` | `-no-force` | false | |
| `Function` | `-function app.current_tenant` | none | creates `CREATE OR REPLACE FUNCTION app.current_tenant() RETURNS uuid LANGUAGE sql STABLE PARALLEL SAFE` and uses it in the policies and the default |
| `Index` | `-index` | false | `<table>_<column>_idx` |
| `SetDefault` | `-default` | false | `INSERT`s may omit the tenant column |
| | `-drop` | | prints `DropScript`: drops the policies, `NO FORCE`, `DISABLE`, drops the default and the function, and keeps the index |

Go: `rls.TableDDL(table, opts)`, `rls.FunctionDDL(opts)`, `rls.Script(tables, opts)`,
`rls.DropDDL`, `rls.DropScript`, and `opts.CurrentTenantExpr()` for writing your own policies,
for example a read-only policy on a shared catalog.

## Setting the tenant at runtime

### Per transaction (recommended)

```go
err := rls.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "UPDATE orders SET status = 'paid' WHERE id = $1", id)
	return err
})
```

`WithTenant` begins a transaction and runs
`SELECT set_config('app.tenant_id', $1, true)` in it. The third argument, `true`, makes the
setting *transaction-local*. It then calls `fn`, committing on nil and rolling back on an
error. Because the setting ends with the transaction:

- the connection goes back to the pool clean, so the next borrower cannot inherit the tenant;
- it works with PgBouncer and other poolers in **transaction mode**, where consecutive
  transactions on one client connection can run on different server connections;
- the tenant ID travels as a bind parameter and is never formatted into SQL.

Details:

- `db` can be a `*pgxpool.Pool`, a `*pgx.Conn` or a `pgx.Tx`. With a `pgx.Tx`, the call
  becomes a savepoint and the new tenant applies until the outer transaction ends.
- An empty tenant ID returns `rls.ErrNoTenant` instead of running with no rows.
- `rls.SetTenant(ctx, tx, tenantID)` sets the tenant inside a transaction you manage yourself.
- `rls.Scope{Setting: "app.org_id", TxOptions: pgx.TxOptions{IsoLevel: pgx.Serializable}}`
  changes the setting name and the transaction options. `Scope` has the same methods as the
  package-level functions.

### From the HTTP request (tenantmw)

`rls.WithRequestTenant(ctx, db, fn)` takes the tenant from the context. It first looks for an
ID stored with `rls.NewContext(ctx, id)`, then for the tenant that
[`tenantmw.Middleware`](middleware.md) stored. `rls.TenantFromContext(ctx)` exposes the same
lookup.

```go
handler := tenantmw.Middleware(resolver, source, tenantmw.Options{})(mux)

mux.HandleFunc("GET /orders", func(w http.ResponseWriter, r *http.Request) {
	err := rls.WithRequestTenant(r.Context(), pool, func(tx pgx.Tx) error { ... })
	if errors.Is(err, rls.ErrNoTenant) { ... }
})
```

Behind [`tenarium-gateway`](gateway.md), the tenant ID arrives in `X-Tenant-Id`. Read it with
`tenantmw.FromHeader("X-Tenant-Id")`, but only if the gateway is the only way to reach the
service.

### Per pool connection (alternative, with pitfalls)

```go
cfg, _ := pgxpool.ParseConfig(dsn)
rls.ConfigurePool(cfg, rls.PoolOptions{RequireTenant: true})
pool, _ := pgxpool.NewWithConfig(ctx, cfg)

rows, err := pool.Query(r.Context(), "SELECT ...") // scoped to the request's tenant
```

`ConfigurePool` installs a `PrepareConn` hook (the successor of `BeforeAcquire`). When a
connection is acquired, the hook runs `set_config(setting, <tenant from ctx>, false)`, a
*session* setting, or sets it to the empty string when the context has no tenant. An
`AfterRelease` hook clears it when the connection is released. Any `PrepareConn` and `AfterRelease` hooks already in the
config run first (pgx ignores a deprecated `BeforeAcquire` once `PrepareConn` is set, so move it). This lets plain `pool.Query` and `pool.Exec` calls work without an explicit
transaction, but it has real drawbacks:

- **Do not use it behind PgBouncer in transaction or statement mode.** The setting stays with
  the server connection, which the pooler gives to other clients between transactions, and
  they inherit the tenant. Use it only with direct connections or session pooling.
- The tenant is fixed when the connection is acquired. A connection kept across tenants, such
  as one from `pool.Acquire` or a long transaction, keeps the first tenant.
- It costs a round trip on every acquire and another on every release.
- Clearing on release is best effort. If it fails, the connection is destroyed rather than
  returned to the pool. A crash between the two hooks is harmless only because every acquire
  sets the setting again, including to empty.
- Every query must carry the request context. A `context.Background()` gets no tenant and no
  rows. Set `RequireTenant` to make such queries fail with `rls.ErrNoTenant` instead.

## Caveats

RLS covers ordinary queries from roles that are subject to it. It does not cover:

- **superusers and `BYPASSRLS` roles**, which always skip RLS. The application must connect as
  a role that has neither. Use bypass policies for privileged roles instead of `BYPASSRLS`.
- **table owners**, unless `FORCE ROW LEVEL SECURITY` is set. The generator sets it by
  default.
- **views**, which run with the view owner's permissions. On PostgreSQL 15+, create them
  `WITH (security_invoker = true)` so the caller's policies apply. **`SECURITY DEFINER`
  functions** likewise run as their owner.
- **`TRUNCATE`**, which does not check policies. Do not grant it to the application role.
- **uniqueness and foreign keys.** Constraint checks look at all rows, so a unique violation
  or a foreign key error can reveal that another tenant's row exists. Make unique keys
  per tenant, for example `UNIQUE (tenant_id, email)`, and include `tenant_id` in composite
  foreign keys.
- **sequences**, which are shared. IDs from a `bigserial` show roughly how busy other tenants
  are. Use UUIDs for public identifiers if that matters.

Performance:

- Index the tenant column (`-index`), or make it the first column of the indexes your queries
  use. The policy adds `tenant_id = <constant>` to every query, and the planner can use an
  index for it.
- `current_setting` is stable within a statement, so the planner evaluates it once rather
  than per row. The optional helper function is a `STABLE` SQL function that PostgreSQL
  inlines.

## Tests

```sh
go test ./pkg/rls/ ./cmd/tenarium-rls/                                   # DDL golden tests
go test ./pkg/rls/ -run Golden -update                                   # regenerate testdata/*.golden.sql
TENARIUM_TEST_POSTGRES_DSN='postgres://postgres:postgres@localhost:55432/postgres?sslmode=disable' \
  go test ./pkg/rls/ -run Postgres                                       # integration
```

The integration tests need a superuser DSN. They create a schema, a table owned by a
non-superuser role, an application role and a bypass role, then apply the generated script
twice. As the application role, they check that:

- with no tenant, no rows are visible;
- tenant A cannot read, update or delete tenant B's rows, cannot insert rows for B and cannot
  move a row to B;
- the setting does not outlive its transaction on a reused connection;
- `FORCE` applies the policy to the table owner, and the bypass role sees every row;
- nested `WithTenant` calls and `WithRequestTenant` with `tenantmw` contexts work, and a
  failing `fn` rolls back;
- the pool hooks scope plain queries, both on one shared connection and under concurrency;
- `DropScript` removes the isolation.

Everything the tests create, roles included, is dropped at the end.
