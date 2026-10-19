# mysql-tenant

Provisions a database and a login user per tenant on MySQL 8 or MariaDB (package
`plugins/mysqltenant`, plugin ID `mysql-tenant`). It manages the SaaS application's data plane,
not Tenarium's own database.

```yaml
- plugin: mysql-tenant
  config:
    dsn: "root:${MYSQL_ADMIN_PASSWORD}@tcp(app-db:3306)/"  # admin connection (go-sql-driver/mysql DSN)
    name_template: "tenant_{{.Slug}}"   # database name (default); sanitized, max 64 chars
    create_user: true                   # default; false = database only
    user_template: "u_{{.Slug}}"        # default: the database name; max 32 chars
    user_host: "%"                      # host part of the account (default "%")
    password_secret: ${MYSQL_TENANT_SECRET}  # required with create_user, >= 16 chars
    privileges: [ALL PRIVILEGES]        # granted ON `<db>`.* (default ALL PRIVILEGES)
    charset: utf8mb4                    # default
    collation: utf8mb4_0900_ai_ci       # default: the server's default for the charset
    limits:                             # optional: user resource limits from entitlements
      max_user_connections: db_connections
      max_queries_per_hour: db_queries_per_hour
      # also: max_updates_per_hour, max_connections_per_hour
    migrations_dir: /migrations         # *.sql, applied in order, tracked per tenant
    on_deprovision: delete              # delete (default) | retain | keep
    connect_address: mysql.internal:3306  # address reported by the route (default: dsn's)
```

## Names

`name_template` and `user_template` are Go templates over the tenant (`{{.ID}}`, `{{.Slug}}`,
...), rendered with `missingkey=error`. The result is lowercased and every character outside
`[a-z0-9_]` becomes `_` (so `acme-corp` gives `tenant_acme_corp`). Names longer than MySQL's
limits (64 characters for databases, 32 for user names) are cut and suffixed with `_` and 8 hex
characters of a hash of the tenant ID, so two tenants never collide through truncation.
Templates are checked at startup: one that renders the same name for two sample tenants, an
empty name, a system name (`mysql`, `sys`, `root`, ...) is rejected, and a user name equal to
the admin user of `dsn` is refused. Use only immutable fields (ID, slug): names are recomputed
on deprovision.

## Credentials

Nothing is stored. A tenant user's password is `hex(HMAC-SHA256(password_secret, tenant_id))[:32]`;
applications that know the secret derive it with `mysqltenant.TenantPassword(secret, tenantID)`
(or the same formula in any language). Every Provision resets the password with `ALTER USER ...
IDENTIFIED BY`, so rotating `password_secret` and re-provisioning tenants rotates all passwords.
If the server runs the `validate_password` component with a policy requiring mixed case or
special characters, the hex passwords are rejected; use the LOW policy or exempt the admin.

Privileges and resource limits are (re)applied on every Provision. Privileges removed from
`privileges` are not revoked from existing users.

## Ownership

- Databases: every database the plugin creates holds a one-row table `_tenarium_owner`
  (`tenant_id`, `db_user`, `created_at`, `deleted_at`). MySQL has no portable database comments,
  so the marker lives inside the database.
- Users: on MySQL 8.0.21+ the user is created with
  `ATTRIBUTE '{"tenarium_tenant_id": "<id>"}'` (read from `INFORMATION_SCHEMA.USER_ATTRIBUTES`),
  atomically with the user. On servers without user attributes (MariaDB, older MySQL) the account
  (`user@host`) is recorded in the database's marker row before the user is created. Support is
  detected automatically.

Provision never adopts a database or user that belongs to another tenant, and Deprovision never
touches one; a name clash (for example a slug reused after `on_deprovision: keep`) makes
Provision fail with a clear reason. An unmarked database is adopted only when it has no tables
(what an interrupted Provision leaves behind); an unmarked user is never adopted, so an existing
application account whose name collides keeps its password.

The tenant user holds the privileges you grant on its database, which with `ALL PRIVILEGES`
includes the marker table. A tenant that tampers with its marker can only prevent the cleanup of
its own database (it is then left in place with a warning); it cannot reach other tenants'
resources. On MariaDB, where the user is recorded in that marker, grant a narrower privilege
list if tenant code is untrusted.

## Deprovisioning

`on_deprovision`:

- `delete` (default, like `postgres-tenant`): drops the user (and terminates its open sessions,
  best effort) and the database. Tenarium's deletion grace period is the safety net; choose
  `retain` if deleted tenants' data must survive.
- `retain`: drops the user so nobody can log in, keeps the database and stamps its marker with
  `deleted_at`, releasing ownership. Provisioning a new tenant whose database name collides with
  retained data fails until an operator drops or renames that database.
- `keep`: touches nothing; the markers stay, so the data is still protected from adoption.

## Quota

With `limits`, each listed user resource option gets the tenant's entitlement limit of the given
name (plan limits with tenant overrides). An absent or negative limit means unlimited (`0`).
Limits are applied at Provision; re-provision a tenant after changing its plan to update them.

## Migrations

`migrations_dir` holds `*.sql` files applied in filename order on every Provision, as the admin
user on a connection whose default database is the tenant's (so plain `CREATE TABLE notes` lands
in it). Files may contain several statements and are Go templates with `{{.Database}}`
(backtick-quoted), `{{.Name}}`, `{{.User}}`, `{{.Account}}` (`'user'@'host'`), `{{.TenantID}}`
and `{{.Slug}}` (the last two raw, not escaped). Applied files are recorded in
`_tenarium_migrations` inside the tenant database, so new files are applied to existing tenants
on their next Provision. Concurrent runs for the same tenant are serialized with `GET_LOCK`.

MySQL DDL is not transactional: if a file fails halfway, its earlier statements stay applied and
the whole file runs again on the next Provision. Write migrations idempotently
(`CREATE TABLE IF NOT EXISTS`, ...).

## Route

`GET /v1/plugins/{instance}/tenants/{tenant}` (tenant ID or slug) requires `tenants:read` on the
tenant and answers 404 for unknown tenants and for callers who may not read it:

```json
{"database": "tenant_acme", "user": "tenant_acme", "user_host": "%",
 "host": "app-db", "port": 3306, "dsn": "tenant_acme@tcp(app-db:3306)/tenant_acme"}
```

With `?reveal=true` the response also contains `password` and a `dsn` including it. This requires
`tenants:update` on the tenant (403 otherwise) and is sent with `Cache-Control: no-store`.

## Health

`/readyz` pings the server through the admin connection.

## Required privileges

The admin user of `dsn` needs:

- `CREATE`, `DROP` (databases), and `SELECT`, `INSERT`, `UPDATE`, `CREATE` on tenant databases
  for the marker and migrations (plus whatever your migrations do), e.g. global privileges;
- `CREATE USER` and the privileges it grants, `WITH GRANT OPTION`;
- `SELECT` on `mysql.user` (account lookup);
- optional: `PROCESS` and `CONNECTION_ADMIN` (MySQL) / `CONNECTION ADMIN` (MariaDB) to terminate
  a dropped user's sessions.

A dedicated account could be created like this (MySQL 8):

```sql
CREATE USER 'tenarium'@'%' IDENTIFIED BY '...';
GRANT ALL PRIVILEGES ON *.* TO 'tenarium'@'%' WITH GRANT OPTION;
```

or, narrower, `GRANT CREATE, DROP, SELECT, INSERT, UPDATE, DELETE, ALTER, INDEX, REFERENCES,
CREATE TEMPORARY TABLES, LOCK TABLES, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE,
EXECUTE, EVENT, TRIGGER, CREATE USER, PROCESS, CONNECTION_ADMIN ON *.* TO 'tenarium'@'%' WITH
GRANT OPTION` (it can only grant what it holds).

## Tests

Unit tests need no server. Integration tests run against `TENARIUM_TEST_MYSQL_DSN`:

```sh
docker run -d --name tenarium-test-mysql -e MYSQL_ROOT_PASSWORD=pw -p 47306:3306 mysql:8
TENARIUM_TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:47306)/' go test ./plugins/mysqltenant/
```

They pass against MySQL 8 (user attributes) and MariaDB 11 (marker-recorded users).
