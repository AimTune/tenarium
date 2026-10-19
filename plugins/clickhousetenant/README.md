# clickhouse-tenant

Gives every tenant its own ClickHouse database, a user with grants on that database and,
optionally, a settings profile and a quota (package `plugins/clickhousetenant`). It talks to the
ClickHouse HTTP interface using only the Go standard library.

```yaml
- plugin: clickhouse-tenant
  config:
    url: http://clickhouse:8123          # required; http(s)://host[:port]
    username: tenarium_admin             # admin account (default "default")
    password: ${CLICKHOUSE_ADMIN_PASSWORD}
    cluster: ""                          # optional: adds ON CLUSTER '<cluster>' to every DDL
    database_engine: ""                  # optional, e.g. Atomic or Replicated('/clickhouse/db/{uuid}', '{shard}', '{replica}')
    name_template: "tenant_{{.Slug}}"    # database name (default)
    user_template: ""                    # user name; default: the database name
    password_secret: ${CH_TENANT_SECRET} # required, >= 16 chars; derives user passwords
    grants:                              # privileges ON <db>.*; default shown below
      [SELECT, INSERT, ALTER TABLE, ALTER VIEW, CREATE TABLE, CREATE VIEW, CREATE DICTIONARY,
       DROP TABLE, DROP VIEW, DROP DICTIONARY, TRUNCATE, OPTIMIZE, SHOW, dictGet]
    settings_profile:                    # optional per-tenant SETTINGS PROFILE
      settings: {max_execution_time: 60, max_threads: 4}
      from_limits: {max_memory_usage: clickhouse_memory_bytes}  # setting -> entitlement limit
      lock: true                         # READONLY settings the tenant cannot change (default true)
    quota:                               # optional per-tenant QUOTA
      interval: "1 hour"                 # <n> second|minute|hour|day|week|month|quarter|year
      limits: {queries: 100000}
      from_limits: {read_bytes: clickhouse_read_bytes, execution_time: clickhouse_cpu_seconds}
    on_deprovision: delete               # delete (default) | keep | retain
    timeout_seconds: 30                  # per HTTP request (default 30)
```

## Names

`name_template` and `user_template` are text/templates over the tenant (`{{.ID}}`, `{{.Slug}}`,
...), rendered with `missingkey=error`. The result is lowercased and every character outside
`[a-z0-9_]` becomes `_`. A leading digit gets a `_` prefix. Names longer than 63 characters are
cut and suffixed with a hash of the tenant ID, so truncation cannot make two tenants share a
name. At startup each template is rendered for two sample tenants. A template that gives both
the same name, or that renders a reserved name (`system`, `default`, `information_schema`), is
rejected. Use only immutable fields (ID, Slug), because names are computed again on
deprovision. The settings profile and the quota take the user's name.

## Credentials

Nothing is stored. A tenant's password is the first 32 hex characters of
`HMAC-SHA256(password_secret, tenant ID)`. Applications that hold the secret compute it the same
way; in Go they can call `clickhousetenant.TenantPassword(secret, tenantID)`. The user is created
with `IDENTIFIED WITH sha256_password` and `DEFAULT DATABASE <db>`. Every Provision applies the
password again with `ALTER USER`, so changing `password_secret` and re-provisioning rotates the
passwords. Grants are applied with `GRANT ... ON <db>.* TO <user> WITH REPLACE OPTION`, so
removing a privilege from `grants` takes effect on the next Provision.

The default grants leave out `ALTER DATABASE`, `DROP DATABASE` and `ALL`. Those privileges would
let a tenant rewrite or drop its database's ownership comment. You can configure them, but the
plugin then cannot guarantee the ownership checks below. Grant names must be words made of
letters, for example `CREATE TABLE`.

## Ownership

- **Database**: it is created with `COMMENT 'tenarium:tenant=<id>'` in the same `CREATE
  DATABASE` statement, so an interrupted Provision never leaves an unmarked database. A database
  marked for another tenant, or carrying any comment Tenarium did not write, is never adopted or
  dropped. An unmarked database is adopted (its comment is set with `ALTER DATABASE ... MODIFY
  COMMENT`) only if `system.tables` lists no tables in it.
- **User, settings profile, quota**: not every ClickHouse version supports comments on these
  objects. The user counts as the tenant's when the tenant's database is theirs and the user's
  `default_database` (in `system.users`) is that database. A user with the same name and another
  default database is never modified or dropped, and Provision fails. A settings profile or
  quota counts as the tenant's when it applies to that user only (`apply_to_list`).

## Deprovisioning

| `on_deprovision` | Effect |
| --- | --- |
| `delete` (default) | Drops the quota, the settings profile and the user, then runs `DROP DATABASE ... SYNC`. The database goes last, so a retry after an interruption is safe. |
| `keep` | Touches nothing. The database keeps its marker, so a new tenant with the same slug cannot adopt it. |
| `retain` | Drops the quota, profile and user. The data stays, and the database comment becomes `tenarium:deleted-tenant=<id> deleted-at=<RFC3339>`. Provisioning any tenant whose name collides with a retained database fails until an operator removes or renames it. |

`delete` is the default for consistency with `postgres-tenant` and `s3-tenant`. Tenarium's
deletion grace period runs before Deprovision. If tenant data must outlive the tenant, use
`retain`.

## Quotas and settings from entitlements

`settings_profile.from_limits` and `quota.from_limits` map a ClickHouse setting or quota key to
an entitlement limit name. The tenant's effective limit, from `sdk.Host.Entitlements`, overrides
the fixed `settings` or `limits` value. If the tenant has no value for that limit (unlimited),
the fixed value applies, or nothing is set. When a quota ends up with no limits at all, it is
created as `TRACKING ONLY`, so usage still appears in `system.quotas_usage`. The available quota
keys are `queries`, `query_selects`, `query_inserts`, `errors`, `result_rows`, `result_bytes`,
`read_rows`, `read_bytes`, `execution_time` (seconds), `written_bytes` and
`failed_sequential_authentications`. With `lock: true`, settings are marked `READONLY`, so the
tenant cannot override them with `SET` or a `SETTINGS` clause. Every Provision recreates the
profile and the quota (`OR REPLACE`), so re-provisioning picks up plan changes. If you later
remove `settings_profile` or `quota` from the config, existing objects are not dropped until the
tenant is deprovisioned.

## Route and health

`GET /v1/plugins/{instance}/tenants/{tenant}` (ID or slug) returns
`{"database", "user", "url", "cluster", "settings_profile", "quota"}` and never the password.
Callers who may not read the tenant (`tenants:read`) get 404, like an unknown tenant.

`Health` (used by `/readyz`) runs `SELECT 1` with the admin credentials.

## Required privileges

The admin account needs access management (`access_management=1` for users defined in
`users.xml`, or `CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1` for the Docker image). It also needs:

- `CREATE DATABASE`, `DROP DATABASE` and `ALTER DATABASE` (for comments) on the tenant databases
  (`*.*`);
- `CREATE USER`, `ALTER USER`, `DROP USER`, `CREATE SETTINGS PROFILE`, `DROP SETTINGS PROFILE`,
  `CREATE QUOTA` and `DROP QUOTA` (or `ACCESS MANAGEMENT`);
- every privilege in `grants`, `WITH GRANT OPTION`;
- `SELECT` on `system.databases`, `system.tables`, `system.users`, `system.settings_profiles`
  and `system.quotas`;
- with `cluster`: `CLUSTER` (for `ON CLUSTER`).

## Compatibility

The integration tests were run against `clickhouse/clickhouse-server:latest` (26.9) and `23.8`.
On 23.8, which has no `ALTER DATABASE ... MODIFY COMMENT`, provisioning, `delete` and `keep` work.
Adopting an existing unmarked database and `on_deprovision: retain` fail there with a clear
error.

## Tests

Unit tests use an in-memory fake of the HTTP interface. The integration tests run when
`TENARIUM_TEST_CLICKHOUSE_URL` is set:

```sh
docker run -d --name ch -p 8123:8123 -e CLICKHOUSE_USER=admin -e CLICKHOUSE_PASSWORD=pw \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 clickhouse/clickhouse-server
TENARIUM_TEST_CLICKHOUSE_URL=http://localhost:8123 TENARIUM_TEST_CLICKHOUSE_USER=admin \
  TENARIUM_TEST_CLICKHOUSE_PASSWORD=pw go test ./plugins/clickhousetenant/
```
