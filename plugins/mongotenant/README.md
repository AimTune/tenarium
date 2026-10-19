# mongodb-tenant

Provisions a MongoDB **database and database user per tenant**.

```yaml
- plugin: mongodb-tenant
  config:
    uri: mongodb://tenarium:${MONGO_ADMIN_PASSWORD}@mongo-0:27017,mongo-1:27017/?replicaSet=rs0&authSource=admin
    password_secret: ${MONGO_TENANT_SECRET}  # required, >= 16 characters
    name_template: "tenant_{{.Slug}}"        # database name (default)
    user_template: "app_{{.Slug}}"           # default: the database name
    auth_database: ""                        # "" = the tenant database (default) | "admin" | another shared db
    roles: [readWrite]                       # granted on the tenant database (default [readWrite])
    quota_from_limit: storage_gb             # optional, recorded only (see below)
    on_deprovision: delete                   # delete (default) | keep | retain
```

## Names

`name_template` and `user_template` are Go `text/template`s over the tenant (`{{.ID}}`,
`{{.Slug}}`, ...; unknown fields are an error). Use immutable fields only: names are recomputed
when the tenant is deprovisioned. Rendered names are lowercased (MongoDB treats database names
that differ only in case as the same), every character outside `[a-z0-9_-]` becomes `_`, and
names longer than 63 bytes are shortened and suffixed with a hash of the tenant ID, so two
tenants never collide through truncation. A template that renders the same name for two sample
tenants, or that renders `admin`, `local`, `config` or the configured `auth_database`, is
rejected at startup.

## Users and passwords

The user is created with `createUser` in `auth_database` (by default the tenant database itself,
so clients use `authSource=<tenant db>`) and granted `roles` on the tenant database only, e.g.
`[readWrite, dbAdmin]`. Its password is never stored: it is derived as

```
hex(HMAC-SHA256(password_secret, tenant_id))[:32]
```

(`mongotenant.TenantPassword`), so applications that know the secret compute it themselves.
Every Provision runs `updateUser` with the password, roles and customData, so re-provisioning
after changing `password_secret` or `roles` rotates them.

## Ownership

- The database holds a collection `_tenarium` with `{_id: "owner", tenant_id, tenant_slug,
  created_at}`. MongoDB creates databases lazily, so writing this marker is what creates it.
- The user carries `customData: {tenarium_tenant_id: <id>}`.

A database or user marked for another tenant is never adopted, updated or dropped (Provision
fails with a clear error; Deprovision logs a warning and leaves it alone). An unmarked database
is adopted only if it has no collections other than `_tenarium` (what an interrupted Provision
leaves); an unmarked user is never adopted.

## Deprovisioning

The user is always handled first (only if its customData names the tenant), so access ends
before data is touched.

- `delete` (default): `dropUser`, then `dropDatabase`. Tenant deletion already has a grace
  period in the core, which is why delete is the default here as for `s3-tenant`; choose
  `retain` or `keep` if databases must survive tenant deletion.
- `keep`: nothing is touched; the markers remain, so a new tenant with the same slug cannot
  adopt the data.
- `retain`: the user is dropped and the data stays, but ownership is released: the owner marker
  is replaced by `{_id: "retained", deleted_at, deleted_tenant_id}`. Provisioning a tenant whose
  name collides with retained data fails until an operator drops or renames the database.

Missing databases and users count as already deprovisioned; both operations are idempotent.

## Quota

MongoDB has no storage quotas. With `quota_from_limit`, the tenant's entitlement limit of that
name is recorded in the owner marker as `quota_metric` / `quota_limit` (removed for unlimited
tenants) for downstream tooling (a usage scanner, `dbStats`-based alerts) to enforce. The plugin
itself does not enforce it.

## Route

`GET /v1/plugins/{instance}/tenants/{tenant}` (tenant ID or slug) answers 404 for unknown
tenants and for callers not allowed `tenants:read` on the tenant:

```json
{
  "database": "tenant_acme",
  "user": "tenant_acme",
  "auth_database": "tenant_acme",
  "roles": [{"role": "readWrite", "db": "tenant_acme"}],
  "uri": "mongodb://tenant_acme@mongo-0:27017,mongo-1:27017/tenant_acme?authSource=tenant_acme&replicaSet=rs0"
}
```

The URI is derived from the admin `uri`: admin credentials and `authSource`/`authMechanism*`
options are removed, other options (TLS, replica set, ...) are kept. The password is included
(`"password": "..."`) only with `?include_password=true` and only for callers also allowed
`tenants:update` on the tenant (403 otherwise). Responses are sent with `Cache-Control: no-store`.

## Health

`/readyz` pings the primary.

## Required permissions

The admin user in `uri` needs, on every tenant database:

- `userAdmin` (createUser, updateUser, dropUser, usersInfo) — when
  `auth_database` is shared, `userAdmin` on that database plus the right to grant the configured
  roles on tenant databases;
- `readWrite` (the `_tenarium` marker collection, listCollections);
- `dropDatabase` (`dbAdmin`) for `on_deprovision: delete`.

In practice that is `userAdminAnyDatabase` + `readWriteAnyDatabase` + `dbAdminAnyDatabase` on
the `admin` database (or `root`). Granting a role to a user requires the `grantRole` privilege on
that role's database, which `userAdminAnyDatabase` includes.

## Tests

Unit tests run against an in-memory fake. Integration tests run against a real server with
authentication enabled:

```sh
docker run -d --name mongo -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=root -e MONGO_INITDB_ROOT_PASSWORD=pw mongo:7
TENARIUM_TEST_MONGODB_URI='mongodb://root:pw@127.0.0.1:27017/?authSource=admin' \
  go test ./plugins/mongotenant/
```

They check that the tenant user can log in and write to its own database (and not to another),
password rotation, ownership protection, retain and delete.
