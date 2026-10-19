# rabbitmq-tenant

Provisions per-tenant isolation on RabbitMQ: one **virtual host**, one
**user** and the user's **permissions** on that vhost per tenant, plus
optional vhost limits taken from the tenant's entitlements. Everything goes
through the RabbitMQ Management HTTP API (plain `net/http`, no AMQP
connection). Requires RabbitMQ 3.11 or later (vhost tags/metadata are used as
ownership markers; tested against 3.13).

## Configuration

```yaml
plugins:
  - plugin: rabbitmq-tenant
    config:
      url: http://rabbitmq:15672          # Management API base URL
      username: tenarium-admin
      password: ${RABBITMQ_ADMIN_PASSWORD}
      timeout: 10s
      # tls_insecure_skip_verify: false
      vhost_template: "tenant-{{.Slug}}"
      username_template: "tenant-{{.Slug}}"
      password_secret: ${RABBITMQ_TENANT_SECRET}   # HMAC key, >= 16 chars
      permissions:                        # regexes on the tenant vhost
        configure: ".*"
        write: ".*"
        read: ".*"
      user_tags: [management]             # optional
      default_queue_type: quorum          # optional: classic | quorum | stream
      limits:                             # vhost limit -> entitlement limit
        max-connections: amqp_connections
        max-queues: amqp_queues
      amqp_url: amqps://rabbit.example.com:5671   # returned to tenants
      on_deprovision: delete              # delete | keep | retain
```

| Field | Default | Description |
|---|---|---|
| `url` | required | Management API base URL (`http(s)://host:port[/prefix]`), no credentials. |
| `username`, `password` | required | Admin user. Needs the `administrator` tag (it manages vhosts and users). |
| `timeout` | `10s` | Per-request timeout. |
| `tls_insecure_skip_verify` | `false` | Skip TLS verification of the Management API (testing only). |
| `vhost_template` | `tenant-{{.Slug}}` | text/template over the tenant giving the vhost name. |
| `username_template` | `tenant-{{.Slug}}` | text/template giving the tenant user name. |
| `password_secret` | required | HMAC key for tenant passwords (min. 16 characters). |
| `permissions.configure/write/read` | `.*` each | Permission regexes on the tenant vhost. `""` grants nothing. |
| `user_tags` | none | Extra user tags (e.g. `management`, `policymaker`). `administrator` and `monitoring` are rejected because they see every vhost; `tenarium-*` is reserved. |
| `default_queue_type` | unset | Default queue type of the vhost. |
| `limits` | none | Map of `max-connections` / `max-queues` to a Tenarium limit name. |
| `amqp_url` | unset | Broker URL without path/credentials; the vhost is appended in route responses. |
| `on_deprovision` | `delete` | See below. |

## Behavior

### Names

Templates are rendered with `missingkey=error` and validated at Init with two
sample tenants: they must render distinct names. Names are lowercased and
reduced to `[a-z0-9._-]` (other character runs become `-`), at most 64
characters; longer names are truncated and suffixed with `-` plus the first 8
hex characters of `sha256(tenant ID)`, so truncation never collides. Use only
immutable tenant fields (`ID`, `Slug`): names are recomputed on deprovision.
A user template that renders the admin user name is rejected.

### Passwords

Nothing secret is stored. A tenant password is
`base64url(HMAC-SHA256(password_secret, tenant ID))` without padding: 43
characters, 256 bits, URL-safe (usable in AMQP URIs as is). Go code can import
`rabbitmqvhost.TenantPassword(secret, tenantID)`; other languages compute the
same HMAC.

- Why HMAC: the password is reproducible from the secret, so there is no
  credential store to back up or leak, and one tenant's password reveals
  nothing about another's or about the secret.
- Rotation: the password is set again on every Provision. Change
  `password_secret` and reprovision tenants to rotate all passwords (clients
  must pick up the new password; existing connections stay open until they
  reconnect).
- Protect `password_secret` like a master password: anyone holding it can
  derive every tenant's credentials. Inject it from a secret store, not from
  a committed file.

### Ownership

- The vhost gets the tag `tenarium-tenant-id:<tenant id>` and the description
  `Tenarium tenant <slug> (<id>)`. Other (operator) tags are preserved.
- The user gets the tags `user_tags` + `tenarium-tenant-id:<tenant id>`.
- Provision checks both before changing anything. A vhost or user tagged for
  another tenant, holding retained data, or existing without a marker (e.g.
  created by hand, or `guest`) is never adopted: Provision fails with a clear
  error. Because the vhost is created with its marker in a single request, an
  interrupted Provision never leaves an unmarked vhost behind.
- After writing the vhost the plugin reads it back and fails if the marker is
  missing (RabbitMQ releases without vhost metadata).
- Deprovision never deletes or modifies a resource that is not tagged for the
  tenant; it logs a warning and continues.

Note: RabbitMQ has no create-only call, so two Tenarium instances
provisioning colliding names at the exact same moment could race. Names
derive from unique slugs (and hashed tenant IDs when truncated), so this
needs a misconfiguration.

### Provisioning

Idempotent create-or-update: PUT vhost (tags, description,
`default_queue_type`), PUT user (password, tags), PUT permissions, then the
vhost limits. Re-running after a partial failure converges.

### Limits

For each entry of `limits`, the tenant's entitlement limit of that name is set
with `PUT /api/vhost-limits/{vhost}/{limit}`. An absent or negative limit
means unlimited and the vhost limit is deleted. `0` is applied as is
(RabbitMQ then refuses any connection / queue).

### Deprovision modes

- `delete` (default): the user is deleted first (closing its connections),
  then the vhost with all queues, exchanges and messages.
- `keep`: nothing is touched. The resources keep their marker, so another
  tenant cannot adopt them; the tenant can still connect.
- `retain`: the user is deleted (no more access) but the vhost and its
  messages stay. The vhost's `tenarium-tenant-id:` tag is replaced by
  `tenarium-retained-tenant-id:<id>` and `tenarium-deleted-at:<RFC3339>`;
  limits stay. Provisioning any tenant whose name maps to a retained vhost
  fails until an operator archives or deletes it.

## Routes

Mounted under `/v1/plugins/{instance}/`:

- `GET /tenants/{tenant}` (ID or slug): requires `tenants:read` (404 when
  denied or unknown). Returns `{"vhost", "username", "amqp_url"}`, no secret.
- `GET /tenants/{tenant}/credentials`: requires `tenants:read` (404) and then
  `tenants:update` (403). Returns `{"vhost", "username", "password", "uri"}`
  (`uri` only with `amqp_url`), with `Cache-Control: no-store`.

## Health

`GET /api/overview` with the admin credentials.

## Required RabbitMQ permissions

The admin user needs the `administrator` tag (create/delete vhosts and users,
set permissions and vhost limits). RabbitMQ automatically grants the creating
user full permissions on each new vhost.

## Testing

Unit tests run against an in-memory fake of the Management API:

```sh
go test ./plugins/rabbitmqvhost/...
```

Integration tests need a real broker:

```sh
docker run -d --name tenarium-test-rabbitmq -p 45672:15672 rabbitmq:3-management
TENARIUM_TEST_RABBITMQ_URL=http://localhost:45672 go test ./plugins/rabbitmqvhost/... -run Integration -v
docker rm -f tenarium-test-rabbitmq
```

`TENARIUM_TEST_RABBITMQ_USER` / `TENARIUM_TEST_RABBITMQ_PASSWORD` default to
`guest` / `guest`.
