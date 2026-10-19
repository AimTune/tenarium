# Configuration

Tenarium reads one YAML file (`-config path` or the `TENARIUM_CONFIG` environment variable).
`${VAR}` references are expanded from the environment before parsing, so secrets can stay
out of the file. Unknown keys are rejected.

```yaml
server:
  addr: ":8080"
  api_keys: ["${TENARIUM_API_KEY}"]   # static bearer keys; empty entries are ignored
  allow_anonymous: false               # dev only: requests without any credentials act as "anonymous"
  shutdown_timeout: 15s
  tls:                                 # optional: serve HTTPS, see docs/tls.md
    cert_file: ""                      # static certificate and key (PEM)
    key_file: ""
    acme:                              # or certificates from Let's Encrypt / any ACME CA
      enabled: false
      email: ops@example.com
      directory: staging               # staging (default) | production | https://... directory URL
      platform_hosts: [tenarium.example.com]
      http_addr: ":80"                 # http-01 challenges + redirect; "" leaves only tls-alpn-01

log:
  level: info        # debug | info | warn | error
  format: json       # text | json

store:
  driver: postgres   # memory | postgres
  dsn: postgres://user:pass@host:5432/tenarium?sslmode=require
  read_dsn: ""       # optional read replica for list queries (tenants, users, events, audit); may lag

events:
  poll_interval: 1s      # fallback when no notification arrives
  batch_size: 100
  handler_timeout: 30s   # per delivery attempt, unless the subscription sets its own
  lease_ttl: 15s         # failover time between replicas
  instance_id: ""        # lease owner name; random by default (set it to the pod name)
  region: ""             # where this replica runs: region-scoped plugins prefer replicas there (multi-region.md)
  retention: 0           # delete events older than this once all subscriptions processed them (0 = keep)
  prune_interval: 1h

tenants:
  require_known_plans: true
  member_roles: [owner, admin, member, viewer]
  settings_schema:        # JSON Schema 2020-12 for tenant settings (or settings_schema_file)
    type: object
    properties:
      region: {enum: [eu, us]}
    required: [region]
  reserved_domains: [example.com]   # your own domains; tenants cannot claim them or their subdomains
  deletion_grace_period: 720h       # soft delete: suspend now, delete later, restorable meanwhile (0 = off)
  purge_after: 2160h                # remove the data of deleted tenants this long after deletion (0 = keep)
  regions: [eu, us]                 # allowed tenant regions (data residency); empty = any
  default_region: eu                # used when neither the request nor the parent names one

usage:                   # metered metrics, see docs/tenants.md
  metrics:
    api_calls: {period: month, overage: allow, thresholds: [80, 100]}   # period: day, month, year, cycle or empty

scheduler:
  interval: 30s          # runs due scheduled actions and closes ended usage periods (0 disables it here)

webhooks:                # self-service tenant webhooks, see docs/webhooks.md
  enabled: true
  timeout: 10s
  attempts: 3
  max_failures: 50       # disable an endpoint after that many consecutive failed events (0 = never)
  max_per_tenant: 10
  delivery_retention: 720h
  allow_http: false              # development only
  allow_private_networks: false  # development only: lets tenants target internal addresses

bootstrap:               # created at startup if missing; existing records are left alone
  plans:
    - id: free
      name: Free
      features: {sso: false}
      limits: {members: 5, api_calls: 10000}
  users:
    - {email: admin@example.com, roles: [admin], password: "${TENARIUM_ADMIN_PASSWORD}"}

users:                   # see docs/users.md
  directory: internal    # or the instance name of a user directory plugin (e.g. keycloak)
  mailer: smtp           # mailer plugin instance; default: the only one, else emails are logged
  public_url: https://tenarium.example.com
  product_name: Tenarium
  password_min_length: 12
  invitation_ttl: 168h
  reset_ttl: 1h
  lockout: {max_failures: 10, duration: 15m}
  breached_password_check: false   # reject new passwords found in Have I Been Pwned (k-anonymity)
  magic_link_ttl: 0                # > 0 enables passwordless sign-in by emailed link (e.g. 15m)
  email_change_ttl: 24h            # validity of email-change confirmation links
  templates: {}          # invitation / password_reset overrides

auth:
  tokens:
    enabled: true        # Tenarium-issued JWTs for users
    issuer: ""           # default: users.public_url
    audience: tenarium
    access_ttl: 15m
    refresh_ttl: 720h
    rotation_period: 0   # rotate the signing key when older than this (0 = only on request)
  rate_limit: 30         # /v1/auth requests per client IP per minute (0 = off)
  rate_limit_shared: false  # count rate_limit in the database, across replicas
  sso:                   # per-tenant OpenID Connect and SAML sign-in, see docs/auth.md
    enabled: true
    allowed_redirects: [https://app.example.com]   # origins return_to may use besides users.public_url
    allow_private_issuers: false                    # development only
  webauthn:              # passkeys, see docs/users.md
    enabled: true
    rp_id: ""            # default: the host of users.public_url; must be a domain, not an IP
    origins: []          # default: the origin of users.public_url
  impersonation:         # support access, see docs/users.md
    require_consent: true
    max_ttl: 1h
  provider:              # Tenarium as an OpenID provider for your apps, see docs/oidc-provider.md
    enabled: true
    session_ttl: 12h     # how long the browser stays signed in at /oauth
  social:                # sign-in with Google, GitHub, Microsoft or OIDC, see docs/auth.md
    public_url: ""       # default users.public_url
    allowed_redirects: []
    allow_private_issuers: false
    providers:
      - {name: google, type: google, client_id: ..., client_secret: "${GOOGLE_SECRET}", auto_create: false, allowed_domains: []}
      # other fields: label, issuer, tenant (microsoft), scopes, auth_url/token_url/api_url (github)
  roles:                 # optional: replace the built-in user role tables
    platform: {admin: ["*"], viewer: ["*:read"]}
    tenant: {owner: ["tenants:read", "tenants:update", "members:*"], viewer: ["*:read"]}

ui:
  enabled: true          # admin UI at /ui/

tracing:                 # OpenTelemetry traces over OTLP/HTTP; OTEL_EXPORTER_OTLP_* env vars also apply
  enabled: false
  endpoint: otel-collector:4318
  insecure: true         # plain HTTP to the collector
  headers: {}
  service_name: tenarium
  sample_ratio: 1.0      # for new traces; incoming sampled traces are always followed

secrets:                 # encrypt stored secrets with a KMS, see docs/secrets.md
  provider: none         # none | local | awskms | gcpkms | vault | azurekv
  decrypt_providers: []  # older providers kept for reading during a migration
  dek_ttl: 1h
  dek_max_uses: 16777216
  decrypt_cache_size: 1024
  reject_plaintext: false
  timeout: 30s
  local: {primary: k1, keys: {k1: "${TENARIUM_KEK_1}"}}
  # aws_kms, gcp_kms, vault, azure_key_vault: see docs/secrets.md

plugins:                 # loaded in this order; provisioners run in this order
  - plugin: kafka        # registered plugin ID
    name: kafka          # instance name (default: plugin ID); must be unique
    enabled: true
    scope:               # optional: only apply to these tenants
      plans: [enterprise]
      labels: {tier: gold}
      regions: [eu]      # tenant regions (tenants.regions)
      tenants: [acme]    # IDs or slugs
    config: { ... }      # plugin-specific
```

## Defaults

Keys left out take these values (everything else is zero, empty or off):

| Key | Default |
|---|---|
| `server.addr` | `:8080` |
| `server.shutdown_timeout` | `15s` |
| `log.level`, `log.format` | `info`, `text` |
| `store.driver` | `memory` |
| `events.poll_interval`, `batch_size`, `handler_timeout`, `lease_ttl` | `1s`, `100`, `30s`, `15s` |
| `events.prune_interval` | `1h` |
| `tenants.member_roles` | `[owner, admin, member, viewer]` |
| `scheduler.interval` | `30s` |
| `webhooks.enabled`, `max_failures` | `true`, `50` (`timeout` 10s, `attempts` 3) |
| `users.directory`, `users.public_url` | `internal`, `http://localhost:8080` |
| `auth.tokens.enabled`, `audience`, `access_ttl`, `refresh_ttl` | `true`, `tenarium`, `15m`, `720h` |
| `auth.rate_limit` | `30` |
| `auth.sso.enabled`, `auth.webauthn.enabled`, `auth.provider.enabled` | `true` |
| `auth.impersonation.require_consent`, `max_ttl` | `true`, `1h` |
| `auth.provider.session_ttl` | `12h` |
| `ui.enabled` | `true` |
| `secrets.provider` | `none` |
| `server.tls.acme.directory`, `http_addr` | `staging`, `:80` |

## Feature reference

| Section | Documented in |
|---|---|
| `server.tls` | [TLS and managed certificates](tls.md) |
| `tenants.deletion_grace_period`, `purge_after` | [soft deletion](tenants.md#soft-deletion-and-restore), [data protection](privacy.md#purging-deleted-tenants) |
| `tenants.regions`, `default_region` | [regions](plans.md#regions-and-data-residency) |
| `usage` | [usage periods](tenants.md#usage-periods-soft-limits-and-billing-export) |
| `webhooks` | [tenant webhooks](webhooks.md) |
| `users`, `bootstrap.users` | [users](users.md) |
| `auth.tokens`, `auth.roles`, `auth.sso` | [authentication](auth.md), [users](users.md#signing-in-with-tenarium-tokens) |
| `auth.webauthn` | [passkeys](users.md#passkeys) |
| `auth.impersonation` | [impersonation](users.md#impersonation) |
| `auth.provider` | [OpenID provider](oidc-provider.md) |
| `auth.social` | [social login](auth.md#social-login) |
| `users.magic_link_ttl`, `email_change_ttl`, `breached_password_check` | [sign-in links](users.md#sign-in-links), [email change](users.md#changing-the-email-address), [passwords](users.md#passwords-and-protection) |
| `tracing` | [operations](operations.md#tracing) |
| `secrets` | [secrets at rest](secrets.md) |

## Plugin instances

The same plugin can be configured several times under different `name`s, for example two
webhooks with different endpoints. The instance name prefixes subscription names (and so their
cursors) and is the mount point of the plugin's HTTP routes: `/v1/plugins/{name}/...`.

## Scope

`scope` restricts an instance to some tenants. All criteria that are set must match. Scope
applies to:

- **event subscriptions**, for events that belong to a tenant. Tenant events are matched
  against the tenant as it was when the event happened; events that also carry the previous
  state (`tenant.updated`, `tenant.plan_changed`, `tenant.region_changed`, ...) reach the
  instance if **either** the new or the previous tenant is in scope, so an instance sees a
  tenant leave its scope (moving off a scoped plan or region) and can clean up;
- **hooks**;
- **provisioning**. Deprovisioning always runs, so resources are cleaned up even if a tenant left
  the scope after it was provisioned. Provisioners must treat tenants they never provisioned as a
  no-op.

Changing a tenant's plan or labels does not provision it retroactively for a plugin whose scope
it now enters. Use the provisioning retry, or write the provisioner to also react to
`tenant.updated` events (which reach it, since the new tenant is in its scope).

## Reloading

The file is read at startup. `SIGHUP` or `POST /v1/admin/reload` re-reads it and applies, live,
`log.level` and the `config` of plugin instances that support it (`webhook`, `smtp`, and plugins
implementing `sdk.Reconfigurer`); every other change is reported as needing a restart. See
[reloading the configuration](operations.md#reloading-the-configuration).

## Environment variables

| Variable | Meaning |
|---|---|
| `TENARIUM_CONFIG` | Config file path (default for `-config`) |
| anything referenced as `${VAR}` | Expanded into the config |

## Command-line flags

```
tenarium -config config.yaml
tenarium -list-plugins      # plugins compiled into this binary
tenarium -version
```
