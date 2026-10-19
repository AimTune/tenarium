# vault-tenant

Provisions HashiCorp Vault resources for every tenant through the Vault HTTP API (package
`plugins/vault`, standard library HTTP only, no Vault SDK):

- a path prefix in an existing **KV version 2** mount (`secret/tenants/<slug>` by default),
- an **ACL policy** (`tenant-<slug>`) that grants the tenant access to that prefix and, when
  enabled, to its transit key,
- optionally an **AppRole role** (`auth/approle/role/tenant-<slug>`) whose tokens carry the
  policy, with routes to read its `role_id` and issue `secret_id`s,
- optionally a **transit key** (`transit/keys/tenant-<slug>`).

## Configuration

```yaml
- plugin: vault-tenant
  config:
    address: https://vault.example.com:8200   # required; http(s) URL without path
    namespace: team-a                         # optional, sent as X-Vault-Namespace (Enterprise)
    auth:                                     # exactly one of token / approle
      token: ${VAULT_TOKEN}
      # approle:
      #   mount: approle                      # default
      #   role_id: ${VAULT_ROLE_ID}
      #   secret_id: ${VAULT_SECRET_ID}
    tls:
      ca_file: /etc/tenarium/vault-ca.pem     # optional PEM bundle
      insecure_skip_verify: false
    timeout: 10s                              # per request, default 10s
    kv:
      mount: secret                           # default; must be an existing KV v2 mount
      path_template: "tenants/{{.Slug}}"      # default
    policy:
      name_template: "tenant-{{.Slug}}"       # default
      capabilities: [create, read, update, delete, list]   # default; also: patch
      extra_rules: |                          # optional template appended to the policy
        path "shared/data/common/*" { capabilities = ["read"] }
    approle:                                  # optional; present (even {}) = enabled
      mount: approle                          # default
      role_template: "tenant-{{.Slug}}"       # default
      token_ttl: 1h                           # optional, Vault duration or seconds
      token_max_ttl: 4h
      secret_id_ttl: 720h
      token_policies: [shared-read]           # extra policies on role tokens
    transit:                                  # optional; present (even {}) = enabled
      mount: transit                          # default
      key_template: "tenant-{{.Slug}}"        # default
      type: aes256-gcm96                      # default; aes128-gcm96 | aes256-gcm96 |
                                              # chacha20-poly1305 | rsa-2048 | rsa-3072 | rsa-4096
    on_deprovision: delete                    # delete (default) | keep | retain
```

### Field reference

| Field | Default | Meaning |
|---|---|---|
| `address` | required | Vault base URL. |
| `namespace` | none | Vault Enterprise namespace, sent on every request (not on `sys/health`). |
| `auth.token` | | Static token. |
| `auth.approle.{mount,role_id,secret_id}` | `approle` | AppRole login for the plugin itself. The token is cached and renewed by logging in again at 80% of its lease; any 403 triggers one new login and a retry. |
| `tls.ca_file`, `tls.insecure_skip_verify` | | TLS trust settings. |
| `timeout` | `10s` | Per-request timeout. |
| `kv.mount` | `secret` | KV v2 mount (must exist). |
| `kv.path_template` | `tenants/{{.Slug}}` | Tenant path prefix in the mount. |
| `policy.name_template` | `tenant-{{.Slug}}` | Policy name. |
| `policy.capabilities` | create, read, update, delete, list | Capabilities on `data/<prefix>/*` and `metadata/<prefix>/*`. With `delete`, `update` on `delete/`, `undelete/` and `destroy/<prefix>/*` is also granted. |
| `policy.extra_rules` | none | Template over `{Tenant, KVMount, Prefix, Policy, AppRoleMount, Role, TransitMount, TransitKey}` appended to the policy. |
| `approle.*` | disabled | Per-tenant AppRole role. TTLs are passed to Vault as given; empty fields keep Vault defaults. |
| `transit.*` | disabled | Per-tenant transit key. The type must support encryption. |
| `on_deprovision` | `delete` | See below. |

## Behavior

### Names

All templates are `text/template` over the tenant (`missingkey=error`) and are checked at
startup by rendering them for two sample tenants: a template that renders the same name for
both is rejected ("must depend on the tenant"). Use only immutable fields (`ID`, `Slug`), since
names are recomputed on deprovision.

- Policy, role and key names are lowercased; characters other than `[a-z0-9_-]` become `-`;
  hyphen runs are collapsed and leading/trailing `-`/`_` trimmed. Names over 128 characters are
  truncated and suffixed with `-` plus the first 8 hex characters of sha256(tenant ID), so
  truncation never collides. A name equal to a built-in policy (`root`, `default`, ...) is an
  error.
- The KV prefix is sanitized per `/` segment (`[a-z0-9._-]`, no `.`/`..`, no glob characters,
  empty segments dropped) and limited to 256 characters the same way.

Because every interpolated value is sanitized, tenant data cannot inject HCL into policies.

### Policy

```hcl
# tenarium-tenant-id: <tenant id>
# Managed by tenarium (vault-tenant); manual changes are overwritten.

path "secret/data/tenants/acme/*"     { capabilities = [<capabilities>] }
path "secret/metadata/tenants/acme/*" { capabilities = [<capabilities>] }
path "secret/metadata/tenants/acme"   { capabilities = ["list"] }
path "secret/delete/tenants/acme/*"   { capabilities = ["update"] }   # also undelete/, destroy/
path "secret/data/tenants/acme/.tenarium-owner" { capabilities = ["deny"] }  # and metadata/, delete/, ...
path "transit/encrypt/tenant-acme"    { capabilities = ["update"] }   # also decrypt/, rewrap/
path "transit/datakey/+/tenant-acme"  { capabilities = ["update"] }
<extra_rules>
```

The policy is rewritten only when it differs from the rendered one.

### Ownership

Vault policies, AppRole roles and transit keys have no metadata, so ownership is recorded in a
**marker**: the KV v2 key `<prefix>/.tenarium-owner` in the KV mount. It holds no secret
versions, only `custom_metadata`:

| Key | Value |
|---|---|
| `tenarium_tenant_id` | owning tenant ID |
| `tenarium_approle_role` | `<mount>/<role>` created for the tenant |
| `tenarium_transit_key` | `<mount>/<key>` created for the tenant |
| `tenarium_deleted_tenant_id`, `tenarium_deleted_at` | set instead of `tenarium_tenant_id` after `retain` |

The tenant's own policy denies every operation on the marker, so tenants cannot alter it.
Additionally every managed policy starts with `# tenarium-tenant-id: <id>`.

Provision refuses (with a clear error, before writing anything) to:

- use a prefix whose marker names another tenant, or that holds data retained from a deleted
  tenant;
- claim an unmarked prefix that already contains keys (an empty prefix is claimed);
- overwrite a policy without the header or with another tenant's ID;
- adopt an AppRole role or transit key that exists but is not recorded in the tenant's marker.

A role or key is recorded in the marker before it is created, so an interrupted run converges
on retry. If `approle` is removed from the configuration, the recorded role is deleted on the
next Provision. A recorded transit key is never deleted implicitly (only by `delete`
deprovisioning); if the key template changes, the old key is left in place with a warning.

### Deprovisioning

- **`delete`** (default): deletes the AppRole role, the policy, the transit key (after setting
  `deletion_allowed=true`), and every KV key under the prefix (`DELETE metadata/...`, i.e. all
  versions), recursively. The marker is deleted last, so an interrupted run is retried.
  **Deleting a transit key irrecoverably destroys the ability to decrypt anything encrypted with
  it**, including ciphertext stored outside Vault. Use `retain` or `keep` if tenant ciphertext
  may outlive the tenant.
- **`keep`**: nothing is touched. The marker stays, so a new tenant with a colliding prefix
  cannot take over the data.
- **`retain`**: access is revoked (role and policy are deleted), the KV data and the transit
  key are kept, and ownership is released: the marker's `tenarium_tenant_id` is replaced by
  `tenarium_deleted_tenant_id` and `tenarium_deleted_at`. Provisioning a tenant whose prefix
  holds retained data fails until an operator removes it (including the marker).

Deprovision only deletes resources recorded in the tenant's marker, and policies whose header
names the tenant. A prefix marked for another tenant is left alone (a warning is logged and
Deprovision succeeds). Never-provisioned or already-deleted tenants are a no-op.

### Quota

Not supported: Vault has no per-path storage quota. Rate-limit and lease-count quotas exist,
but they apply to mounts, namespaces or login roles, not to a KV path prefix, so there is no
meaningful entitlement mapping.

## Routes

- `GET /v1/plugins/{instance}/tenants/{tenant}` (`tenants:read`; 404 if denied or unknown):

  ```json
  {"address": "https://vault.example.com:8200", "namespace": "team-a",
   "kv_mount": "secret", "kv_path": "tenants/acme", "policy": "tenant-acme",
   "approle": {"mount": "approle", "role": "tenant-acme", "role_id": "…"},
   "transit": {"mount": "transit", "key": "tenant-acme"}, "provisioned": true}
  ```

  `role_id` is shown only for a role recorded for the tenant; on its own it is not a secret.
- `POST /v1/plugins/{instance}/tenants/{tenant}/secret-id` (only with `approle`): issues a new
  `secret_id` for the tenant's role. Requires `tenants:read` (404 otherwise), then
  `tenants:update` (403 otherwise). Returns `role_id`, `secret_id`, `secret_id_accessor` and
  `secret_id_ttl` (seconds, 0 = no expiry) with `Cache-Control: no-store`; 409 if the tenant is
  not provisioned. The secret ID carries metadata `tenarium_tenant_id` and `tenarium_issued_by`
  (`<authenticator>:<subject>`) for auditing.

## Health

`/readyz` calls `GET /v1/sys/health`: active nodes (200), standbys (429) and performance
standbys (473) are healthy because they serve (or forward) requests; DR secondaries (472),
uninitialized (501) and sealed (503) nodes are not. It then checks the plugin's token with
`auth/token/lookup-self` (allowed by Vault's `default` policy), logging in first with AppRole.

## Required Vault permissions

For the default names and mounts:

```hcl
path "secret/metadata/tenants/*"  { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/policies/acl/tenant-*"  { capabilities = ["create", "read", "update", "delete"] }
path "auth/approle/role/tenant-*" { capabilities = ["create", "read", "update", "delete"] }  # approle
path "transit/keys/tenant-*"      { capabilities = ["create", "read", "update", "delete"] }  # transit
```

The AppRole auth method and the transit engine must be enabled by an operator; the plugin
never mounts anything.

## Security notes

- Anyone who can write `sys/policies/acl/*` can grant themselves anything; give the plugin a
  token restricted to the paths above (a name prefix such as `tenant-` makes that possible).
- The secret-id route returns live credentials; restrict `tenants:update` accordingly.
- Prefer `tls.ca_file` over `insecure_skip_verify`.

## Testing

Unit tests run against an in-memory fake Vault (`go test ./plugins/vault/...`). Integration
tests run against a real server when `TENARIUM_TEST_VAULT_ADDR` is set
(`TENARIUM_TEST_VAULT_TOKEN`, default `root`); they enable `approle/` and `transit/` if missing
and expect KV v2 at `secret/` (as in dev mode):

```sh
docker run -d --name tenarium-test-vault -p 48200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=root --cap-add=IPC_LOCK hashicorp/vault
TENARIUM_TEST_VAULT_ADDR=http://127.0.0.1:48200 go test ./plugins/vault/...
docker rm -f tenarium-test-vault
```
