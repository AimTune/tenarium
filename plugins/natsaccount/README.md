# nats-tenant

Provisions one NATS account per tenant for NATS decentralized JWT
authentication (operator mode). For each tenant the plugin:

1. derives the tenant's account key pair from the tenant ID (nothing is stored),
2. builds an account JWT with the tenant's name, an ownership tag and
   limits mapped from Tenarium entitlements,
3. signs it with the operator signing key, and
4. pushes it to the account resolver: the NATS servers themselves (`full` or
   `cache` resolver) or an HTTP account server (`nats-account-server`).

Applications then issue user JWTs for the tenant's account and connect to
NATS as that tenant.

## Configuration

```yaml
plugins:
  - plugin: nats-tenant
    config:
      # Operator seed (SO...) that signs account JWTs: the operator identity
      # key or, better, one of its signing keys.
      operator_signing_key: ${NATS_OPERATOR_SIGNING_SEED}
      # Optional: shown on the tenant route and checked against the JWT.
      operator_public_key: OAB...
      # Optional: verifies that operator_signing_key is trusted by the
      # operator (listed in signing_keys, or the identity key without
      # strict_signing_key_usage).
      operator_jwt: ${NATS_OPERATOR_JWT}
      # HMAC key that account keys are derived from. Protect it like the
      # signing key (see "Account keys").
      account_seed_secret: ${NATS_ACCOUNT_SEED_SECRET}
      name_template: "tenant-{{.Slug}}"
      resolver:
        mode: nats
        urls: ["nats://nats-1:4222", "nats://nats-2:4222"]
        credentials_file: /etc/tenarium/nats-sys.creds   # a system account user
        timeout: 5s
      limits:
        conn: max_connections
        subs: max_subscriptions
        payload: max_message_bytes
        disk_storage: jetstream_disk_bytes
        streams: jetstream_streams
      jetstream: true
      jetstream_feature: jetstream     # optional
      on_deprovision: delete
```

HTTP account server:

```yaml
      resolver:
        mode: http
        url: http://nats-account-server:9090/jwt/v1
      on_deprovision: disable
```

### Fields

| Field | Required | Description |
|---|---|---|
| `operator_signing_key` | yes | Operator seed (`SO...`). Account seeds or user seeds are rejected. |
| `operator_public_key` | no | Operator identity (`O...`), for display and validation. |
| `operator_jwt` | no | Operator JWT. When set, Init checks that the signing key is trusted by it and that it matches `operator_public_key`. |
| `account_seed_secret` | yes | HMAC key (at least 16 characters) that account keys are derived from. |
| `name_template` | no | `text/template` over the tenant, rendered into the account JWT `name`. Default `tenant-{{.Slug}}`. |
| `resolver.mode` | yes | `nats` or `http`. |
| `resolver.urls` | nats | NATS server URLs (`nats://`, `tls://`, `ws://`, `wss://`). |
| `resolver.url` | http | Account server base URL; the plugin uses `GET/POST {url}/accounts/{pub}`. |
| `resolver.credentials_file` | no | Creds file of a system account user (nats mode). |
| `resolver.user_jwt` + `resolver.user_seed` | no | The same credentials inline (nats mode). |
| `resolver.user` + `resolver.password` | no | Username/password (nats mode). |
| `resolver.token` | no | NATS auth token (nats mode) or a bearer token sent to the account server (http mode). |
| `resolver.ca_file` | no | PEM file of CAs trusted for TLS. |
| `resolver.timeout` | no | Timeout of each resolver request, a Go duration. Default `5s`. |
| `limits` | no | Map of NATS account limit to Tenarium limit name, see below. |
| `jetstream` | no | Enable JetStream for tenant accounts. Default `false`. |
| `jetstream_feature` | no | Enable JetStream only for tenants with this feature (requires `jetstream: true`). |
| `on_deprovision` | no | `delete` (default in nats mode), `disable` (default in http mode) or `keep`. |

Only one credentials method may be set. In nats mode the credentials must
belong to a user of the **system account**: NATS servers only accept claim
updates (`$SYS.REQ.CLAIMS.UPDATE`) from it. Other credentials get "no
responders".

## Behavior

### Account keys

Account keys are not stored anywhere. The 32-byte ed25519 seed of a tenant's
account is

```
HMAC-SHA256(account_seed_secret, "nats-account:" + tenant ID)
```

made into an account key with `nkeys.FromRawSeed(nkeys.PrefixByteAccount, seed)`.
This means:

- The same secret always gives the same account, so Provision can be re-run
  and nothing needs to be backed up except the secret.
- Two tenants never share an account, because the key is derived from the
  unique tenant ID.
- Rotating `account_seed_secret` is a breaking change. Every tenant gets a
  new, empty account, and existing user JWTs (issued by the old account
  keys) stop working. The old accounts stay in the resolver until removed.
- Anyone who has the secret can sign users into any tenant's account. Keep
  it in a secret store and do not share it more widely than the operator
  signing key.

The derivation is exported so applications can issue user JWTs for a tenant:

```go
import (
    "github.com/AimTune/tenarium/plugins/natsaccount"
    "github.com/nats-io/jwt/v2"
    "github.com/nats-io/nkeys"
)

akp, _ := natsaccount.AccountKeyPair(secret, tenantID)  // account key pair
upair, _ := nkeys.CreateUser()
upub, _ := upair.PublicKey()
uc := jwt.NewUserClaims(upub)
uc.Pub.Allow.Add("orders.>")
userJWT, _ := uc.Encode(akp)
seed, _ := upair.Seed()
creds, _ := jwt.FormatUserConfig(userJWT, seed)        // a .creds file
```

`natsaccount.TenantAccountPublicKey(secret, tenantID)` returns only the
public key. Generating user credentials is not part of this plugin.

### Account JWT

- `sub`: the derived account public key; `iss`: the operator signing key.
  The servers' operator JWT must list that signing key, or the signing key
  must be the operator identity key and `strict_signing_key_usage` must be
  off.
- `name`: `name_template` rendered and restricted to letters, digits, `-`,
  `_` and `.`. Names longer than 64 characters are shortened and suffixed
  with the first 8 hex characters of sha256(tenant ID). The name is for
  display only (the account is identified by its key), so templates may use
  mutable fields. It is updated on the next Provision. Prefer `ID` and
  `Slug` anyway.
- `tags`: `tenarium-tenant-id:<id>` (lower case, as NATS tags are).
- `iat`: issue time. The full resolver ignores updates older than the JWT it
  holds.

### Ownership

Before every push the plugin looks up the current JWT
(`$SYS.REQ.ACCOUNT.<pub>.CLAIMS.LOOKUP` in nats mode, `GET` in http mode).
A JWT tagged for another tenant, or one without any `tenarium-tenant-id`
tag (created by hand or by another tool), is never overwritten: Provision
fails with a clear error, and Deprovision logs a warning and leaves it
alone. Because keys are derived from tenant IDs this should only happen if
another tool or installation shares the operator and the secret.

### Limits

`limits` maps these NATS account limits to Tenarium limit names (read from
the tenant's entitlements):

| Key | NATS limit |
|---|---|
| `conn` | active client connections |
| `subs` | subscriptions |
| `data` | bytes |
| `payload` | maximum message payload |
| `leaf` | leaf node connections |
| `imports`, `exports` | number of imports/exports |
| `mem_storage`, `disk_storage` | JetStream memory/file storage bytes |
| `streams`, `consumers` | JetStream streams/consumers |

An absent or negative entitlement, or an unmapped limit, is unlimited
(`-1`, `jwt.NoLimit`). A value of `0` means none (for example, `mem_storage: 0`
disables memory streams). JetStream is off unless `jetstream: true`. With
`jetstream_feature` it is enabled only for tenants that have that feature.
JetStream limit mappings require `jetstream: true`. Limits change when the
plan changes only after the next Provision (e.g. a provisioning retry).

### Deprovisioning

| `on_deprovision` | Effect |
|---|---|
| `delete` | Sends `$SYS.REQ.CLAIMS.DELETE` with a generic JWT signed by (and with subject) the operator signing key, listing the account in `accounts`. The account is removed from the resolver and its clients are disconnected. This needs `resolver: { type: full, allow_delete: true }`. If the servers answer "delete must be enabled", the plugin logs a warning and falls back to `disable`. Not available in http mode, because the account server has no delete API. |
| `disable` | Re-pushes the account JWT with every limit set to 0, JetStream disabled and all user JWTs issued so far revoked (`revocations: {"*": now}`), tagged `tenarium-disabled`. Existing connections are dropped and new ones refused, but the account stays known to the resolver. |
| `keep` | Nothing is touched. |

A tenant whose account is unknown to the resolver counts as already
deprovisioned. Repeated runs are no-ops. There is no `retain` mode, because
ownership cannot be handed to another tenant: the account key is derived
from the tenant ID.

Resolver support:

| Resolver | Push | Lookup | Delete |
|---|---|---|---|
| nats-server `full` | yes | yes | with `allow_delete: true` |
| nats-server `cache` | yes | yes | no (falls back to disable) |
| nats-server `URL` + nats-account-server | via `mode: http` | yes | no |
| nats-server `MEMORY` | no (static config) | no | no |

## Routes

`GET /v1/plugins/{instance}/tenants/{tenant}` (tenant ID or slug) requires
`tenants:read` on the tenant. A caller without it gets `404`, as for an
unknown tenant. The response contains no secrets:

```json
{
  "account_public_key": "AB...",
  "account_name": "tenant-acme",
  "account_jwt": "eyJ0eXAiOiJKV1Qi...",
  "provisioned": true,
  "operator_public_key": "OA...",
  "signing_key": "OD...",
  "resolver_mode": "nats"
}
```

`account_jwt` is the JWT the resolver currently holds (omitted when not
provisioned). `disabled` is `true` after `on_deprovision: disable`. If the
resolver cannot be reached, the route answers `502`.

## Health

- nats mode: connects (lazily, on first use) and flushes the connection.
- http mode: `GET {url}`, which is healthy unless the request fails or the
  status is 5xx.

Init never contacts the resolver. `Stop` closes the NATS connection.

## Required permissions

- The operator signing key, trusted by the servers' operator.
- nats mode: a system account user that may publish requests to
  `$SYS.REQ.CLAIMS.UPDATE`, `$SYS.REQ.CLAIMS.DELETE` and
  `$SYS.REQ.ACCOUNT.*.CLAIMS.LOOKUP` and receive replies.
- http mode: write access to the account server API.

## Security notes

- `operator_signing_key` and `account_seed_secret` are as sensitive as each
  other. Either one is enough to create users for any tenant, so load both
  from a secret store.
- Use a signing key rather than the operator identity key, and consider
  `strict_signing_key_usage` on the operator.
- Account JWTs are not secret: they hold only public keys, limits and tags.
- The delete request is self-signed by the signing key and does not expire.
  Replaying it can only delete accounts that the operator already wanted to
  delete.

## Testing

Unit tests need no network:

```
go test ./plugins/natsaccount/...
```

Integration tests need a NATS server in operator mode with a full resolver
(`allow_delete: true` for the delete path) and a system account:

| Variable | Meaning |
|---|---|
| `TENARIUM_TEST_NATS_URL` | e.g. `nats://127.0.0.1:44222`; tests skip when unset |
| `TENARIUM_TEST_NATS_SIGNING_KEY` | operator signing seed trusted by the server |
| `TENARIUM_TEST_NATS_CREDS` | path to a system account user creds file |
| `TENARIUM_TEST_NATS_OPERATOR_JWT` | optional operator JWT |

A minimal server configuration:

```
port: 4222
operator: "<operator JWT listing the signing key>"
system_account: <SYS account public key>
jetstream: { store_dir: "/data/js" }
resolver: { type: full, dir: "/data/jwt", allow_delete: true }
resolver_preload: { <SYS account public key>: "<SYS account JWT>" }
```

```
docker run -d --name tenarium-test-nats -p 44222:4222 -v $PWD/nats:/etc/nats nats:latest -c /etc/nats/nats-server.conf
```
