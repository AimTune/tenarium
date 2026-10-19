# Tenarium

**Website and documentation: [tenarium.aimtune.dev](https://tenarium.aimtune.dev)** ·
[API reference](https://tenarium.aimtune.dev/api/)

Tenarium is an open-source **tenant control plane** for multi-tenant SaaS applications.
It owns the tenant lifecycle (create, provision, suspend, delete), plans and entitlements,
members and usage quotas, records every change in a durable event log, and lets **plugins**
take part in all of it: publish events to Kafka, give each tenant its own database schema or
Keycloak realm, authenticate with OIDC or LDAP, enforce custom policies, and anything else you
write. Plugins can be compiled in (Go), run as separate processes in any language, or run as
sandboxed WebAssembly.

```
            ┌───────────── Tenarium ─────────────────────────────────────────┐
 REST API ─▶│ authn ─▶ authz ─▶ hooks ─▶ [ tx: state + event (outbox) ]      │
 Admin UI   │                                    │                           │
            │                       dispatcher (cursor, retry, DLQ, leases)  │
            └──────────┬───────────────┬───────────────┬─────────────────────┘
                       ▼               ▼               ▼
                  provisioning      Kafka /        your plugins
              (schema, realm, …)    webhooks     (Go · HTTP · WASM)
```

## Features

- **Tenant lifecycle** with a strict state machine, hierarchy (organization → workspace),
  labels, JSON-Schema-validated settings, optimistic locking (`ETag`/`If-Match`) and
  idempotent creates (`Idempotency-Key`), scheduled actions and trials, soft deletion with
  restore, and custom domains with DNS verification.
- **Plans, entitlements and quotas**: features and limits per plan with per-tenant overrides,
  atomic usage counters per day, month or year, soft limits with overage and threshold events,
  a `members` limit, and usage export to Stripe meters.
- **Users and members**: platform-wide users with memberships in many tenants, invitation
  emails, password reset, lockout, two-factor authentication (TOTP), and Tenarium-issued JWTs
  (with JWKS and key rotation) — or keep identities in Keycloak through a pluggable user
  directory.
- **Reliable events**: a transactional outbox in PostgreSQL; every plugin subscription has its own
  cursor, retries with backoff, a dead-letter queue and replay. Events are CloudEvents 1.0.
- **Horizontal scaling**: run several replicas on one database; leases make sure each
  subscription is processed by exactly one replica, with automatic failover.
- **Authentication & authorization**: API keys, OIDC (Keycloak, Auth0, Entra ID, …), LDAP/AD,
  tenant API keys, per-tenant single sign-on (each customer's own OIDC provider), SCIM 2.0
  provisioning from the customer's directory, role-based access control, and tenant-scoped
  administrators who can only reach their own subtree.
- **Self-service webhooks and audit trail**: tenants register signed webhooks with a delivery
  log; every change is queryable by actor, tenant, type and time.
- **Plugin system** with seven extension points and three runtimes; SDKs for Go, TypeScript and
  Python.
- **Operations**: embedded admin UI, OpenAPI 3.1 spec, Prometheus metrics, health/readiness
  probes, OpenTelemetry tracing, event retention, Docker image, Helm chart, a Go client and the
  `tenariumctl` CLI.

### Built-in plugins

| Plugin | What it does |
|---|---|
| `kafka` | Publishes events to Kafka (keyed by tenant, CloudEvents structured or binary). |
| `webhook` | Delivers signed events to an HTTP endpoint ([Standard Webhooks](https://www.standardwebhooks.com)). |
| `redis` | Events to Redis Streams, a tenant/entitlement cache for your services, Redis ACL user per tenant. |
| `postgres-tenant` | Schema- or database-per-tenant provisioning with migrations. |
| `keycloak` | Realm-per-tenant provisioning, member sync, and Keycloak as the user directory. |
| `kubernetes-tenant` | Namespace-per-tenant with quota, limit range, network policy and role bindings. |
| `s3-tenant` | Bucket- or prefix-per-tenant on S3 and S3-compatible storage. |
| `stripe` | Syncs tenants to Stripe customers and subscriptions; suspends and resumes from billing webhooks. |
| `smtp` | Sends invitation and password-reset emails. |
| `oidc` | Authenticates JWT access tokens from any OIDC provider. |
| `ldap` | Authenticates Basic credentials against LDAP / Active Directory. |
| `rbac` | Role-based authorization. |
| `policy` | Reserved slugs, plan allow-list, default and required labels. |
| `external` | Hosts out-of-process plugins written in any language. |
| `wasm` | Runs sandboxed WebAssembly modules as hooks and event handlers. |
| `logger` | Logs events (a minimal example). |

## Quick start

With Docker (PostgreSQL, Redpanda/Kafka and Tenarium):

```sh
docker compose up -d
open http://localhost:8080/ui/          # API key: dev-key
```

From source (in-memory store):

```sh
TENARIUM_API_KEY=dev go run ./cmd/tenarium -config config.example.yaml
```

```sh
curl -H "Authorization: Bearer dev" -H "Content-Type: application/json" \
  -d '{"slug": "acme", "name": "Acme Inc", "plan": "free"}' \
  http://localhost:8080/v1/tenants
```

## A plugin in 20 lines

```go
package audit

import (
	"context"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() { sdk.Register("audit", func() sdk.Plugin { return &Plugin{} }) }

type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "audit", Name: "Audit", Version: "1.0.0"}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	log := r.Logger()
	r.Subscribe("log", sdk.EventFilter{Types: []string{"tenant.*"}}, func(_ context.Context, e sdk.Event) error {
		log.Info("tenant event", "type", e.Type, "tenant", e.TenantID, "actor", e.Actor)
		return nil
	})
	r.Hook(sdk.HookBeforeTenantCreate, func(_ context.Context, req *sdk.HookRequest) error {
		if req.Tenant.Plan == "" {
			return sdk.Reject("a plan is required")
		}
		return nil
	})
	return nil
}
```

Compile it into a custom binary with `tenarium-build --with example.com/audit=./audit`, or run
the same plugin out of process with `extplugin.Serve(&audit.Plugin{})`.
See [Writing plugins](docs/plugins/writing-go.md).

## Documentation

The documentation is published at **[tenarium.aimtune.dev](https://tenarium.aimtune.dev)**. Its
sources are the Markdown files in [docs/](docs); the site itself is a Docusaurus project in
[website/](website) (`cd website && npm ci && npm start`, or `make docs-serve`).

- [Architecture](docs/architecture.md): domain model, event delivery guarantees, scaling
- [Configuration](docs/configuration.md): every config option
- [API](docs/api.md): REST conventions; the full spec is served at `/openapi.yaml`
- [Tenant lifecycle](docs/tenants.md): scheduled actions and trials, soft delete and restore, custom domains, tenant API keys, usage periods and soft limits, SCIM, audit trail
- [Tenant webhooks](docs/webhooks.md): self-service endpoints, signatures, delivery log
- [Users](docs/users.md): user directories, invitations, sign-in, tokens, two-factor authentication, built-in roles
- [Authentication and authorization](docs/auth.md): API keys, OIDC, LDAP, RBAC, tenant scope, per-tenant SSO, signing keys
- [Plugins](docs/plugins/README.md): extension points, runtimes and built-in plugin reference
  - [Writing Go plugins](docs/plugins/writing-go.md)
  - [External plugins (any language)](docs/plugins/external.md)
  - [WebAssembly plugins](docs/plugins/wasm.md)
- [Go client and tenariumctl](docs/client.md): calling the API from Go and the command line
- [Tenant middleware](docs/middleware.md): resolving the current tenant in your services (Go, TypeScript, Python)
- [Operations](docs/operations.md): deployment, Helm, metrics, tracing, retention, upgrades
- [Roadmap](docs/roadmap.md)
- [API reference](https://tenarium.aimtune.dev/api/): the OpenAPI spec rendered with Redoc

## Project layout

```
cmd/tenarium/          server binary with all built-in plugins
cmd/tenarium-build/    builds custom binaries with extra plugins
cmd/tenariumctl/       command-line client
pkg/client/            Go API client
pkg/tenantmw/          Go tenant-resolution middleware for your services
pkg/sdk/               public plugin contract (stable)
pkg/sdk/sdktest/       test helpers for plugin authors
pkg/extplugin/         out-of-process plugin protocol and Go runner
pkg/wasmguest/         guest-side helpers for WASM modules written in Go
pkg/server/            wiring; custom distributions call server.Main()
internal/              domain, API, store, dispatcher, authz, UI
plugins/               built-in plugins
sdks/typescript, sdks/python   external plugin SDKs
sdks/typescript-middleware, sdks/python-middleware   tenant middleware for Node.js and Python apps
deploy/                Helm chart, compose config
docs/                  documentation (Markdown)
website/               documentation website (Docusaurus)
examples/              example plugins (Go external, WASM)
```

## Development

```sh
make test               # unit tests
make test-db            # start a throwaway PostgreSQL on :55432
make test-integration   # everything, including PostgreSQL-backed tests
make lint
```

Kafka and LDAP integration tests run when `TENARIUM_TEST_KAFKA_BROKERS` /
`TENARIUM_TEST_LDAP_URL` are set. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
