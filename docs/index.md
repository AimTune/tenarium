# Tenarium documentation

Tenarium is an open-source tenant control plane for multi-tenant SaaS applications. It owns the
tenant lifecycle (create, provision, suspend, delete), plans and entitlements, users, members and
usage quotas, records every change in a durable event log, and lets plugins take part in all of
it. The [README](https://github.com/AimTune/tenarium/blob/main/README.md) has the quick start.

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

## Using Tenarium

| Page | Covers |
|---|---|
| [Configuration](configuration.md) | every configuration key and its default |
| [REST API](api.md) | resources, errors, concurrency, idempotency, pagination |
| [Tenant lifecycle](tenants.md) | templates, cloning, scheduled actions, maintenance windows, soft deletion, custom domains, branding, API keys, health scores, usage periods, SCIM, audit |
| [Plans and placement](plans.md) | entitlements, plan revisions, add-ons, feature rollouts, regions |
| [Users](users.md) | directories, sign-in, sign-in links, email change, sessions, roles, two-factor authentication, passkeys, impersonation |
| [Authentication and authorization](auth.md) | authenticators, actions, tenant roles and groups, OIDC and SAML SSO, social login, signing keys |
| [OpenID provider](oidc-provider.md) | Tenarium as the sign-in service of your applications |
| [Tenant webhooks](webhooks.md) | self-service webhooks with Standard Webhooks signatures |
| [Event schema registry](event-schemas.md) | JSON Schemas of every event type and their versioning |
| [Data protection](privacy.md) | exports, user erasure, purging deleted tenants |

## Integrating your application

| Page | Covers |
|---|---|
| [Go client and tenariumctl](client.md) | the API client and the CLI |
| [Tenant middleware](middleware.md) | resolving and checking tenants in Go, TypeScript and Python services |
| [Gateway integration](gateway.md) | tenant resolution at the API gateway |
| [PostgreSQL row-level security](rls.md) | isolating tenants in a shared database |

## Plugins

[Plugins](plugins/README.md) lists every built-in plugin and the extension points.
[Writing Go plugins](plugins/writing-go.md), [external plugins](plugins/external.md) and
[WebAssembly plugins](plugins/wasm.md) show how to write your own.

## Running Tenarium

| Page | Covers |
|---|---|
| [Operations](operations.md) | deployment, PostgreSQL, scaling, health, metrics, tracing, security checklist |
| [TLS and managed certificates](tls.md) | HTTPS with a static certificate or ACME |
| [Secrets at rest](secrets.md) | KMS envelope encryption of stored secrets |
| [Multi-region deployments](multi-region.md) | what works today and a recommended cell architecture |
| [Architecture](architecture.md) | domain model, events, delivery, hooks, package map |
| [Testing](testing.md) | unit, integration, fuzz, load and chaos tests |
| [Roadmap](roadmap.md) | what is done and what may come |
