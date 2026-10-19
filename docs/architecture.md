# Architecture

Tenarium is a single Go binary. It serves the REST API and the admin UI, keeps state in
PostgreSQL (or in memory for development), and drives plugins.

```
request ─▶ authenticate ─▶ authorize ─▶ validate ─▶ hooks ─▶ ┌ transaction ──────────────┐
                                                             │ write state               │
                                                             │ append event (outbox)     │
                                                             └───────────────────────────┘
                                                                          │ commit, NOTIFY
                                       ┌──────────────────────────────────┴─────────────┐
                                       ▼                                                ▼
                         subscription "core/provisioning"           subscription "kafka/publish" …
                         own cursor · retries · DLQ · lease          own cursor · retries · DLQ · lease
```

## Domain model

**Tenant**: `id` (UUIDv7, so IDs sort by creation time), `slug` (a DNS label, unique among
tenants that are not deleted, immutable), `name`, optional `parent_id`, `status`, `plan`,
`labels`, `settings` (free-form JSON, optionally validated by a JSON Schema), feature and limit
overrides, and `version` for optimistic locking.

Tenant status follows a state machine:

```
create ─▶ provisioning ─fail─▶ failed
              │    ▲              │
              │    └────retry─────┘
              ▼ ok
           active ◀─resume── suspended
              │ └──suspend──────▲
              ▼ delete (from any live status)
          deleting ─▶ deleted
```

Without provisioners a tenant is `active` immediately and is `deleted` at once.

**Hierarchy.** A tenant may have a parent, which is set at creation and never changes. You
cannot create a child under a deleting or deleted parent, or delete a tenant that still has
live children (both checks lock the parent row, so they hold under concurrency). A child
created without a plan inherits its parent's plan. Tenant-scoped administrators (see [auth](auth.md)) reach their tenant and all of
its descendants.

**Plan**: an ID, a name, `features` (`map[string]bool`) and `limits` (`map[string]int64`).
A tenant's **entitlements** are its plan's features and limits (or those of a pinned plan
revision), plus add-ons and feature rollouts, with the tenant's own overrides applied on top
(see [plans and placement](plans.md)). A plan that live tenants still use cannot be deleted. With
`tenants.require_known_plans` set, tenants can only reference existing plans.

**Member**: an email, a role (from `tenants.member_roles`), and an optional `user_id` linking an
identity. A member without `user_id` is `invited`; setting it activates the member. The
`members` limit caps the number of members per tenant.

**Usage**: named counters per tenant (`api_calls`, `storage_gb`, …). `RecordUsage` adds a delta
atomically and refuses increments that would exceed the tenant's limit for that metric
(HTTP 429, plus a `tenant.quota_exceeded` event). Only active tenants can consume quota;
negative deltas are always allowed. Counters clamp at zero.

## Events

Every state change appends a domain event to the event log **in the same transaction** as the
change itself: a transactional outbox. A crash therefore never leaves a change without its event,
or an event without its change.

| Event | When |
|---|---|
| `tenant.created`, `tenant.updated`, `tenant.plan_changed` | create / update (plan changes emit both) |
| `tenant.provisioning`, `tenant.provisioned`, `tenant.provisioning_failed` | provisioning |
| `tenant.suspended`, `tenant.resumed` | suspension |
| `tenant.deleting`, `tenant.deleted`, `tenant.deprovisioning_failed` | deletion |
| `tenant.member_added`, `tenant.member_updated`, `tenant.member_removed` | members |
| `tenant.region_changed` | a [region move](plans.md#regions-and-data-residency) |
| `tenant.purged` | the data of a deleted tenant was [purged](privacy.md#purging-deleted-tenants) |
| `tenant.quota_exceeded`, `tenant.usage_threshold_reached`, `tenant.usage_period_closed` | usage |
| `tenant.action_scheduled`, `tenant.action_canceled`, `tenant.action_failed` | scheduled actions |
| `tenant.maintenance_started`, `tenant.maintenance_ended` | [maintenance windows](tenants.md#maintenance-windows) |
| `rollout.updated`, `rollout.deleted` | [feature rollouts](plans.md#feature-rollouts) |
| `plan.created`, `plan.updated`, `plan.deleted` | plans |
| `user.*`, `domain.*`, `apikey.*`, `sso.*`, `role.*`, `group.*`, `webhook.*`, `oauth_client.*`, `signing_key.*` | users and tenant configuration |

The complete list, with a JSON Schema for each type's `data`, is the
[event schema registry](event-schemas.md).

Events are CloudEvents 1.0 with the extension attributes `tenantid`, `actor` (who caused it:
`{authenticator}:{subject}`, `{authenticator}:{subject};impersonated-by={authenticator}:{subject}`
during [impersonation](users.md#impersonation), `plugin:<instance>`, `system:scheduler` or
`system`), `sequence`, and the W3C `traceparent`/`tracestate` of the request that caused them.
Tenant events carry the new tenant and the previous state in `data`.

### Ordering without gaps

Readers consume the log by sequence number ("everything after N"). A naive `bigserial` outbox
breaks this: transaction A takes sequence 10, transaction B takes 11 and commits first; a
reader sees 11, moves its cursor past 10, and never sees A's event. Tenarium takes a
transaction-scoped advisory lock right before drawing sequence numbers, so writers commit in
sequence order and no reader can observe a hole that is later filled. The lock covers only the
end of write transactions; Tenarium is a control plane, so its write rate is modest. The store
conformance suite (`internal/store/storetest`) checks this with concurrent writers against both
stores.

### Delivery

The dispatcher runs one worker per **subscription**. A subscription is a plugin's event
handler with a stable name (`{plugin-instance}/{name}`) and its own durable cursor. Delivery is:

- **At least once and ordered per subscription.** Handlers must be idempotent; use the event ID.
- **Isolated.** A failing subscriber retries with exponential backoff and jitter. After
  `MaxAttempts` the event goes to the **dead-letter queue** and the cursor moves on. Other
  subscribers are not affected. Dead letters can be inspected, replayed and discarded through
  the API or the UI.
- **Prompt.** Commits wake workers in the same process directly, and other replicas through
  PostgreSQL `LISTEN/NOTIFY`, so polling (`events.poll_interval`) is only a fallback.

- **Traceable.** Each event stores the W3C trace context of the request that caused it. A
  delivery attempt is its own span, *linked* to the producing span rather than parented by it,
  because delivery is asynchronous and may repeat (see [tracing](operations.md#tracing)).

A new subscription starts at the beginning of the log (it replays history) unless it sets
`StartAtEnd`. A time range of stored events can be redelivered to one subscription without
moving its cursor (`POST /v1/events/replay`, see
[replaying a time range](operations.md#replaying-a-time-range)).

### Provisioning is a subscription too

The core subscription `core/provisioning` reacts to `tenant.created`, `tenant.provisioning`
(retry) and `tenant.deleting`. It runs the provisioners in configuration order (each step is
retried a few times) and then marks the tenant `active`, or `failed` with the reason.
Deprovisioning runs in reverse order with the same per-step retries. A tenant is only reported
`deleted` once its resources are gone; if a step keeps failing, the tenant becomes `failed`
with the reason (`tenant.deprovisioning_failed`), and deleting it again retries. Failing rather
than retrying forever keeps one stuck tenant from blocking provisioning for everyone else. Because provisioning is driven by the outbox, a process
that dies halfway simply has the event redelivered, and the idempotent provisioners run again.

## Hooks

Hooks run synchronously before a change is stored, in priority order. `before_create` and
`before_update` hooks may modify the proposed tenant (for example to add default labels);
member add and update hooks may change the role and user ID. Other hooks can only allow or
reject. A hook rejects with `sdk.Reject(...)`, which the API returns as 422 with the reason.
After hooks run, Tenarium restores identity and lifecycle fields (ID, slug, parent, status,
version, timestamps) and validates the result again, so hooks cannot get around the state
machine.

Hooks run outside the transaction because they may be slow. The write that follows is guarded
by the version that was read, so a concurrent change makes the operation fail with a version
conflict rather than overwrite it.

## Running several replicas

All replicas serve the API. For event delivery, each subscription is guarded by a **lease** in
the database: one replica holds it and renews it every `lease_ttl/3`. If that replica stops,
another takes the lease within `lease_ttl` and continues from the shared cursor. A replica that
loses its lease (for example after a long GC pause) cancels its in-flight delivery, so two
replicas do not process the same subscription at the same time.

## Plugins

See [plugins](plugins/README.md). In short, a plugin implements `sdk.Plugin` and, during `Init`,
registers any of: event subscriptions, hooks, provisioners, HTTP routes, authenticators and
authorizers. Registrations are fixed at startup. A plugin whose `Init` fails stops startup, and
nothing it registered before failing is kept. Panics in plugin code are recovered and treated as
errors.

## Stores

`store.Store` has two implementations: `memory` for development and tests, and `postgres` for
production. Both pass the same conformance suite. The PostgreSQL store applies its embedded
migrations at startup under an advisory lock, so several replicas can start at once.

## Package map

| Package | Responsibility |
|---|---|
| `pkg/sdk` | Public plugin contract: types, interfaces, registry |
| `internal/tenant` | Domain services, validation, state machine, provisioning runner |
| `internal/events` | Dispatcher: cursors, leases, retries, DLQ, replay |
| `internal/store/{memory,postgres}` | Persistence and outbox |
| `internal/plugin` | Plugin loading, registrar, hook chain, scoping |
| `internal/authz` | Tenant-scope rule and authorizer combination |
| `internal/api` | HTTP handlers, authentication chain, idempotency, metrics |
| `internal/ui` | Embedded admin UI |
| `internal/identity` | Token signing keys, JWTs, OIDC discovery |
| `internal/sso` | Per-tenant OIDC and SAML sign-in |
| `internal/oidcprovider` | Tenarium as an OpenID provider (`/oauth`) |
| `internal/scim` | SCIM 2.0 service provider per tenant |
| `internal/webhooks` | Self-service tenant webhooks |
| `internal/eventschema` | JSON Schemas of every event type |
| `internal/secrets`, `internal/store/encrypted` | Envelope encryption of stored secrets |
| `internal/certs` | ACME certificates for platform and tenant hostnames |
| `internal/netguard` | SSRF guard for tenant-chosen URLs |
| `pkg/server` | Configuration and wiring |
