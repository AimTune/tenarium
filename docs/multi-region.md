# Multi-region deployments

Status: **design document**. The first section describes what Tenarium supports today; the rest
is a recommended architecture and the work it would need. Items marked *not implemented* do not
exist in the code yet.

Two things are easy to mix up, so keep them apart:

- the **control plane** is Tenarium itself: tenants, plans, users, memberships, keys, the event
  log, and the plugins that react to it;
- the **data plane** is your application and the per-tenant resources Tenarium provisions
  (databases, buckets, namespaces, topics). It serves the tenants' traffic.

"Multi-region" can mean data residency (a tenant's data stays in its region), latency (serve
users close to them) or availability (survive the loss of a region). Tenarium today covers the
first well for the data plane, the second for reads, and the third only partially.

## What works today

**A region per tenant.** `tenants.regions` lists the allowed regions; a tenant gets one at
creation (explicitly, from its parent, or `tenants.default_region`) and keeps it until it is
moved. Rollouts can target regions, and `GET /v1/regions` lists them. See
[regions](plans.md#regions-and-data-residency).

**Region-scoped plugins.** A plugin instance with `scope.regions` provisions, hooks and receives
events only for tenants of those regions. One instance per region of `postgres-tenant`,
`s3-tenant`, `kubernetes-tenant` and so on places each tenant's data-plane resources in its
region, and one instance per region of `kafka`, `nats` or `webhook` feeds each region's own
consumers.

**Region moves as events.** `POST /v1/tenants/{id}/move` (platform only, `tenants:move`) changes
the region and emits `tenant.region_changed` with the old and the new region. Tenarium only
records the placement; copying the data is up to a subscriber. The event reaches plugin instances
scoped to the old or the new region and unscoped ones. A [maintenance window](tenants.md#maintenance-windows)
keeps the tenant read-only for its own users while the data moves.

**PostgreSQL as the single source of truth.** Every replica, wherever it runs, reads and writes
one PostgreSQL database. State changes and their events are written in one transaction
(outbox), and an advisory lock around sequence allocation gives the event log one global,
gap-free order. Replicas learn about new events through `LISTEN/NOTIFY` and fall back to polling.

**Leases for replicas.** Each event subscription is processed by one replica at a time under a
lease in the database (`events.lease_ttl`). If the holder dies, another replica takes over within
the TTL from the shared cursor; `tests/chaos` checks that nothing is skipped (see
[testing](testing.md#chaos-and-failover-tests)). The scheduler claims each action on one replica,
ACME state and token signing keys live in the database, and idempotency keys are stored there
too, so replicas are interchangeable.

**Offline verification in every region.** Tenarium access tokens are ES256 JWTs; services in any
region verify them against `/.well-known/jwks.json` without calling Tenarium on each request.
The `redis` plugin's tenant cache and the [tenant middleware](middleware.md) cache keep tenant
status and entitlements close to the application.

Put together, the topology that works today is **one write region, many serving regions**:

```
                 ┌──────────── home region ────────────┐
                 │ PostgreSQL primary (+ standby)      │
                 │ Tenarium replicas                   │
                 └───────▲───────────────▲─────────────┘
              SQL (WAN)  │               │  SQL (WAN)
   ┌──────── eu ─────────┴──┐       ┌────┴──────── us ───────────┐
   │ Tenarium replicas      │       │ Tenarium replicas          │
   │ app + tenant DBs (eu)  │       │ app + tenant DBs (us)      │
   │ redis cache, broker    │       │ redis cache, broker        │
   └────────────────────────┘       └────────────────────────────┘
```

Its limits, honestly:

- **Writes are not regional.** A replica in a remote region pays the round trip to the primary
  for every statement of every write transaction. The event advisory lock is held until commit,
  so cross-region latency also caps the control plane's write throughput. Tenarium is a control
  plane with a modest write rate, so this is often acceptable, but usage recording at high rates
  from far away is not.
- **Read replicas serve lists only.** `store.read_dsn` sends the list queries (tenants, users, the
  event log, the audit trail) to a replica, which may lag by its replication delay; single-object
  reads, writes, quota checks and event delivery stay on the primary.
- **Losing the home region stops the control plane** until a standby is promoted, and the RPO is
  the replication lag of that standby. Data planes keep serving if they verify tokens offline and
  use cached tenant state, but nothing can be created, changed or provisioned meanwhile.
- **Lease affinity.** With `events.region` set on each replica, a subscription of a plugin scoped
  to `eu` runs on a replica in `eu` whenever one is up: such a replica takes the lease over from
  one elsewhere (a short overlap can deliver a few events twice, which the at-least-once
  contract allows). Without a replica in the region, any replica runs it.
- **Control-plane data is not partitioned.** User emails and names, member lists, settings,
  audit events and the tenant snapshots inside events live in the one database, whatever the
  tenant's region. If regulations require that this metadata stays in the region too, run
  separate deployments (below).
- **Rate limits** are counted per replica by default; `auth.rate_limit_shared: true` counts them
  in the database so the limit holds across replicas (one extra write per sign-in request).

## Recommended architecture: regional cells with a global control plane

```
                       ┌──────────── global control plane ─────────────┐
                       │ Tenarium + PostgreSQL primary                 │
   tenant → region ───▶│ tenants, plans, users, memberships, billing   │
   (edge routing)      │ event log (global order)                      │
                       └──────┬───────────────────────────┬────────────┘
                 events (eu)  │                           │  events (us)
              kafka/nats, scoped to eu            kafka/nats, scoped to us
                       ┌──────▼──────── cell eu ─┐ ┌──────▼──────── cell us ─┐
                       │ broker (regional)       │ │ broker (regional)       │
                       │ provisioners (eu)       │ │ provisioners (us)       │
                       │ app, tenant data (eu)   │ │ app, tenant data (us)   │
                       │ tenant cache, JWKS      │ │ tenant cache, JWKS      │
                       └─────────────────────────┘ └─────────────────────────┘
```

**Cells.** Each region is a self-contained cell: the application, the tenants' data stores, a
regional broker and cache, and Tenarium replicas running that region's scoped plugins. A cell
serves its tenants' traffic without calling another region on the request path.

**Global control plane.** One Tenarium deployment owns the tenant registry, plans, users and
memberships, the routing table (tenant → region) and billing. Its PostgreSQL primary runs in one
region with a synchronous standby in another zone and an asynchronous replica in a second
region for disaster recovery.

**Data placement.**

| Data | Lives in | Notes |
|---|---|---|
| tenant data (application databases, objects, queues) | the tenant's cell | provisioned by region-scoped plugins |
| tenant registry, plans, users, memberships, keys | control plane | small, changes rarely |
| event log | control plane, replicated to cells through brokers | keep `events.retention` short, archive per region if needed |
| usage counters | control plane | see quotas below |
| caches (tenant state, JWKS) | every cell | rebuilt from events |

**Event replication.** One broker instance per region, scoped to that region (`kafka` with
`scope.regions: [eu]` to the EU cluster, and so on), plus an unscoped one for global consumers.
Records are keyed by tenant ID, so each tenant's events stay ordered within the cell. Delivery is
at least once; consumers deduplicate on the event ID. If a cell's broker is unreachable, its
subscription retries with backoff while the other regions' subscriptions carry on; once the
retries are exhausted, events go to the dead-letter queue and must be replayed
(`/v1/dead-letters`). Alert on dead letters and subscription lag per region.

**Routing.** The edge maps a request to a cell before it reaches the application: by custom
domain (`/v1/domains/resolve`, cached), by tenant slug in the hostname, or by the `tid` claim of
the token. Tenant access tokens carry the tenant's region in a `region` claim, and
`/v1/domains/resolve` returns it, so the edge can route without another lookup; for slugs, use the
cached tenant (`GET /v1/tenants/{id}`, the `redis` cache).

**Failover.**

- *A cell is lost:* its tenants are down unless their data is replicated to another region by
  the data stores themselves. Moving them (`/move`) only helps once the data exists elsewhere.
  Tenarium's part is to record the new region and drive provisioning there.
- *The control-plane region is lost:* promote the cross-region replica and point the Tenarium
  replicas at it. Lost transactions are at most the replication lag, and their events are lost
  with them (state and events stay consistent because they share a transaction). Subscribers may
  get some events again from older cursors, which the at-least-once contract already covers.
  Cells keep serving existing tenants meanwhile.
- *A replica is lost:* nothing to do; leases move within `events.lease_ttl`.

**Consistency of quotas.** `POST /v1/tenants/{id}/usage/{metric}` is an atomic update of one row
in the control plane, so limits are exact, at the price of a round trip to the control-plane
region per increment. Choose per metric:

| Strategy | Enforcement | Cost |
|---|---|---|
| synchronous, central (today) | exact | one WAN round trip per increment; fine for rare events (members, projects, seats) |
| batched deltas from the cell, `overage: allow` | soft: the cell aggregates locally and sends one delta every few seconds; overshoot is bounded by the batch window | low; works today, the batching is in your application |
| regional allowances (usage grants) | exact: a cell reserves a share of the limit, spends it locally and returns what it did not use; a share that is not released counts as used | one round trip per chunk; `client.Allowance` in Go |

Use thresholds (`tenant.usage_threshold_reached`) and period-closed events for billing; they are
computed centrally whatever the strategy.

**Trade-offs.**

- *Versus one region:* cells give residency and latency for the data plane, at the cost of
  running N copies of the data-plane stack and a WAN dependency for control-plane writes.
- *Versus fully independent deployments per region:* a global control plane keeps one identity
  per user across regions, one plan catalog and one billing view. Independent deployments
  (one Tenarium with its own database per jurisdiction) give complete isolation of control-plane
  data and work today, but a person in two regions has two accounts, and plans, reporting and
  billing must be merged outside Tenarium.
- *Versus multi-master databases:* Tenarium's gap-free event ordering relies on one
  transactional database drawing sequence numbers under a lock. Multi-master PostgreSQL variants
  or distributed SQL would break that guarantee or need a different outbox design, so they are
  not supported.

## What Tenarium would need

| Step | Status | Work |
|---|---|---|
| Region per tenant, regional rollouts, region-scoped plugins | done | |
| Region moves recorded and announced (`tenant.region_changed`) | done | |
| Per-region event fan-out | done | scoped broker plugins; consumers dedupe on event ID |
| Offline token verification, cached tenant state | done | JWKS, `redis` cache, tenant middleware |
| Lease affinity | done | `events.region` per replica; subscriptions of region-scoped plugins run on a replica in their region when one is up |
| Read replicas | done (lists) | `store.read_dsn` for list queries; single reads and writes stay on the primary |
| Region in routing data | done | `region` claim in tenant access tokens and in `/v1/domains/resolve` |
| Move building blocks | done | maintenance windows (tenant read-only for its users), `tenant.region_changed` delivered to instances scoped to the old and the new region |
| Move orchestration | done | `POST /v1/tenants/{id}/move` with `reprovision: true`: maintenance window, provisioning in the new region, window closed on success; data copy stays with the data stores or the old region's plugins |
| Regional quota allowances | done | usage grants (`POST /v1/tenants/{id}/usage/{metric}/grants`, release with what was used) and the Go client's `Allowance`, which spends grants locally |
| Shared rate limiting | done | `auth.rate_limit_shared` counts in the database |
| Control-plane data residency | *not implemented*, no plan | partitioning users, members and events by region needs per-region stores and a global directory; until then, use independent deployments per jurisdiction |
| Global edge routing, data-store replication | outside Tenarium | DNS or anycast routing to cells; replication of tenant databases and buckets by the stores themselves |
