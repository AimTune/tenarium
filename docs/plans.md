# Plans and placement

A plan is an ID, a name, `features` (`map[string]bool`) and `limits` (`map[string]int64`). This
page covers what is layered on top: plan revisions and grandfathering, add-ons, feature rollouts,
and regions for data residency. Plan CRUD itself is in the [API reference](api.md).

## How entitlements are computed

`GET /v1/tenants/{id}/entitlements` returns a tenant's effective features and limits. Plugins get
the same through `Host().Entitlements`. They are resolved in this order, later steps winning:

1. the tenant's **plan**, or the **plan revision** it is pinned to;
2. its **add-ons**: features are OR-ed in; a limit that the base plan sets is raised by the
   add-on's value (a limit the base plan leaves unset stays unlimited);
3. enabled **feature rollouts** the tenant falls into (they can only turn features on);
4. the tenant's own `features` and `limits` overrides, which always win.

Plans, revisions and add-ons that no longer exist are skipped.

```json
{"tenant_id": "0192...", "plan": "pro", "plan_revision": 3, "add_ons": ["extra-seats"],
 "features": {"sso": true, "audit_export": true}, "limits": {"members": 60, "api_calls": 100000}}
```

## Plan revisions and grandfathering

Every create and update of a plan records a **revision** (its `version` at that time):

```sh
curl -s $API/v1/plans/pro/revisions -H "$AUTH"       # newest first
```

A tenant follows the current plan unless it is **pinned** to a revision. To raise prices or cut
limits for new customers only, update the plan with `grandfather`:

```sh
curl -sX PATCH $API/v1/plans/pro -H "$AUTH" -d '{"limits":{"members":25},"grandfather":true}'
```

Before the change is stored, every live tenant on `pro` that is not pinned yet is pinned to the
current revision (one `tenant.updated` event each), so it keeps the old values. New tenants get
the new ones. Migrate a tenant later, or pin one by hand:

```sh
curl -sX PUT $API/v1/tenants/acme/plan-revision -H "$AUTH" -d '{"revision":0}'   # follow the current plan again
curl -sX PUT $API/v1/tenants/acme/plan-revision -H "$AUTH" -d '{"revision":2}'   # pin to revision 2
```

- Pinning needs `tenants:update` and `plans:write` (platform only). The revision must exist for
  the tenant's plan.
- Changing a tenant's plan resets the pin: a new plan starts on its current revision.
- The pinned revision is the tenant's `plan_revision` field and is part of `tenant.*` events,
  so billing plugins can see it.

## Add-ons

Add-ons are other plans stacked on the tenant's plan, for example a "more seats" or "audit log"
package sold separately:

```sh
curl -sX POST $API/v1/plans -H "$AUTH" -d '{"id":"extra-seats","name":"10 extra seats","limits":{"members":10}}'
curl -sX PATCH $API/v1/tenants/acme -H "$AUTH" -d '{"add_ons":["extra-seats"]}'
```

- `add_ons` holds up to 20 plan IDs. Each must be a defined plan, cannot be the tenant's own
  plan and cannot appear twice. `PATCH` replaces the whole list.
- Setting add-ons needs `plans:write` (platform only), like changing the plan.
- Add-ons are plain plans: they can be updated (and grandfathering applies to tenants that have
  them as their base plan only).

## Feature rollouts

A rollout turns a feature on gradually, independently of plans:

```sh
curl -sX PUT $API/v1/rollouts/new-editor -H "$AUTH" -d '{
  "enabled": true, "percentage": 10,
  "plans": ["pro", "enterprise"], "regions": ["eu"], "labels": {"beta": "yes"},
  "include": ["<tenant-id>"], "exclude": ["<tenant-id>"]}'
curl -s $API/v1/rollouts -H "$AUTH"
curl -sX DELETE $API/v1/rollouts/new-editor -H "$AUTH"
```

- A tenant gets the feature when the rollout is `enabled`, it is not in `exclude`, and it is
  either in `include` or matches every cohort filter that is set (`plans`, `regions`, `labels`)
  and falls within `percentage` (0-100).
- The percentage uses a stable hash of feature and tenant ID: raising 10 to 20 keeps the first
  10% and adds more, and different features pick different tenants first.
- `"enabled": false` is the kill switch. A tenant's own `features` override always wins, so
  `{"features": {"new-editor": false}}` opts a tenant out.
- `include` and `exclude` together hold at most 1000 tenant IDs, and a tenant cannot be in
  both.
- Rollouts name tenants, so even reading them needs `plans:write` (platform only).
- Changes emit `rollout.updated` and `rollout.deleted` (platform events without a tenant).
  The `redis` plugin's tenant cache refreshes every tenant on them, and refreshes the tenants
  using a plan (as base plan or add-on) on `plan.updated` and `plan.deleted`.

## Regions and data residency

Each tenant can be placed in a region, which plugins and your own services use to keep its data
in that region:

```yaml
tenants:
  regions: [eu, us]
  default_region: eu
```

- `region` is set at creation (`POST /v1/tenants` with `"region": "us"`). Without one, a child
  tenant takes its parent's region, then `default_region` applies. With `regions` configured,
  a new tenant must end up in one of them, otherwise the request fails. Without `regions`, any
  lowercase identifier is accepted. `default_region` must be one of `regions`.
- `GET /v1/regions` lists the configured regions (`plans:read`, so tenant callers can read it).
- Tenants created before `regions` was configured may have no region; they keep working, and
  moving them requires a region from the list.
- `region` cannot be changed with `PATCH`. Hooks cannot change it either.

**Region-scoped plugins.** A plugin instance with `scope.regions` only provisions, hooks and
receives events for tenants in those regions, so you can configure one provisioner per region:

```yaml
plugins:
  - plugin: postgres-tenant
    name: pg-eu
    scope: {regions: [eu]}
    config: {dsn: "postgres://...@db.eu.internal/app"}
  - plugin: postgres-tenant
    name: pg-us
    scope: {regions: [us]}
    config: {dsn: "postgres://...@db.us.internal/app"}
```

**Moving a tenant.** `POST /v1/tenants/{id}/move` with `{"region": "us"}` changes the region and
emits `tenant.region_changed`, whose `data.tenant.region` is the new region and
`data.previous.region` the old one.

```sh
curl -sX POST $API/v1/tenants/acme/move -H "$AUTH" -d '{"region":"us"}'
```

- It needs `tenants:move`, which is platform-only. The tenant must be live and not already in
  that region.
- **Tenarium only records the placement.** It does not copy data, re-run provisioning or
  deprovision the old region. Whoever moves the data (a migration job, or a plugin subscribed to
  `tenant.region_changed`) typically opens a [maintenance window](tenants.md#maintenance-windows),
  copies, and ends it.
- `tenant.region_changed` reaches plugin instances scoped to the old **or** the new region
  (and unscoped ones): the new region's instance can provision or copy, the old region's
  instance can clean up. Provisioners are not run by the move (`retry-provisioning` only
  applies to `failed` tenants), so a plugin that should follow moves must subscribe to the
  event. Later events of the tenant reach only the new region's instances.

See [multi-region deployments](multi-region.md) for running Tenarium itself in several regions.
