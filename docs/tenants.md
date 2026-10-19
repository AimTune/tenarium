# Tenant lifecycle features

This page covers templates and cloning, scheduled actions and trials, maintenance windows,
soft deletion, custom domains, branding, tenant API keys, health scores,
usage periods and soft limits, SCIM provisioning and the audit trail. The basics (create,
update, suspend, plans, members) are in the
[README](https://github.com/AimTune/tenarium/blob/main/README.md) and the [API reference](api.md);
plans, add-ons, rollouts and regions in [plans and placement](plans.md); exports, erasure and
purging in [data protection](privacy.md).

## Tenant templates

A template presets new tenants: plan, add-ons, region, labels, settings, features, limits,
branding and custom roles. Platform callers manage them (`plans:write`; reading needs
`plans:read`):

```sh
curl -sX PUT $API/v1/tenant-templates/startup -H "$AUTH" -d '{
  "name": "Startup", "description": "Trial setup for small teams",
  "plan": "pro", "add_ons": ["extra-seats"], "region": "eu",
  "labels": {"segment": "smb"}, "settings": {"locale": "en"}, "limits": {"projects": 5},
  "branding": {"primary_color": "#1a2b3c"},
  "roles": [{"name": "billing-admin", "actions": ["usage:read", "tenants:read"]}]}'
curl -sX POST $API/v1/tenants -H "$AUTH" -d '{"slug":"acme","name":"Acme","template":"startup"}'
```

- The request wins: `plan`, `region`, `add_ons` and `branding` from the template apply only when
  the request leaves them out; `labels`, `features` and `limits` are merged with the request's
  entries winning; `settings` from the template are the base the request's settings are merged
  into (RFC 7386).
- A template is validated like a tenant when it is saved (plan and add-ons must exist, values
  must pass `tenants.settings_schema`). Its custom roles are created right after the tenant; if
  one fails, the tenant exists without it and the error names the role.
- Creating from a template that sets a plan, add-ons, features or limits needs `plans:write`,
  as if the caller had set them, and the caller must be allowed every action of the template's
  roles ([escalation prevention](auth.md#tenant-roles-and-groups)).
- `GET /v1/tenant-templates[/{id}]` reads templates, `DELETE` removes one. Tenants created from
  a template keep no link to it.

## Cloning tenants

```sh
curl -sX POST $API/v1/tenants/acme/clone -H "$AUTH" \
  -d '{"slug":"acme-staging","name":"Acme (staging)","members":true}'
```

The copy gets the source's plan, add-ons, region, labels, settings, features, limits, branding
and custom roles, and the label `tenarium.io/cloned-from: <source-id>`. With `"members": true`
the source's active members are added with their roles. Domains, SSO, API keys, webhooks,
groups, schedules and usage are not copied. `parent_id` places the copy under another tenant.
The copy is a new tenant: hooks run, `tenant.created` is emitted and provisioners run as for any
other.

The source must be live. The caller needs `tenants:read` on the source, `tenants:create` (on the
parent, if given), `plans:write` if the source has a plan, add-ons, features or limits,
`members:read` on the source to copy members, and every action of the copied custom roles.

## Scheduled actions and trials

Any of `suspend`, `resume`, `set_plan` and `delete` can be scheduled for a later time:

```sh
# end a trial in 14 days by moving to the free plan, suspend if still unpaid after 30
curl -sX POST $API/v1/tenants/acme/schedule -H "$AUTH" -d '{"action":"set_plan","plan":"free","after":"14d"}'
curl -sX POST $API/v1/tenants/acme/schedule -H "$AUTH" -d '{"action":"suspend","at":"2026-12-01T00:00:00Z","reason":"trial expired"}'
curl -s $API/v1/tenants/acme/schedule -H "$AUTH"                     # pending and finished actions
curl -sX DELETE $API/v1/tenants/acme/schedule/<action-id> -H "$AUTH" # cancel
```

`at` is an absolute time; `after` is relative (`36h`, `14d`). Actions can also be passed when
creating a tenant, which is how trials are usually set up:

```json
{"slug": "acme", "name": "Acme", "plan": "pro-trial",
 "schedule": [{"action": "set_plan", "plan": "free", "after": "14d"}]}
```

Scheduling needs the same permission as doing the action directly (`set_plan` needs
`tenants:update` and `plans:write`). Every instance runs the scheduler (`scheduler.interval`,
default 30s); each action is claimed by exactly one instance, and an action whose instance died
mid-run is picked up again after five minutes.

Executed actions emit the usual events (`tenant.suspended`, `tenant.plan_changed`, ...) with
actor `system:scheduler`, so hooks and plugins (e.g. Stripe) see them like any other change.
An action that cannot run (a hook rejects it, the plan no longer exists) ends as `failed`, with
the reason in `error` and a `tenant.action_failed` event. Actions of tenants deleted in the
meantime end as `canceled`. Scheduling emits `tenant.action_scheduled`, canceling
`tenant.action_canceled`.

## Maintenance windows

A maintenance window makes a tenant read-only for its own users while operators work on it,
without suspending it:

```sh
curl -sX POST $API/v1/tenants/acme/maintenance -H "$AUTH" \
  -d '{"message":"Moving to the EU data center","until":"2026-11-02T06:00:00Z"}'
curl -sX DELETE $API/v1/tenants/acme/maintenance -H "$AUTH"      # end it early or after an open-ended window
```

- While the window is active, **tenant-scoped callers** (members' tokens, tenant API keys,
  SCIM) get 503 `maintenance` with `Retry-After: 300` for every action on the tenant that is not
  a `*:read`. Reads keep working, and platform callers, who run the maintenance, are not
  restricted. Sign-in is not blocked.
- `until` is optional and must be in the future. Without it the window lasts until `DELETE`.
  When `until` passes, the restriction lifts on its own, but the tenant's `maintenance` field
  (`message`, `started_at`, `until`) stays until `DELETE`, and no event is emitted at that
  moment.
- Starting needs `tenants:suspend`, ending `tenants:resume` (platform roles only, by default).
  The tenant must be live. `message` is at most 500 characters.
- Events: `tenant.maintenance_started` and `tenant.maintenance_ended`, with the tenant before
  and after, so plugins can show a banner, pause jobs or start a migration.
- The tenant's [health score](#health-scores) drops by 10 during the window.

**Moving a tenant between cells or regions.** The usual workflow:

1. `POST /v1/tenants/{id}/maintenance`: the tenant's users can still read, but not write.
2. Move the data. Then switch where the tenant lives: `POST /v1/tenants/{id}/move` for a
   [region](plans.md#regions-and-data-residency) (subscribers of `tenant.region_changed` in the
   old and the new region react), or change the label the [gateway](gateway.md#cells) routes on
   (`PATCH /v1/tenants/{id}` with `{"labels": {"cell": "eu-2", ...}}`; labels replace the whole
   map).
3. `DELETE /v1/tenants/{id}/maintenance` once the new location serves the tenant.

Caches that hold the tenant (the `redis` plugin, the tenant middleware) update from the events;
mind their TTLs before ending the window.

## Soft deletion and restore

With `tenants.deletion_grace_period` set (e.g. `720h`), `DELETE /v1/tenants/{id}` no longer
deletes at once. Instead:

1. the tenant is suspended with reason `pending deletion` (its users and keys stop working);
2. a `delete` action is scheduled for the end of the grace period; the response has the
   `Tenarium-Deletion-At` header;
3. `POST /v1/tenants/{id}/restore` cancels the deletion and resumes the tenant, until then.

A tenant that was already suspended for another reason (say, billing) stays suspended with that
reason when restored. Plain `resume` refuses tenants pending deletion; use `restore`. Repeating
the delete request returns the scheduled deletion instead of scheduling another one.

`DELETE /v1/tenants/{id}?force=true` skips the grace period. It needs `tenants:purge`, which
only platform callers can hold. Without a grace period configured, deletion behaves as before:
immediate, or `deleting` while provisioners clean up.

A deleted tenant's record and its related data (members, usage, keys, domains, webhooks, SSO,
roles, groups) stay in the database until `tenants.purge_after` removes them; see
[purging deleted tenants](privacy.md#purging-deleted-tenants).

## Custom domains

Tenants can bring their own hostnames:

```sh
curl -sX POST $API/v1/tenants/acme/domains -H "$AUTH" -d '{"hostname":"app.acme.com"}'
# → {"domain": {...}, "instructions": {"type": "TXT", "name": "_tenarium-challenge.app.acme.com", "value": "tenarium-verification=..."}}
curl -sX POST $API/v1/tenants/acme/domains/app.acme.com/verify -H "$AUTH"   # after publishing the TXT record
curl -s "$API/v1/domains/resolve?host=app.acme.com" -H "$AUTH"              # → {"tenant_id", "slug", "hostname"}
```

- Hostnames are normalised (lowercase, no trailing dot or port) and unique across tenants.
  `tenants.reserved_domains` (your own domains) and their subdomains cannot be claimed.
- Verification looks up the TXT record; until it succeeds the domain resolves to nothing. A
  failed check answers 422 `verification_failed` with the record to publish.
- Tenarium can terminate TLS for verified domains itself, with certificates from Let's Encrypt
  (`server.tls.acme`, see [TLS and managed certificates](tls.md));
  `GET /v1/tenants/{id}/domains/{hostname}/certificate` then shows the certificate's issuer and
  expiry.
- With a separate TLS proxy instead, `GET /v1/domains/check?domain=` (no authentication) answers
  200 only for verified domains of live tenants. Point Caddy's on-demand TLS at it so
  certificates are only issued for real tenant domains:

  ```
  { on_demand_tls { ask http://tenarium:8080/v1/domains/check } }
  https:// { tls { on_demand } reverse_proxy app:3000 }
  ```

- Your application resolves the incoming `Host` with `/v1/domains/resolve` or, more cheaply,
  with the [tenant middleware](middleware.md), which caches the answer.
- Verified domains are also what a tenant's [single sign-on](auth.md#single-sign-on-per-tenant)
  connection may claim as email domains.

Events: `domain.added`, `domain.verified`, `domain.removed`. Permissions: `domains:read`,
`domains:write` (tenant owners and admins have both).

## Tenant API keys

Services of a tenant authenticate with keys scoped to that tenant:

```sh
curl -sX POST $API/v1/tenants/acme/api-keys -H "$AUTH" -d '{"name":"ci","roles":["member"],"expires_in":"2160h"}'
# → {"key": "tnr_...", ...}   the secret is shown only once
curl -s $API/v1/tenants/acme/api-keys -H "$AUTH"
curl -sX DELETE $API/v1/tenants/acme/api-keys/<id> -H "$AUTH"
```

Keys are sent as `Authorization: Bearer tnr_...`. Only a hash is stored. A key carries tenant
roles (the same role table as tenant members) and acts as a tenant-scoped principal, so it can
never reach other tenants or platform-only actions. A caller can only grant roles it holds
itself. Keys stop working immediately when revoked or expired, and while their tenant is not
active. Platform keys (`/v1/api-keys`) carry platform roles.


## Branding

Each tenant can carry branding for its sign-in pages, emails or application shell:

```sh
curl -sX PATCH $API/v1/tenants/acme -H "$AUTH" -d '{"branding": {
  "display_name": "Acme Cloud", "logo_url": "https://cdn.acme.com/logo.svg", "icon_url": "https://cdn.acme.com/icon.png",
  "primary_color": "#1a2b3c", "accent_color": "#f50", "support_email": "help@acme.com", "support_url": "https://acme.com/help"}}'
```

- URLs must be `https`, colors `#rgb` or `#rrggbb`, `support_email` a plain address. `PATCH`
  replaces the whole object; `{"branding": {}}` removes it. Branding can also be set at
  creation, from a [template](#tenant-templates), and is copied by [cloning](#cloning-tenants).
- Sign-in pages, which have no session yet, read it without authentication:

  ```sh
  curl -s "$API/v1/auth/branding?tenant=acme"           # ID or slug
  curl -s "$API/v1/auth/branding?host=app.acme.com"     # a verified custom domain
  # → {"tenant_id": "...", "slug": "acme", "display_name": "Acme Cloud", "logo_url": "...", ...}
  ```

  Answers are cacheable for 5 minutes and rate limited like the rest of `/v1/auth/`. Tenants
  that are not live or have no branding answer 404, so the endpoint reveals nothing a sign-in
  page would not show anyway.

## Health scores

`GET /v1/tenants/{id}/health` (`tenants:read`) scores a tenant for customer-success dashboards
and alerts: 100 minus the impact of each factor found, with a grade.

```json
{"tenant_id": "...", "score": 65, "grade": "at_risk",
 "factors": [{"name": "usage", "impact": 20, "detail": "at or near limits: api_calls 98000/100000, members 10/10"},
             {"name": "activity", "impact": 15, "detail": "no member signed in during the last 30 days"}]}
```

| Factor | Impact |
|---|---|
| `status` | suspended 40, provisioning failed 60, still provisioning 10, deleting or deleted 100 |
| `maintenance` | 10 during an active [maintenance window](#maintenance-windows) |
| `usage` | per metric at 90% or more of its limit: 10, at or over the limit: 20 (at most 40) |
| `quota_refusals` | 5 per refused usage increment in the last 7 days (at most 20) |
| `provisioning_failures` | 10 per provisioning or deprovisioning failure in the last 30 days (at most 30) |
| `dead_letters` | 5 per undelivered event of the tenant in the dead-letter queue (at most 20) |
| `members` / `activity` | no active members 10; otherwise, for tenants older than 30 days, no member signed in during the last 30 days 15 |

Grades: `healthy` (80 and above), `at_risk` (50 to 79), `critical` (below 50). The score is
computed on request from current data and is not stored or emitted as an event.

## Usage periods, soft limits and billing export

Limits come from plans and tenant overrides; how a metric behaves is configured per metric:

```yaml
usage:
  metrics:
    api_calls: {period: month, overage: allow, thresholds: [80, 100]}
    exports:   {period: day, thresholds: [90]}
    storage_gb: {}        # never resets, blocked at the limit (the default)
```

- **period** (`day`, `month`, `year`, `cycle`, empty = never): `day`, `month` and `year` reset
  at UTC calendar boundaries. `cycle` follows the tenant's own monthly billing cycle, starting at
  its `billing_anchor` (set with `PATCH /v1/tenants/{id}`, for example from the billing
  provider's subscription; platform callers only) or, without one, at its creation time. A cycle
  anchored on the 31st renews on the last day of shorter months. Each period has its own
  counter, so history is kept:
  `GET /v1/tenants/{id}/usage/{metric}/history`. `GET /v1/tenants/{id}/usage` shows the
  current period with `period` and `period_end`.
- **overage**: `block` (default) refuses increments beyond the limit with 429 and emits
  `tenant.quota_exceeded`. `allow` records them (a soft limit); the response and the usage list
  then show `overage: true`.
- **thresholds**: percentages of the limit. Crossing one emits
  `tenant.usage_threshold_reached` (with `percent`, `value`, `limit`), for example to email a
  warning at 80% or to start charging overage at 100%.
- When a period ends, the scheduler emits `tenant.usage_period_closed` once per counter with
  the final value. Billing exports consume it: the [stripe plugin](plugins/README.md#stripe) maps
  metrics to Stripe meters (`meters: {api_calls: api_requests}`) and reports each period
  exactly once; the `lago`, `openmeter` and `orb` plugins do the same for those services, and
  `segment` can forward it as a track event (see the
  [plugin list](plugins/README.md#plugin-catalog)). Periods without usage produce no event.

### Usage grants for remote services

A service far from Tenarium (a regional cell) can enforce a limit without a round trip per use:
it reserves a share, spends it locally, and gives back what it did not use.

```sh
curl -sX POST $API/v1/tenants/acme/usage/api_calls/grants -H "$AUTH" \
  -d '{"amount": 1000, "ttl_seconds": 300, "holder": "eu"}'
# → {"id": "01J…", "amount": 1000, "period": "2026-10", "expires_at": "…"}
curl -sX POST $API/v1/tenants/acme/usage/api_calls/grants/01J…/release -H "$AUTH" -d '{"used": 640}'
```

The reserved amount counts as usage at once (the limit is enforced, so `quota_exceeded` means
there is no room), which keeps limits exact across regions. Releasing gives back
`amount - used`; a grant that is not released before it expires, or whose period has ended,
stays counted in full (`410 grant_gone`), so a crashed cell can only over-count, never let a
tenant past its limit. Both calls need `usage:write`. In Go, `client.Usage.NewAllowance(tenant,
metric, chunk, ttl, holder)` does this for you: `Use(ctx, n)` counts locally and reserves the next
chunk when needed, and `Close` releases the rest.

## SCIM provisioning

Customers can let their identity provider (Okta, Entra ID, OneLogin, JumpCloud, ...) manage
who belongs to their tenant, using SCIM 2.0:

1. Create a tenant API key with the `admin` role (`POST /v1/tenants/acme/api-keys`).
2. In the identity provider, set the SCIM base URL to
   `https://<tenarium>/v1/tenants/acme/scim/v2` and the bearer token to the key.

Mapping:

| SCIM | Tenarium |
|---|---|
| User (`userName` = email) | a membership of the tenant; the user is created or invited if new |
| `active: false` | the membership is **suspended** (no sign-in to the tenant); `true` lifts it |
| DELETE User | the membership is removed (the platform-wide user stays) |
| `roles[0].value` | the member role (optional) |
| Group named after a role (`owner`, `admin`, ... or a [custom role](auth.md#tenant-roles-and-groups)) | that member role: the group's members hold it. Removing someone from a role group returns them to the default role (`member`) |
| any other Group | a tenant [group](auth.md#tenant-roles-and-groups), created on first push; its members get the group's roles, which a tenant admin assigns in Tenarium |
| `name`, `displayName` | the user name, but only for users whose email domain is a [verified domain](#custom-domains) of the tenant; users are platform-wide, so one customer's directory cannot rename another customer's people |

Supported: filtering users by `userName`, `emails.value` or `id` and groups by
`displayName` (`eq` only), `startIndex`/`count` paging, PatchOp (including Entra ID's
`"True"`/`"False"` strings), `excludedAttributes=members`. Not supported: bulk, sorting,
ETags, `externalId` storage (providers then match on `userName`). All changes go through the
normal member operations, so hooks, quotas (`members` limit) and `tenant.member_*` events
apply. Members can also be suspended directly with `PATCH /v1/tenants/{id}/members/{member}`
`{"active": false}`.
## Audit trail

Every change is an event with its actor (`core/token:<user>`, `core/key:<key>`,
`plugin:<instance>`, `system:scheduler`, ...), so the event log is the audit trail:

```sh
curl -s "$API/v1/audit?actor=core/token:<user-id>&type=tenant.*&since=2026-10-01T00:00:00Z" -H "$AUTH"
curl -s "$API/v1/tenants/acme/audit?limit=50" -H "$AUTH"
```

Results are newest first; pass `next` as `before` for older pages. `type` may be repeated and
accepts `prefix.*` patterns. Tenant-scoped callers (with `events:read`, which tenant owners and
admins have) see only their tenant's trail. To keep audit data longer than
`events.retention`, stream events to durable storage with a plugin (kafka, webhook, or `siem`
for Splunk, syslog and Elasticsearch/OpenSearch).

Changes made by support staff while [impersonating](users.md#impersonation) a user name both:
`core/token:<user>;impersonated-by=<authenticator>:<subject>`. The data schema of every event
type is published in the [event schema registry](event-schemas.md).
