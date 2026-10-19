# REST API

The full OpenAPI 3.1 description is served by every instance at `GET /openapi.yaml` (source:
[internal/api/openapi.yaml](https://github.com/AimTune/tenarium/blob/main/internal/api/openapi.yaml)). A test keeps it in sync with the
router. This page covers the conventions.

## Resources

| Path | Operations |
|---|---|
| `/v1/tenants` | list (filters: `status`, `plan`, `parent_id`, `label=k=v`, `include_deleted`), create |
| `/v1/tenants/{id}` | get, `PATCH`, `DELETE` (accepts an ID or a slug; `?force=true` skips the [deletion grace period](tenants.md#soft-deletion-and-restore)) |
| `/v1/tenants/{id}/suspend` · `/resume` · `/restore` · `/retry-provisioning` | lifecycle transitions |
| `/v1/tenants/{id}/schedule[/{action}]` | [scheduled actions](tenants.md#scheduled-actions-and-trials): list, schedule, cancel |
| `/v1/tenants/{id}/domains[/{hostname}[/verify]]`, `/v1/domains/resolve`, `/v1/domains/check` | [custom domains](tenants.md#custom-domains) |
| `/v1/tenants/{id}/domains/{hostname}/certificate` | status of the [managed certificate](tls.md) of a domain |
| `/v1/tenants/{id}/api-keys[/{key}]`, `/v1/api-keys[/{key}]` | [tenant and platform API keys](tenants.md#tenant-api-keys) |
| `/v1/tenants/{id}/webhooks[/...]` | [tenant webhooks](webhooks.md) and their delivery log |
| `/v1/tenants/{id}/sso` | the tenant's [SSO connection](auth.md#single-sign-on-per-tenant) (OIDC or SAML) |
| `/v1/tenants/{id}/roles[/{role}]` | [tenant roles](auth.md#tenant-roles-and-groups): list (built-in and custom), get, `PUT`, `DELETE` |
| `/v1/tenants/{id}/groups[/{group}[/members/{member}]]` | [groups](auth.md#tenant-roles-and-groups): CRUD, `PUT`/`DELETE` a member |
| `/v1/tenants/{id}/export` | [data export](privacy.md#exports) of the tenant |
| `/v1/audit`, `/v1/tenants/{id}/audit` | the [audit trail](tenants.md#audit-trail): newest first, filter by actor, type, time |
| `/v1/tenants/{id}/children` | direct children |
| `/v1/tenants/{id}/entitlements` | effective features and limits ([how they are computed](plans.md#how-entitlements-are-computed)) |
| `/v1/tenants/{id}/plan-revision` | `PUT {"revision": n}` pins the tenant to a [plan revision](plans.md#plan-revisions-and-grandfathering) (`0` unpins) |
| `/v1/tenants/{id}/move` | `POST {"region": "us"}` moves the tenant to another [region](plans.md#regions-and-data-residency) (platform only) |
| `/v1/tenants/{id}/clone` | [clone a tenant](tenants.md#cloning-tenants) |
| `/v1/tenants/{id}/maintenance` | `POST` starts, `DELETE` ends a [maintenance window](tenants.md#maintenance-windows) |
| `/v1/tenants/{id}/health` | the tenant's [health score](tenants.md#health-scores) |
| `/v1/tenant-templates[/{template}]` | [tenant templates](tenants.md#tenant-templates): list, get, `PUT`, `DELETE`; use with `"template"` on create |
| `/v1/tenants/{id}/members[/{member}]` | list, add/invite, change role or accept, remove |
| `/v1/tenants/{id}/usage[/{metric}[/history]]` | current counters and limits; `POST {"delta": n}` to record usage; past periods ([usage periods](tenants.md#usage-periods-soft-limits-and-billing-export)) |
| `/v1/tenants/{id}/scim/v2/...` | [SCIM 2.0](tenants.md#scim-provisioning) Users and Groups for identity providers |
| `/v1/plans[/{id}]`, `/v1/plans/{id}/revisions` | CRUD; recorded [revisions](plans.md#plan-revisions-and-grandfathering) |
| `/v1/rollouts[/{feature}]` | [feature rollouts](plans.md#feature-rollouts): list, get, `PUT`, `DELETE` (platform only) |
| `/v1/regions` | the configured regions (`tenants.regions`) |
| `/v1/actions` | every built-in action, for building [custom roles](auth.md#tenant-roles-and-groups) |
| `/v1/events` | the event log (`after`, `tenant_id`, `type` glob, `limit`) |
| `/v1/events/replay` | redeliver a [time range](operations.md#replaying-a-time-range) of events to one subscription |
| `/v1/event-schemas[/{type}[/{version}]]` | the [event schema registry](event-schemas.md) |
| `/v1/dead-letters[/{id}[/replay]]` | inspect, replay or discard failed deliveries |
| `/v1/plugins` | loaded plugin instances and their registrations |
| `/v1/admin/reload` | `POST` [reloads the configuration file](operations.md#reloading-the-configuration) (platform only, `config:reload`) |
| `/v1/me`, `/v1/me/memberships`, `/v1/me/password`, `/v1/me/mfa/...` | the authenticated caller, [two-factor authentication](users.md#two-factor-authentication) |
| `/v1/me/passkeys[/{passkey}]`, `/v1/me/passkeys/register/begin` · `/finish` | the caller's [passkeys](users.md#passkeys) |
| `/v1/me/sessions[/{session}]`, `/v1/users/{id}/sessions[/{session}]` | list and revoke a user's [sessions](users.md#sessions-and-devices) (`DELETE /v1/users/{id}/sessions` revokes all) |
| `/v1/auth/branding` | public [branding](tenants.md#branding) for sign-in pages (`?tenant=` or `?host=`; no auth) |
| `/v1/me/email`, `/v1/auth/email-change/confirm` | [email change](users.md#changing-the-email-address) with confirmation link |
| `/v1/auth/magic-link` | [sign-in links](users.md#sign-in-links) (`grant_type: magic_link` at `/v1/auth/token`) |
| `/v1/auth/social`, `/v1/auth/social/{provider}/start` · `/callback` | [social login](auth.md#social-login) (no auth) |
| `/v1/me/export`, `/v1/me/impersonation-consent` | the caller's [data export](privacy.md#exports), [impersonation consent](users.md#impersonation) |
| `/v1/users[/{id}]` and `/disable`, `/enable`, `/password`, `/invitation`, `/sessions`, `/mfa`, `/memberships` | user administration ([users](users.md)) |
| `/v1/users/{id}/export` · `/erase` · `/impersonate` | [export, erasure](privacy.md) and [impersonation](users.md#impersonation) |
| `/v1/oauth-clients[/{client}[/rotate-secret]]` | applications of the [OpenID provider](oidc-provider.md) (platform only) |
| `/v1/signing-keys`, `/rotate`, `/{kid}` | [token signing keys](auth.md#signing-keys) |
| `/v1/auth/token`, `/logout`, `/password-reset[/confirm]`, `/invitations/accept`, `/passkey/begin` · `/finish` | sign-in and account recovery (no auth, rate limited) |
| `/v1/auth/sso/start` · `/callback` · `/discover`, `/v1/auth/sso/saml/{tenant}/metadata` · `/acs` | [tenant SSO](auth.md#single-sign-on-per-tenant) (no auth) |
| `/oauth/authorize`, `/login`, `/consent`, `/token`, `/userinfo`, `/logout` | the [OpenID provider](oidc-provider.md) endpoints (no auth; `/oauth/login` and `/oauth/token` are rate limited) |
| `/.well-known/openid-configuration`, `/.well-known/jwks.json` | verify Tenarium tokens in your services |
| `/v1/plugins/{instance}/...`, `/v1/plugins/{instance}/public/...` | routes contributed by plugins (public ones without auth) |
| `/healthz`, `/readyz`, `/metrics`, `/openapi.yaml`, `/ui/` | operations (no auth) |

## Conventions

**Errors** always have this shape:

```json
{"error": {"code": "validation_failed", "message": "must be 1-200 characters", "field": "name"}}
```

| Status | Code |
|---|---|
| 400 | `reload_failed`, `validation_failed`, `invalid_json`, `invalid_body`, `invalid_idempotency_key`, `invalid_token`, `tenant_required`, `not_a_user`, `password_login_unavailable` |
| 401 | `unauthorized`, `invalid_credentials`, `mfa_required`, `invalid_otp`, `passkey_rejected` |
| 403 | `forbidden`, `sso_required`, `consent_required` (impersonation without a valid consent code) |
| 404 | `not_found` |
| 409 | `already_exists`, `invalid_transition`, `unknown_subscription`, `active_key` |
| 412 | `version_conflict` |
| 422 | `rejected` (a plugin hook refused), `idempotency_key_reused`, `verification_failed` (domain TXT record missing) |
| 429 | `quota_exceeded` (`field` holds the metric; `X-Quota-Limit` the limit), `account_locked`, `rate_limited` |
| 502 | `replay_failed` |
| 503 | `maintenance` (a tenant-scoped write during a [maintenance window](tenants.md#maintenance-windows); `Retry-After` is set) |

**Optimistic concurrency.** Tenants, plans and members carry a `version`, returned as
`ETag: "3"`. Send `If-Match: "3"` with `PATCH` to fail with 412 if the resource changed in the
meantime.

**Idempotency.** `POST` requests may carry `Idempotency-Key`. The first response (unless it is a
5xx) is stored for 24 hours per caller and path; retrying with the same key and body returns it
again with `Idempotent-Replayed: true`. Reusing a key with a different body returns 422.

**Pagination.** Lists return `{"items": [...], "next": "<cursor>"}`; pass `after=<cursor>` to
get the next page. `next` is absent on the last page.

**Partial updates.** In `PATCH /v1/tenants/{id}`, `labels`, `features`, `limits` and `add_ons`
replace the whole map or list, and `settings` is an
[RFC 7386 merge patch](https://www.rfc-editor.org/rfc/rfc7386) (`null` deletes a key). `region`
cannot be patched; use `POST /v1/tenants/{id}/move`. In `PATCH /v1/plans/{id}`,
`"grandfather": true` keeps the plan's current tenants on the old values (see
[plan revisions](plans.md#plan-revisions-and-grandfathering)).

**Request IDs.** Every response has `X-Request-ID` (your value is echoed back if you send one).
It appears in error logs.

## Example session

```sh
API=http://localhost:8080; AUTH="Authorization: Bearer $TENARIUM_API_KEY"

curl -sX POST $API/v1/plans -H "$AUTH" -d '{"id":"pro","name":"Pro","limits":{"members":50,"api_calls":100000}}'
curl -sX POST $API/v1/tenants -H "$AUTH" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"slug":"acme","name":"Acme","plan":"pro","labels":{"region":"eu"}}'
curl -sX POST $API/v1/tenants/acme/members -H "$AUTH" -d '{"email":"ada@acme.io","role":"owner"}'
curl -sX POST $API/v1/tenants/acme/usage/api_calls -H "$AUTH" -d '{"delta":1}'
curl -s "$API/v1/events?tenant_id=$(curl -s $API/v1/tenants/acme -H "$AUTH" | jq -r .id)" -H "$AUTH"
```
