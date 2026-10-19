# grafana-tenant

Provisions one [Grafana](https://grafana.com/) organization per tenant through the
Grafana HTTP API. It can also mirror tenant members into the organization, set
organization quotas from plan limits, and create per-tenant data sources.

```yaml
plugins:
  - plugin: grafana-tenant
    config:
      url: http://grafana:3000
      username: admin                       # a Grafana server admin
      password: ${GRAFANA_ADMIN_PASSWORD}
      # token: ${GRAFANA_TOKEN}             # alternative to username/password, see "Authentication"
      timeout: 10s
      name_template: "tenant-{{.Slug}}"     # default
      on_deprovision: delete                # delete (default) | retain | keep
      remove_creator: true                  # drop the plugin's account from orgs once another admin exists
      sync_members: true
      create_users: false                   # create missing Grafana users for members
      role_map:                             # merged over the defaults below
        owner: Admin
        admin: Admin
        member: Editor
        billing: None
      default_role: Viewer                  # roles missing from role_map
      quota:                                # Grafana quota target -> entitlement limit
        dashboard: dashboards
        data_source: datasources
        org_user: seats
        alert_rule: alert_rules
        api_key: api_keys
      datasources:
        - name: Metrics
          type: prometheus
          url: "http://mimir/prometheus"
          access: proxy                     # default
          is_default: true
          json_data:
            httpHeaderName1: X-Scope-OrgID
          secure_json_data:
            httpHeaderValue1: "{{.Tenant.ID}}"
```

## Organization names

`name_template` is a Go `text/template` over the tenant (`.ID`, `.Slug`, `.Name`, ...),
executed with `missingkey=error`. The name is recomputed on deprovision and for member
events, so use only immutable fields (`ID`, `Slug`); the display name `.Name` can change
and would orphan the organization. The rendered name is cleaned up (control characters and
`/ \ ? # %` become `-`, whitespace runs collapse to one space). Names longer than 100
characters are shortened and suffixed with a hash of the tenant ID, so two tenants never
collide through truncation. A template that renders the same name for two different
tenants is rejected at startup.

## Ownership

Grafana organizations have no labels, so the plugin marks ownership in the
organization's **address**: `address1 = tenarium-tenant-id:<tenant id>` (other address
fields are preserved).

- An organization marked for another tenant is never adopted by Provision (it fails with
  a clear error) and never touched by Deprovision.
- An unmarked organization is adopted only when it is empty: no members other than the
  plugin's own account, no dashboards or folders and no data sources. That is what an
  interrupted Provision (created but not yet marked) leaves behind. Anything else is
  refused. If the plugin's account is not a member, emptiness is judged from quota usage
  (only with quotas enabled); otherwise the organization is treated as not empty.
- The main organization (ID 1) is never adopted or deleted.

The marker guards against accidental collisions. Grafana lets organization admins edit
their organization's name and address, so it is not a security boundary against a
malicious organization admin; if tenant admins are untrusted, map their roles to
`Editor` or lower.

## Deprovisioning

`on_deprovision`:

- `delete` (default): the organization is deleted with its dashboards, data sources,
  alert rules and memberships. Grafana users are platform-wide and are not deleted, even
  those created by `create_users`. Grafana content is usually rebuildable (dashboards as
  code), and deletion happens only after Tenarium's own deletion flow (including any grace
  period), so delete is the default; choose `retain` if dashboards are customer data you
  must keep.
- `retain`: the organization and its content stay, but ownership is released:
  `address1` becomes `tenarium-deleted-tenant-id:<id>`, `address2`
  `tenarium-deleted-at:<RFC3339>`, and the organization is renamed to
  `<name>-deleted-<unix>`, so a new tenant with the same slug gets a fresh organization.
  The marker is replaced before the rename; if the rename was interrupted, the next
  Deprovision finishes it, and Provision refuses the half-retained organization.
- `keep`: nothing is touched. The ownership marker remains, so a new tenant with the same
  name cannot adopt the organization.

Deprovision is idempotent; a missing organization counts as deprovisioned.

## Members (`sync_members`)

Subscribes to `tenant.member_added`, `tenant.member_updated` and `tenant.member_removed`
(subscription `members`). Tenarium roles map to Grafana roles (`Admin`, `Editor`,
`Viewer`, `None`) through `role_map`, merged over the defaults
`owner: Admin, admin: Admin, member: Editor`; other roles get `default_role` (`Viewer`).

- Added/updated members: the Grafana user is looked up by email
  (`GET /api/users/lookup`) and added to the organization or has its role updated. Without
  `create_users`, a member with no Grafana user is skipped (logged); a later
  `member_updated` adds them. With `create_users`, the user is created in the organization
  (`POST /api/admin/users`, login = email) with a random password nobody knows: users sign
  in through SSO (OAuth/SAML/LDAP/auth proxy matching by email) or reset their password.
- Email changes remove the old identity from the organization and add the new one.
- Removed or suspended members are removed from the organization. Only Grafana users
  matching the member's email are touched; users added in Grafana by other means are left
  alone, and the plugin's own account is never managed. Grafana refuses to remove or
  demote an organization's last admin; that is logged and not retried.
- Events for a tenant whose organization does not exist yet are retried while the tenant
  is provisioning (or failed), and ignored otherwise.

## Plugin account membership (`remove_creator`)

Grafana adds the account that creates an organization as its `Admin`. With
`remove_creator: true` the plugin removes itself once another admin exists (after
Provision and whenever a member is granted `Admin`). Grafana does not allow removing the
last admin, so the account stays until then. Org-scoped calls (data sources) need
membership, so the plugin temporarily re-joins when it has to update data sources and
leaves again afterwards. The plugin's account never needs to stay a member for org-level
admin APIs (users, quotas, rename, delete).

## Quota

`quota` maps Grafana organization quota targets (`dashboard`, `data_source`, `org_user`,
`api_key`, `alert_rule`) to entitlement limit names. The limit from
`Host.Entitlements` is applied with `PUT /api/orgs/{id}/quotas/{target}`; an absent
(unlimited) limit sets `-1`. Quotas are applied on Provision and re-applied on
`tenant.updated` and `tenant.plan_changed` (subscription `quota`). Changing a plan's
limits does not touch existing organizations until their tenant is updated or
re-provisioned.

Grafana enforces quotas only with quotas enabled: `[quota] enabled = true` in
`grafana.ini` (or `GF_QUOTA_ENABLED=true`). Otherwise Provision fails with a hint.

## Data sources

Each entry of `datasources` is created in every organization, or updated on
re-provision (matched by name). `url`, `database`, `user` and every string in
`json_data` and `secure_json_data` are `text/template`s over
`{Tenant, OrgID, OrgName}`, validated at startup. Typical use: a shared Mimir/Loki/Tempo
with the tenant ID as `X-Scope-OrgID`.

## Route

`GET /v1/plugins/{instance}/tenants/{tenant}` (tenant ID or slug) returns:

```json
{"org_name": "tenant-acme", "org_id": 7, "provisioned": true, "url": "http://grafana:3000/?orgId=7"}
```

`url` opens Grafana switched to the tenant's organization. `provisioned` is false (and
`org_id`/`url` empty) when the organization does not exist or is not marked for the
tenant. The caller needs `tenants:read` on the tenant; denied callers and unknown tenants
get `404`.

## Health

`Health` (used by `/readyz`) calls `GET /api/health` and then `GET /api/orgs?perpage=1`,
which verifies that the credentials have server admin rights.

## Authentication and required permissions

Organization management (`/api/orgs`, `/api/orgs/{id}/users`, quotas, address) and user
administration (`/api/users/lookup`, `/api/admin/users`) are **server admin** APIs. Use
`username`/`password` of a Grafana server admin (basic auth must be enabled, which is the
default: `[auth.basic] enabled = true`).

`token` is sent as `Authorization: Bearer <token>`. Grafana service account tokens and API
keys are scoped to one organization and cannot be server admins, so they **cannot**
create organizations or manage users; Provision and Health fail with 403. Use `token` only
when the bearer token maps to a server admin (e.g. JWT auth or an authenticating proxy in
front of Grafana that grants server admin).

Data source creation runs org-scoped calls with `X-Grafana-Org-Id`, which requires the
plugin's account to be a member of the organization (handled automatically, see
`remove_creator`).

## Tests

Unit tests use an in-memory fake Grafana. Integration tests run against a real Grafana:

```sh
docker run -d --name tenarium-test-grafana -p 47700:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=testpass123 -e GF_QUOTA_ENABLED=true grafana/grafana:11.3.0
TENARIUM_TEST_GRAFANA_URL=http://localhost:47700 \
TENARIUM_TEST_GRAFANA_USER=admin \
TENARIUM_TEST_GRAFANA_PASSWORD=testpass123 \
  go test ./plugins/grafanatenant/ -run Integration -v
```
