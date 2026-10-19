# hubspot

Mirrors tenants into HubSpot CRM as **companies** and, optionally, tenant members as
**contacts** associated with their tenant's company. Uses the HubSpot CRM REST API with a
private app access token.

## Setup in HubSpot

1. Create a company property (Settings → Properties → Company) with internal name
   `tenarium_tenant_id` (or set `tenant_id_property`), type single-line text, with
   **"Require unique values"** enabled. Companies are upserted by this property.
2. Create any other properties you map (e.g. `tenarium_plan`, `tenarium_status`).
3. Create a private app with scopes `crm.objects.companies.read/write` and, for members,
   `crm.objects.contacts.read/write`.

## Configuration

```yaml
plugins:
  - plugin: hubspot
    config:
      access_token: ${HUBSPOT_TOKEN}
      properties:
        name: "{{.Name}}"
        domain: '{{index .Labels "domain"}}'
        tenarium_plan: "{{.Plan}}"
        tenarium_status: "{{.Status}}"
      contact_properties:
        jobtitle: "{{.Member.Role}}"
      on_delete: archive
```

| Key | Type | Default | Description |
|---|---|---|---|
| `access_token` (required) | string | | Private app token. |
| `api_base` | URL | `https://api.hubapi.com` | |
| `timeout` | duration | `15s` | Per request. |
| `tenant_id_property` | string | `tenarium_tenant_id` | Unique company property holding the tenant ID; always set. |
| `properties` | map | `{name: "{{.Name}}"}` | Company property → template on the tenant. |
| `sync_members` | bool | `true` | Mirror members as associated contacts. |
| `contact_properties` | map | none | Contact property → template on `{Member, Tenant}`. `email` is always the member's email. |
| `on_delete` | enum | `archive` | `archive` the company of a deleted tenant, or `keep` it. |

Property names are HubSpot internal names (`^[a-z][a-z0-9_]*$`).

## Templates

Go `text/template` with `missingkey=error`, parsed at startup.

- Company templates get the tenant: `{{.ID}} {{.Slug}} {{.Name}} {{.Plan}} {{.Status}}
  {{.StatusReason}} {{.ParentID}} {{index .Labels "key"}} {{.CreatedAt}}`.
- Contact templates get `{{.Member.Email}} {{.Member.Role}} {{.Member.Status}}
  {{.Member.UserID}}` and `{{.Tenant.…}}`.

Empty results are **not sent**, so they never clear values maintained in HubSpot. A template
that fails at run time (e.g. an unknown field) fails the delivery, which is retried and then
dead-lettered.

## Events

| Event | Action |
|---|---|
| `tenant.created`, `tenant.updated`, `tenant.plan_changed`, `tenant.suspended`, `tenant.resumed` | Upsert the company (`POST /crm/v3/objects/companies/batch/upsert` by `tenant_id_property`). |
| `tenant.deleted` | `archive`: look the company up by tenant ID and archive it (`DELETE`); missing = done. |
| `tenant.member_added`, `tenant.member_updated` | Upsert the tenant's company, upsert the contact by email, and create the default contact→company association (`PUT /crm/v4/.../associations/default/...`). Skipped for unknown or deleted tenants and members without email. |
| `tenant.member_removed` | Remove the contact↔company association. The contact is never deleted. |

Tenant events use the subscription `sync`, member events `members`.

All writes are upserts or idempotent association calls, so redelivered events are harmless.
Every non-2xx response (including 429 rate limits, reported with `Retry-After`) is an error
and the delivery is retried with backoff.

## Health

`/readyz` lists one company, which checks the token and its company scope.
