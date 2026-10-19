# salesforce

Mirrors tenants into Salesforce as records of an sObject (`Account` by default), upserted
through the REST API by an external ID field holding the tenant ID.

## Setup in Salesforce

1. On the object (Account), create a text field such as `Tenarium_Tenant_Id__c` and mark it
   **External ID** (and **Unique**). Create any other fields you map.
2. Create a connected app (or External Client App) with OAuth scope `api` and either:
   - **Client credentials flow**: enable it and set a "Run As" integration user; or
   - **JWT bearer flow**: upload the certificate of an RSA key pair, pre-authorize the
     integration user (admin-approved users / permission set).

## Configuration

```yaml
plugins:
  - plugin: salesforce
    config:
      login_url: https://login.salesforce.com    # https://test.salesforce.com for sandboxes, or My Domain
      auth:
        flow: jwt_bearer                         # or client_credentials
        client_id: ${SF_CLIENT_ID}
        username: integration@acme.com
        private_key_file: /etc/tenarium/salesforce.key
        # flow: client_credentials
        # client_secret: ${SF_CLIENT_SECRET}
      fields:
        Name: "{{.Name}}"
        Tenarium_Slug__c: "{{.Slug}}"
        Tenarium_Plan__c: "{{.Plan}}"
        Tenarium_Status__c: "{{.Status}}"
        Website: '{{index .Labels "website"}}'
      on_delete: update
      deleted_fields:
        Tenarium_Status__c: deleted
```

| Key | Type | Default | Description |
|---|---|---|---|
| `login_url` | URL | `https://login.salesforce.com` | Authorization server; the token URL is `<login_url>/services/oauth2/token` and it is the JWT audience. |
| `instance_url` | URL | from the token response | API host override. |
| `api_version` | string | `v62.0` | REST API version. |
| `auth.flow` (required) | enum | | `client_credentials` or `jwt_bearer`. |
| `auth.client_id` (required) | string | | Connected app consumer key. |
| `auth.client_secret` | string | | Consumer secret (`client_credentials`). |
| `auth.username` | string | | Integration user (`jwt_bearer`). |
| `auth.private_key` / `auth.private_key_file` | PEM | | Unencrypted RSA key, PKCS#1 or PKCS#8 (`jwt_bearer`, exactly one). |
| `external_id_field` | string | `Tenarium_Tenant_Id__c` | External ID field (`..__c`) set to the tenant ID. |
| `sobject` | string | `Account` | Object API name. |
| `fields` | map | `{Name: "{{.Name}}"}` | Field API name → template on the tenant. |
| `on_delete` | enum | `keep` | `keep`, `delete` or `update`. |
| `deleted_fields` | map | | Required for `update`: templates applied over `fields` for deleted tenants. |
| `token_ttl` | duration | `1h` | How long an access token is reused (min `1m`). Keep it below the session timeout. |
| `timeout` | duration | `15s` | Per request. |

## Templates

Go `text/template` with `missingkey=error`, executed against the tenant: `{{.ID}} {{.Slug}}
{{.Name}} {{.Plan}} {{.Status}} {{.StatusReason}} {{.ParentID}} {{index .Labels "key"}}
{{.CreatedAt}}`. Templates are parsed at startup. Empty results are **not sent**, so they never
clear values maintained in Salesforce. A template that fails at run time fails the delivery
(retried, then dead-lettered).

## Events (subscription `sync`)

| Event | Action |
|---|---|
| `tenant.created`, `tenant.updated`, `tenant.plan_changed`, `tenant.suspended`, `tenant.resumed` | `PATCH /services/data/<ver>/sobjects/<sobject>/<external_id_field>/<tenant id>` with the rendered fields (creates or updates). |
| `tenant.deleted` | `keep`: nothing. `delete`: `DELETE` the same URL (404 = done). `update`: upsert with `fields` + `deleted_fields`. |

Upserts by external ID are idempotent, so redelivered events converge on the same record.
Salesforce errors (`[{errorCode, message, fields}]`) are returned as delivery errors and retried.

## Authentication details

- **Client credentials**: `grant_type=client_credentials` with `client_id`/`client_secret` in
  the request body.
- **JWT bearer**: an RS256 assertion with `iss` = client ID, `sub` = username,
  `aud` = `login_url`, expiring after 3 minutes, exchanged with
  `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`.
- Salesforce token responses carry no `expires_in`, so a token is reused for `token_ttl`. If the
  API answers 401 (session expired or revoked), a new token is fetched and the request retried
  once.
- The API host is the `instance_url` returned with the token unless `instance_url` is set.

## Health

`/readyz` fetches `/services/data/<ver>/limits`, which checks authentication and API access.
