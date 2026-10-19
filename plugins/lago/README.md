# lago

Exports tenant usage to [Lago](https://getlago.com) for usage-based billing and, optionally,
keeps Lago customers in step with tenants. The plugin talks to the Lago REST API directly
(Lago Cloud or self-hosted).

## What it does

- **Usage (subscription `meters`)**: when a usage period ends, Tenarium emits
  `tenant.usage_period_closed` with the period's final value. For every metric mapped in
  `metrics`, the plugin sends one Lago event (`POST /api/v1/events`) for the mapped billable
  metric code. Only period totals are exported; real-time increments and threshold events are
  not.
- **Customers (subscription `customers`, with `sync_customers: true`)**: `tenant.created` and
  `tenant.updated` (only when the name or slug changed) create or update the Lago customer
  (`POST /api/v1/customers`, which Lago upserts by `external_id`).

## Configuration

```yaml
plugins:
  - plugin: lago
    config:
      api_key: ${LAGO_API_KEY}
      api_url: https://api.getlago.com      # https://api.eu.getlago.com, or self-hosted
      metrics:
        api_calls: api_calls                # Tenarium metric: Lago billable metric code
        storage_gb: storage
      customer_id_template: "{{.ID}}"
      subscription_id_template: "sub-{{.Slug}}"
      sync_customers: true
```

| Key | Type | Default | Description |
|---|---|---|---|
| `api_key` | string | (required) | Lago API key, sent as `Authorization: Bearer`. |
| `api_url` | string | `https://api.getlago.com` | Lago API base URL (absolute http(s)). |
| `timeout` | duration | `10s` | Timeout per API request. |
| `metrics` | map | (required, at least one) | Tenarium usage metric to Lago billable metric code. Other metrics are ignored. |
| `customer_id_template` | template | `{{.ID}}` | Renders the Lago `external_customer_id` (and the customer's `external_id` for customer sync). |
| `subscription_id_template` | template | (none) | If set, usage events carry `external_subscription_id` rendered from this template instead of `external_customer_id`. |
| `sync_customers` | bool | `false` | Create/update Lago customers from tenant events. |

## Usage events

Each closed period of a mapped metric becomes:

```json
{"event": {
  "transaction_id": "tenarium-<tenant_id>-<metric>-<period>",
  "external_customer_id": "<customer_id_template>",
  "code": "<billable metric code>",
  "timestamp": 1793491199,
  "properties": {"value": 1234}
}}
```

- `timestamp` is the period end minus one second (Unix seconds), so the usage lands in the
  billing period it belongs to.
- The value is in `properties.value`: create sum billable metrics with `field_name: value`
  (count aggregations work without it, but count events, not units).
- With `subscription_id_template`, `external_subscription_id` is sent instead of
  `external_customer_id`. Recent Lago versions attach events to subscriptions, so setting it
  is recommended when a customer has more than one subscription.
- Events with value `0`, without a period end, or for unmapped metrics are skipped.

## Idempotency

Event handlers are at-least-once. The `transaction_id` is the same for every delivery of a
period, so Lago never bills it twice. A repeated `transaction_id` is answered by Lago with
`422` and `error_details.transaction_id: ["value_already_exist"]`; the plugin treats that as
success. Any other non-2xx response or network error is returned so the event is retried (and
dead-lettered if it keeps failing).

Customer sync reads the customer first (`GET /api/v1/customers/{external_id}`) and sends its
existing metadata entries back with their IDs, so the `tenarium_tenant_id` and `tenarium_slug`
entries are updated in place and metadata added in Lago is kept.

## Template data

Templates are Go `text/template`s with `missingkey=error`, executed against the tenant:
`{{.ID}}`, `{{.Slug}}`, `{{.Name}}`, `{{.Plan}}`, `{{.ParentID}}`, `{{index .Labels "x"}}`
(or `{{.Labels.x}}`, which fails when the label is missing). The result is trimmed and must not
be empty, otherwise the event fails (and is retried / dead-lettered). Unknown fields are
rejected at startup.

For usage events, the tenant is read through the host. If it no longer exists, the templates
see a tenant with only `ID` set (a warning is logged); templates using other fields then render
empty and the event fails, which keeps the usage visible in the dead-letter queue instead of
dropping it. Customer sync uses the tenant carried by the event.

## Health

`GET /api/v1/billable_metrics?per_page=1` with the API key.

## Limitations

- Only closed periods are exported; there is no real-time usage export.
- Customers are not deleted or archived when tenants are deleted (Lago keeps billing history).
- Changing `customer_id_template` or `subscription_id_template` for existing tenants points
  new events at different Lago objects.
