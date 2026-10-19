# orb

Exports tenant usage to [Orb](https://withorb.com) for usage-based billing. The plugin talks to
the Orb REST API directly.

## What it does

When a usage period ends, Tenarium emits `tenant.usage_period_closed` with the period's final
value. For every metric mapped in `metrics`, the plugin ingests one Orb event
(`POST /v1/ingest`, subscription `meters`). Only period totals are exported; real-time
increments and threshold events are not.

## Configuration

```yaml
plugins:
  - plugin: orb
    config:
      api_key: ${ORB_API_KEY}
      metrics:
        api_calls: api_request        # Tenarium metric: Orb event_name
        storage_gb: storage_snapshot
      customer_id_template: "{{.ID}}"
      property_name: value
```

| Key | Type | Default | Description |
|---|---|---|---|
| `api_key` | string | (required) | Orb API key, sent as `Authorization: Bearer`. |
| `api_url` | string | `https://api.withorb.com` | Orb API base URL (absolute http(s)). |
| `timeout` | duration | `10s` | Timeout per API request. |
| `metrics` | map | (required, at least one) | Tenarium usage metric to Orb `event_name`. Other metrics are ignored. |
| `customer_id_template` | template | `{{.ID}}` | Renders the Orb `external_customer_id`. |
| `property_name` | string | `value` | Event property carrying the value (not `tenarium_metric` / `tenarium_period`). |
| `debug` | bool | `false` | Sends `debug=true`; Orb then reports ingested/duplicate keys, logged at debug level. |

## Events

Each closed period of a mapped metric becomes:

```json
{"events": [{
  "idempotency_key": "tenarium-<tenant_id>-<metric>-<period>",
  "external_customer_id": "<customer_id_template>",
  "event_name": "<mapped event name>",
  "timestamp": "2026-10-31T23:59:59Z",
  "properties": {"value": 1234, "tenarium_metric": "api_calls", "tenarium_period": "2026-10"}
}]}
```

- `timestamp` is the period end minus one second (RFC 3339, UTC), inside the period.
- Define the Orb billable metric over the event name, e.g. `SUM(value)`.
- Events with value `0`, without a period end, or for unmapped metrics are skipped.

## Idempotency and errors

Event handlers are at-least-once. The `idempotency_key` is the same for every delivery of a
period and Orb deduplicates events by it, so a period is never billed twice; a duplicate is
answered with 200.

Non-2xx responses and network errors are returned so the event is retried. Orb answers 200
even when it rejects an event, listing it in `validation_failed` (for example an unknown
customer, or a timestamp older than the account's ingestion grace period). The plugin turns
that into an error carrying Orb's messages, so the event is retried and finally dead-lettered
rather than silently dropped.

## Template data

`customer_id_template` is a Go `text/template` with `missingkey=error`, executed against the
tenant: `{{.ID}}`, `{{.Slug}}`, `{{.Name}}`, `{{.Plan}}`, `{{.ParentID}}`,
`{{index .Labels "x"}}` (or `{{.Labels.x}}`, which fails when the label is missing). The result
is trimmed and must not be empty. Unknown fields are rejected at startup.

The tenant is read through the host. If it no longer exists, the template sees a tenant with
only `ID` set (a warning is logged); templates using other fields then render empty and the
event fails into the dead-letter queue instead of being dropped.

## Health

`GET /v1/ping` with the API key.

## Limitations

- Only closed periods are exported. Orb rejects events older than its ingestion grace period;
  if Tenarium was down for longer than that when a period closed, use Orb's backfill API for
  the dead-lettered periods.
- Customers are not created in Orb; `external_customer_id` must match customers you created
  there.
