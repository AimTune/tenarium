# openmeter

Exports tenant usage to [OpenMeter](https://openmeter.io) (OpenMeter Cloud or self-hosted) as
CloudEvents, for usage-based billing and analytics.

## What it does

When a usage period ends, Tenarium emits `tenant.usage_period_closed` with the period's final
value. For every metric mapped in `metrics`, the plugin sends one CloudEvent to
`POST /api/v1/events` (subscription `meters`). The OpenMeter meter whose `eventType` matches
the mapped type aggregates it. Only period totals are exported; real-time increments and
threshold events are not.

## Configuration

```yaml
plugins:
  - plugin: openmeter
    config:
      api_key: ${OPENMETER_API_KEY}     # optional for self-hosted without auth
      api_url: https://openmeter.cloud  # or http://openmeter:8888
      metrics:
        api_calls: tenarium.api_calls   # Tenarium metric: CloudEvent type (meter eventType)
      subject_template: "{{.ID}}"
      source: tenarium
      value_property: value
```

| Key | Type | Default | Description |
|---|---|---|---|
| `api_key` | string | (none) | OpenMeter API token, sent as `Authorization: Bearer` when set. |
| `api_url` | string | `https://openmeter.cloud` | OpenMeter base URL (absolute http(s)). |
| `timeout` | duration | `10s` | Timeout per API request. |
| `metrics` | map | (required, at least one) | Tenarium usage metric to CloudEvent `type`. Other metrics are ignored. |
| `subject_template` | template | `{{.ID}}` | Renders the CloudEvent `subject` (the OpenMeter subject / customer key). |
| `source` | string | `tenarium` | CloudEvent `source`. |
| `value_property` | string | `value` | `data` property carrying the value (not `metric` / `period`). |

Matching meter (SUM over the value):

```yaml
meters:
  - slug: api_calls
    eventType: tenarium.api_calls
    aggregation: SUM
    valueProperty: $.value
```

## Events

Each closed period of a mapped metric is sent as a structured CloudEvent
(`Content-Type: application/cloudevents+json`):

```json
{
  "specversion": "1.0",
  "id": "tenarium-<tenant_id>-<metric>-<period>",
  "source": "tenarium",
  "type": "tenarium.api_calls",
  "subject": "<subject_template>",
  "time": "2026-10-31T23:59:59Z",
  "datacontenttype": "application/json",
  "data": {"value": 1234, "metric": "api_calls", "period": "2026-10"}
}
```

- `time` is the period end minus one second (RFC 3339, UTC), inside the period.
- Events with value `0`, without a period end, or for unmapped metrics are skipped.

## Idempotency and errors

Event handlers are at-least-once. The event `id` is the same for every delivery of a period
and OpenMeter deduplicates events by `(id, source)`, so a redelivered period is accepted (2xx,
typically 204) but counted once. Keep `source` stable: changing it makes earlier IDs count
again. Non-2xx responses (OpenMeter's problem details are included in the error) and network
errors are returned so the event is retried and finally dead-lettered.

## Template data

`subject_template` is a Go `text/template` with `missingkey=error`, executed against the
tenant: `{{.ID}}`, `{{.Slug}}`, `{{.Name}}`, `{{.Plan}}`, `{{.ParentID}}`,
`{{index .Labels "x"}}` (or `{{.Labels.x}}`, which fails when the label is missing). The result
is trimmed and must not be empty. Unknown fields are rejected at startup.

The tenant is read through the host. If it no longer exists, the template sees a tenant with
only `ID` set (a warning is logged); templates using other fields then render empty and the
event fails into the dead-letter queue instead of being dropped.

## Health

`GET /api/v1/meters`, with the token when `api_key` is set.

## Limitations

- Only closed periods are exported; there is no real-time usage export.
- Subjects/customers are not created in OpenMeter; the rendered subject must match what your
  OpenMeter customers or entitlements use.
