# siem

Exports Tenarium events as an audit trail to SIEM systems:

- **Splunk HTTP Event Collector** (HEC)
- **syslog**: RFC 5424 over TCP, TLS or UDP, with a JSON or ArcSight CEF message
- **Elasticsearch / OpenSearch** through the `_bulk` API, one index per day

Configure any combination of sinks in one instance. Each sink has its own subscription
(`splunk`, `syslog`, `elastic`) with its own cursor, retries and dead-letter queue, so an
unreachable SIEM never holds back the others.

## Configuration

```yaml
plugins:
  - plugin: siem
    config:
      events: []                         # glob patterns; empty = all events
      exclude_events: ["tenant.usage_*"]
      include_data: true                 # add the event payload to records
      timeout: 10s
      splunk:
        url: https://splunk.example.com:8088
        token: ${SPLUNK_HEC_TOKEN}
        index: tenarium
        sourcetype: tenarium:audit
      syslog:
        address: siem.example.com:6514
        network: tls                     # tcp | tls | udp
        format: cef                      # json | cef
        tls: {ca_file: /etc/ssl/siem-ca.pem}
      elastic:
        url: https://es.example.com:9200
        api_key: ${ES_API_KEY}           # or username/password
        index_prefix: tenarium-audit
```

### Top level

| Key | Type | Default | Description |
|---|---|---|---|
| `events` | list of globs | all | Event types to export (`path.Match` syntax, e.g. `tenant.*`). |
| `exclude_events` | list of globs | none | Event types never exported. |
| `include_data` | bool | `true` | Include the event payload (`data`). Turn off to keep tenant settings out of the SIEM. |
| `timeout` | duration | `10s` | Per request / connection attempt. |

At least one of `splunk`, `syslog` and `elastic` is required.

### `splunk`

| Key | Default | Description |
|---|---|---|
| `url` (required) | | HEC base URL, e.g. `https://splunk:8088`. Events go to `/services/collector/event`. |
| `token` (required) | | HEC token, sent as `Authorization: Splunk <token>`. |
| `index` | token default | Target index. |
| `sourcetype` | `tenarium:event` | |
| `source` | `tenarium` | |
| `host` | unset | Event `host` field. |
| `channel` | unset | `X-Splunk-Request-Channel`, needed for tokens with indexer acknowledgement. |
| `tls` | system roots | See [TLS](#tls). |

The record is the HEC `event`; `event_id`, `event_type`, `seq`, `tenant_id`, `tenant_slug`,
`actor`, `actor_type`, `actor_id` and `outcome` are also sent as indexed `fields`. A HEC
response with a non-zero `code` is an error.

### `syslog`

| Key | Default | Description |
|---|---|---|
| `address` (required) | | `host:port` of the collector. |
| `network` | `tcp` | `tcp`, `tls` or `udp`. |
| `format` | `json` | Message body: the JSON record or a CEF line. |
| `framing` | `octet_counting` | For TCP/TLS: `octet_counting` (RFC 6587/5425, `LEN SP MSG`) or `non_transparent` (newline-terminated). |
| `facility` | `13` (log audit) | 0-23. |
| `severity` | `6` (informational) | 0-7. Failed operations use at most 4 (warning). |
| `app_name` | `tenarium` | RFC 5424 APP-NAME. |
| `hostname` | machine host name | RFC 5424 HOSTNAME. |
| `sd_id` | `tenarium@32473` | Structured data ID carrying the key fields. `32473` is the example enterprise number of RFC 5612; use your own if you have one. `-` sends no structured data. |
| `tls` | | For `network: tls`. The server name defaults to the address host. |

A message looks like:

```
<110>1 2026-10-10T08:30:00.123456Z cp-1 tenarium 4711 tenant.suspended [tenarium@32473 event_id="..." event_type="tenant.suspended" seq="42" tenant_id="..." tenant_slug="acme" actor="oidc:alice@example.com" actor_type="oidc" actor_id="alice@example.com" outcome="success"] {"time":...}
```

The MSGID is the event type (truncated to 32 characters). The connection is kept open and
re-dialed once if a write fails. UDP sends one datagram per event; delivery is not confirmed.

**CEF** messages use vendor and product `Tenarium`, the event type as signature ID and name,
severity 3 (7 for failures) and these extensions: `rt` (epoch ms), `externalId` (event ID),
`cat` (event type), `outcome`, `cn1` (sequence), `suser` (actor), `suid` (actor ID),
`cs1` tenantId, `cs2` tenantSlug, `cs3` subject, `cs4` source and `msg` (the JSON payload,
when `include_data` is on).

### `elastic`

Works with Elasticsearch and OpenSearch.

| Key | Default | Description |
|---|---|---|
| `url` (required) | | Cluster URL. |
| `username` / `password` | | Basic authentication. |
| `api_key` | | Elasticsearch API key (encoded `id:key`), sent as `Authorization: ApiKey ...`. Not together with `username`. |
| `index_prefix` | `tenarium-events` | Lowercase index name prefix. |
| `index_date_format` | `2006.01.02` | Go time layout appended as `-<date>` from the event time (UTC); `none` writes to the prefix only (e.g. a data stream). |
| `pipeline` | unset | Ingest pipeline. |
| `tls` | system roots | See [TLS](#tls). |

Each event is sent with a `create` action and `_id` = event ID, so redelivered events are not
indexed twice (a `409` for the item counts as success). Documents carry ECS fields:
`@timestamp`, `event.{id,action,kind,category,dataset,provider,sequence,outcome}`,
`organization.{id,name}` (the tenant), `user.{id,domain}` (the actor), `message`, and the full
record under `tenarium`. Create an index template for `tenarium-events-*` to control mappings
and retention.

### TLS

`tls` accepts `ca_file`, `cert_file` + `key_file` (client certificate), `server_name` and
`insecure_skip_verify` (testing only).

## Record fields

| Field | Description |
|---|---|
| `time`, `id`, `type`, `seq`, `source`, `subject` | From the event. |
| `tenant_id` | The event's tenant. `tenant_slug` and `tenant_name` are added for `tenant.*` events. |
| `actor` | Who caused the event: `{authenticator}:{subject}`, `plugin:{instance}` or `system`. |
| `actor_type`, `actor_id` | `actor` split at the first `:`. |
| `outcome` | `failure` for `*_failed`, `tenant.quota_exceeded` and `user.locked`, else `success`. |
| `data` | The event payload (with `include_data`). |

## Delivery

Delivery is at least once. Splunk and syslog may receive an event twice after a retry;
deduplicate on `event_id` if needed. Elasticsearch deduplicates on `_id`. Events of one
subscription are delivered in order, one at a time, so every event is sent in its own request.

## Health

`/readyz` checks the Splunk HEC health endpoint, the Elasticsearch cluster info (which also
checks credentials) and, for TCP/TLS syslog, that the collector accepts connections.
