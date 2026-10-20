# Event archive

The `archive` plugin (package `plugins/archive`) copies every event to object storage for
long-term retention. The event log in the database is pruned after `events.retention`; the
archive keeps events for as long as your bucket's lifecycle rules allow. Operators can read
archived events back by time range, or replay them to an HTTP endpoint.

Supported backends: Amazon S3 and S3-compatible stores (MinIO, Ceph RGW, SeaweedFS, Cloudflare
R2), Google Cloud Storage, Azure Blob Storage, and a local directory.

## Configuration

```yaml
- plugin: archive
  config:
    backend: s3                      # s3 | gcs | azure | file (required)
    prefix: events                   # key prefix (default "events")
    events: []                       # glob filter on event types; empty = all events
    batch_size: 100                  # max events per object (1-1000)
    flush_interval: 1m               # close a batch once it is this old
    compression: gzip                # gzip (default) | none
    timeout: 30s                     # per storage request
    max_attempts: 30                 # before an event is dead-lettered (backoff up to 2m)
    s3:
      endpoint: s3.eu-central-1.amazonaws.com   # host[:port], no scheme
      region: eu-central-1
      access_key: ${ARCHIVE_S3_ACCESS_KEY}
      secret_key: ${ARCHIVE_S3_SECRET_KEY}
      secure: true                   # HTTPS (default true)
      bucket: tenarium-event-archive # must exist
    replay:
      timeout: 10s                   # per request to the replay target
      max_events: 100000             # cap per replay request
      allow_http: false              # development only
      allow_private_networks: false  # development only
```

Exactly one backend block, matching `backend`, must be set:

```yaml
    gcs:
      bucket: tenarium-event-archive
      credentials_file: /etc/tenarium/gcs-sa.json   # or credentials_json; default: ADC
      # endpoint: http://localhost:4443             # emulator
      # anonymous: true                             # emulator only
    azure:
      connection_string: ${AZURE_STORAGE_CONNECTION_STRING}   # or account_name + account_key (+ endpoint)
      container: event-archive       # must exist
    file:
      dir: /var/lib/tenarium/archive # created if missing; for single-node setups and tests
```

Credentials are given the same way as for the `s3-tenant`, `gcs-tenant` and `azure-blob`
plugins. The plugin needs these permissions on the bucket or container: put, get, delete and
list objects (S3: `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject`, `s3:ListBucket`; GCS:
`roles/storage.objectAdmin` on the bucket; Azure: an account key). `/readyz` checks that the
bucket, container or directory exists.

## Layout

Each object holds NDJSON, one [`sdk.Event`](https://github.com/AimTune/tenarium/blob/main/pkg/sdk/event.go) JSON object per line in
sequence order, gzip-compressed by default:

```
{prefix}/{yyyy}/{mm}/{dd}/{hh}/{firstSeq}-{lastSeq}.ndjson.gz
events/2026/10/10/08/00000000000000004711-00000000000000004810.ndjson.gz
```

The date and hour are the UTC time of the events. Every event in an object falls into that
object's hour, so reading a time range only lists the days it covers. Sequence numbers are
zero-padded to 20 digits so keys sort in log order. The objects are plain files: you can also
process them with `aws s3 cp`, Athena, BigQuery or `zcat | jq`.

Use your storage's lifecycle rules (for example a transition to Glacier or Archive tier after
90 days, and expiry after 7 years) to decide how long events are kept. If you use the replay
and read routes on old data, pick a tier that supports direct reads.

## Delivery guarantees

The archive is a normal event subscription (`archive`), with its own cursor, retries and
dead-letter queue. The dispatcher hands it one event at a time and moves the cursor as soon as
the handler returns, so the plugin returns only once the event is durably stored:

- Each event is appended to the open batch, the whole batch is written as
  `{firstSeq}-{lastSeq}`, and the previous, shorter object of that batch is deleted.
- A batch is closed after `batch_size` events, after `flush_interval`, when the hour changes, or
  when an older event arrives (a redelivery or a dead-letter replay). The next event starts a
  new object.
- Storage therefore holds one object per batch, but an open batch costs one write and one
  delete per event, and its object is rewritten each time. `batch_size` trades the number of
  objects against this rewrite cost.

Delivery is at least once. A retried event rewrites an object under the same name. A crash, a
failed delete, or the subscription moving to another replica can leave overlapping objects.
Reads merge objects in sequence order and drop duplicate event IDs, so a reader never sees a
duplicate.

If storage is unavailable, events are retried with backoff for about an hour (`max_attempts`)
and then dead-lettered. Replaying them from the dead-letter queue
(`POST /v1/dead-letters/{id}/replay`) archives them.

## Reading archived events

```
GET /v1/plugins/{instance}/events?from=2026-10-01T00:00:00Z&to=2026-10-02T00:00:00Z&type=tenant.*&tenant_id=...
```

| Parameter | Description |
|---|---|
| `from` (required) | RFC 3339 time, inclusive. |
| `to` | RFC 3339 time, exclusive (default now). Ranges are limited to 5 years. |
| `type` | Glob pattern on the event type; repeat it or separate patterns with commas. |
| `tenant_id` | Only this tenant's events. |
| `limit` | Stop after this many events. |

The response is `application/x-ndjson`: one event per line, in sequence order, without
duplicates. It is streamed, so large ranges do not have to fit in memory. If storage fails
after streaming has started, the response ends early and the HTTP trailer
`Tenarium-Archive-Error` carries the error.

## Replaying archived events

```
POST /v1/plugins/{instance}/replay
{
  "from": "2026-10-01T00:00:00Z",
  "to": "2026-10-02T00:00:00Z",
  "type": "tenant.*",
  "tenant_id": "",
  "url": "https://billing.example.com/hooks/tenarium",
  "secret": "<the receiver's signing secret, e.g. whsec_ + base64>",
  "limit": 0
}
```

Each matching event is POSTed to `url` as a CloudEvent (`application/cloudevents+json`), signed
like Tenarium webhooks according to [Standard Webhooks](https://www.standardwebhooks.com):
`webhook-id` is the event ID, `webhook-timestamp` the send time, and `webhook-signature` is
`v1,<base64 HMAC-SHA256 of "id.timestamp.body">`. A `whsec_` secret is base64-decoded, and any
other string is used as is. The receiver can verify with any Standard Webhooks library and
dedupe on `webhook-id`.

Events are sent one at a time, in sequence order. Each is tried up to 3 times. The replay stops
at the first event the endpoint does not accept with a 2xx response. The response reports the
counts:

```json
{"matched": 1200, "sent": 1199, "failed": 1, "last_seq": 48211, "error": "event 1200: endpoint responded 503 Service Unavailable"}
```

The status is 200 when every matched event was sent, and 502 when the replay stopped on an
error. `truncated: true` means `limit` (or `replay.max_events`) was reached. To resume, replay
again from the time of the event after `last_seq`. The request runs synchronously, so split long
ranges into smaller ones if a proxy in front of Tenarium has short timeouts.

Like Tenarium webhooks, the target must use `https` and must not resolve to a loopback, private,
link-local (cloud metadata), CGNAT or multicast address. The address is checked again when
connecting, so DNS rebinding cannot bypass the check. Proxies are not used and redirects are not
followed. `replay.allow_http` and `replay.allow_private_networks` lift these limits for
development.

## Authorization

Both routes are behind authentication and the `plugins:route` check like every plugin route.
Archived events span all tenants, so the plugin also requires a platform-wide caller (no tenant
scope) that holds `events:read`. Replay additionally requires `deadletters:replay`. Other
callers get 403.

## Testing

The unit tests use the `file` backend and in-memory fakes of the GCS and Azure APIs. The S3
integration test runs when `TENARIUM_TEST_S3_ENDPOINT` is set, as for `s3-tenant`:

```sh
docker run -d --name tenarium-s3 -p 18333:8333 chrislusf/seaweedfs server -s3
TENARIUM_TEST_S3_ENDPOINT=localhost:18333 go test ./plugins/archive/
```
