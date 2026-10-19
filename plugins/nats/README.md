# nats

Publishes Tenarium events to [NATS JetStream](https://docs.nats.io/nats-concepts/jetstream) as
CloudEvents (plugin ID `nats`).

```yaml
- plugin: nats
  config:
    url: nats://nats-1:4222,nats://nats-2:4222   # comma-separated; tls:// also works
    subject: 'tenarium.{{or .TenantID "global"}}.{{.Type}}'   # default
    events: ["tenant.*"]          # glob filter; empty = all events
    name: tenarium                # client connection name
    timeout: 10s                  # connect and publish-ack timeout
    # Authentication: at most one of these
    creds_file: /etc/nats/tenarium.creds
    # nkey_seed: ${NATS_NKEY_SEED}     # SU... seed, inline
    # nkey_seed_file: /etc/nats/tenarium.nk
    # token: ${NATS_TOKEN}
    # username: tenarium
    # password: ${NATS_PASSWORD}
    tls:
      enabled: true
      ca_file: /etc/nats/ca.pem
      cert_file: /etc/nats/client.pem   # mutual TLS (with key_file)
      key_file: /etc/nats/client-key.pem
      server_name: nats.internal
      insecure_skip_verify: false
    stream:                       # optional
      name: TENARIUM              # publishes must land in this stream
      create: true                # create it if missing (never modifies an existing stream)
      subjects: ["tenarium.>"]    # default
      storage: file               # file | memory
      replicas: 3
      max_age: 720h
      duplicate_window: 10m       # Nats-Msg-Id dedupe window (server default 2m)
```

## Behavior

- **Subject.** `subject` is a Go template over the event (`.ID`, `.Type`, `.TenantID`,
  `.Source`, `.Subject`, `.Actor`, `.Seq`). Event types contain dots, so `tenant.created`
  adds two tokens: consumers can subscribe to `tenarium.<tenant>.>` or `tenarium.*.tenant.deleted`.
  `plan.*` events have no tenant ID; the default template uses `global` for them. A subject
  that renders empty tokens, whitespace or wildcards fails the delivery.
- **Body.** The structured CloudEvent JSON (`Content-Type: application/cloudevents+json`),
  plus the headers `ce-id`, `ce-type` and `ce-tenantid`.
- **Dedupe.** The `Nats-Msg-Id` header is the event ID. JetStream drops a message whose ID
  it has seen within the stream's duplicate window, so retries of the same event are stored
  once.
- **Acknowledgements.** A delivery succeeds only when JetStream acknowledges it. If no stream
  captures the subject, or it lands in another stream than `stream.name`, the publish fails
  and is retried.
- **Connection.** Startup does not wait for NATS; the client reconnects forever. `/readyz`
  fails while disconnected or when JetStream is unavailable for the account.

## Delivery guarantees

Tenarium delivers at least once and in order per subscription. Retries within the duplicate
window are deduplicated by JetStream; beyond that a retried event can appear twice, so
consumers should dedupe on the CloudEvent `id` (also the `Nats-Msg-Id` header).

## Required permissions

The NATS user needs publish permission on the configured subjects and on the JetStream API:
`$JS.API.INFO` (health), and with `stream.create`, `$JS.API.STREAM.INFO.<name>` and
`$JS.API.STREAM.CREATE.<name>`. Subscribe permission on `_INBOX.>` is needed for the
acknowledgements.

## Tests

`go test ./plugins/nats/` runs unit tests. The integration test needs a JetStream server:

```sh
docker run -d --name tenarium-nats -p 14222:4222 nats -js
TENARIUM_TEST_NATS_URL=nats://localhost:14222 go test ./plugins/nats/
```
