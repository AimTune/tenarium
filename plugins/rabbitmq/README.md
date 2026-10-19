# rabbitmq

Publishes Tenarium events to a RabbitMQ (AMQP 0-9-1) exchange as CloudEvents (plugin ID
`rabbitmq`).

```yaml
- plugin: rabbitmq
  config:
    url: amqps://tenarium:${RABBITMQ_PASSWORD}@rabbitmq:5671/prod   # amqp:// or amqps://
    exchange: tenarium.events     # "" = default exchange (routing key = queue name)
    exchange_type: topic          # topic (default) | direct | fanout | headers
    declare_exchange: true        # declare it (durable) on every connect
    routing_key: "{{.Type}}"      # default; Go template over the event
    events: ["tenant.*"]          # glob filter; empty = all events
    mandatory: true               # unroutable messages fail instead of being dropped
    timeout: 10s                  # dial and publisher-confirm timeout
    tls:                          # only with amqps://
      ca_file: /etc/rabbitmq/ca.pem
      cert_file: /etc/rabbitmq/client.pem   # mutual TLS / EXTERNAL auth (with key_file)
      key_file: /etc/rabbitmq/client-key.pem
      server_name: rabbitmq.internal
      insecure_skip_verify: false
```

## Behavior

- **Message.** The body is the structured CloudEvent JSON with content type
  `application/cloudevents+json`. Messages are persistent (`delivery_mode=2`); `message_id`
  is the event ID, `type` the event type, `timestamp` the event time and `app_id` is
  `tenarium`. The headers `ce_id`, `ce_type`, `ce_source` and `tenant_id` allow routing with
  a headers exchange.
- **Routing key.** A Go template over the event (`.ID`, `.Type`, `.TenantID`, `.Source`,
  `.Subject`, `.Actor`, `.Seq`), e.g. `tenant.{{.TenantID}}.{{.Type}}`. `plan.*` events have
  no tenant ID; use `{{or .TenantID "global"}}` if the key needs one. Bind queues with
  patterns such as `tenant.*` or `#`.
- **Publisher confirms.** The channel runs in confirm mode. A delivery succeeds only after
  the broker acks the message; a nack, a timeout or a broken connection is an error, and
  Tenarium retries. With `mandatory`, a message that no queue is bound to receive is returned
  by the broker and the delivery fails too; without it RabbitMQ drops such messages silently
  (unless the exchange has an alternate exchange).
- **Reconnects.** If the connection or channel is closed (broker restart, network failure),
  the next publish or health check reconnects and declares the exchange again. Startup does
  not wait for RabbitMQ. `/readyz` reports whether a connection can be established.

## Delivery guarantees

At least once: if a confirm is lost (connection dropped after the broker stored the
message), the event is published again. Consumers should dedupe on `message_id` (the
CloudEvent `id`). Events of one subscription are published one at a time, in order.

## Required permissions

The user needs `write` on the exchange and, with `declare_exchange`, `configure` on it
(for example `rabbitmqctl set_permissions -p prod tenarium '^tenarium\.events$' '^tenarium\.events$' '^$'`).

## Tests

`go test ./plugins/rabbitmq/` runs unit tests. The integration test needs a broker:

```sh
docker run -d --name tenarium-rabbitmq -p 15673:5672 rabbitmq:3-management
TENARIUM_TEST_RABBITMQ_URL=amqp://guest:guest@localhost:15673/ go test ./plugins/rabbitmq/
```
