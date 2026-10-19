# azure-servicebus

Publishes Tenarium events to an Azure Service Bus queue or topic as CloudEvents (plugin ID
`azure-servicebus`, package `plugins/azureservicebus`). It uses the Service Bus REST API with
Shared Access Signature (SAS) authentication and only the Go standard library.

```yaml
- plugin: azure-servicebus
  config:
    connection_string: ${SERVICEBUS_CONNECTION_STRING}
    # Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKeyName=tenarium-send;SharedAccessKey=...
    entity: tenarium-events       # queue or topic; default: EntityPath of the connection string
    events: ["tenant.*"]          # glob filter; empty = all events
    session: false                # SessionId = tenant ID (for session-enabled entities)
    properties: {env: prod}       # custom properties on every message
    time_to_live: 168h            # message TTL; default: the entity's default
    token_ttl: 1h                 # SAS token lifetime (min 10m)
    timeout: 30s                  # per request
    # endpoint: https://proxy.internal   # override the namespace URL
```

## Behavior

- **Request.** `POST https://<namespace>.servicebus.windows.net/<entity>/messages` with the
  structured CloudEvent JSON as the body (`Content-Type: application/cloudevents+json`).
- **BrokerProperties.** `MessageId` = event ID, `Label` = event type, `SessionId` = tenant ID
  with `session` (`global` for events without a tenant), and `TimeToLive` with
  `time_to_live`.
- **Custom properties.** `ce_id`, `ce_type`, `ce_source`, `ce_specversion`, `tenant_id` and
  `properties`, sent as HTTP headers with JSON-quoted values as the REST API requires. Topic
  subscriptions can use SQL filters such as `tenant_id = 'abc'` or
  `ce_type LIKE 'tenant.%'`.
- **Authentication.** The connection string's `Endpoint`, `SharedAccessKeyName` and
  `SharedAccessKey` are used to sign SAS tokens (HMAC-SHA256 over the URL-encoded entity URI
  and the expiry) for the entity URI. Tokens are cached and renewed five minutes before they
  expire. A connection string with a ready-made `SharedAccessSignature` is used as is (it
  is not renewed). The local Service Bus emulator only speaks AMQP and is not supported.
- **Errors.** Anything but a 2xx response (for example a missing `SessionId` on a
  session-enabled entity, throttling with 429/503, or a quota exceeded) is an error, and the
  event is retried. The `<Detail>` of the Service Bus error is included.
- **Health.** `/readyz` reads the entity description. That needs `Manage`; with a Send-only key
  Service Bus answers "claims required", which still proves that the namespace is reachable
  and the signature valid, and counts as healthy. An invalid signature or a missing entity
  is unhealthy.

## Delivery guarantees

At least once. If the entity has duplicate detection enabled, Service Bus drops messages
whose `MessageId` (the event ID) it has seen within the detection window, so retries are
stored once. Otherwise consumers should dedupe on `MessageId` / `ce_id`. With `session`,
session-aware receivers get each tenant's events in order.

## Required permissions

A shared access policy with the `Send` claim on the namespace or, preferably, on the entity.
`Manage` is only needed for the full health check.

## Tests

`go test ./plugins/azureservicebus/` runs unit tests against a fake REST endpoint, including
an independent check of the SAS signature. The integration test needs a real namespace:

```sh
TENARIUM_TEST_AZURE_SERVICEBUS_CONNECTION_STRING='Endpoint=sb://...' \
TENARIUM_TEST_AZURE_SERVICEBUS_ENTITY=tenarium-test \
go test ./plugins/azureservicebus/
```
