# gcp-pubsub

Publishes Tenarium events to a Google Cloud Pub/Sub topic as CloudEvents (plugin ID
`gcp-pubsub`, package `plugins/gcppubsub`). It calls the Pub/Sub REST API directly.

```yaml
- plugin: gcp-pubsub
  config:
    project: my-project
    topic: tenarium-events        # topic ID (not the full resource name)
    events: ["tenant.*"]          # glob filter; empty = all events
    credentials_file: /var/secrets/google/key.json   # or credentials_json; default: ADC
    # credentials_json: ${GOOGLE_CREDENTIALS_JSON}
    ordering: true                # ordering key = tenant ID
    attributes: {env: prod}       # extra attributes on every message
    timeout: 30s                  # per request
    # endpoint: https://europe-west1-pubsub.googleapis.com   # regional endpoint
    # Pub/Sub emulator (no authentication):
    # emulator: true
    # endpoint: http://pubsub-emulator:8085   # default http://localhost:8085
```

## Behavior

- **Message.** `data` is the structured CloudEvent JSON. Attributes: `ce-id`, `ce-type`,
  `ce-source`, `ce-specversion`, `ce-subject`, `tenant_id` (when set) and
  `content-type: application/cloudevents+json`, plus `attributes`. Subscriptions can filter on
  them, e.g. `attributes.tenant_id = "..."` or `hasPrefix(attributes.ce-type, "tenant.")`.
- **Ordering.** With `ordering`, the ordering key is the tenant ID (`global` for events
  without a tenant). Subscriptions created with message ordering then receive each tenant's
  events in order. Google recommends a regional `endpoint` when publishing with ordering keys.
- **Credentials.** `credentials_file` / `credentials_json` accept service account keys,
  authorized user credentials, external account (workload identity federation) and
  impersonated service account configurations. Without them, Application Default
  Credentials are used (`GOOGLE_APPLICATION_CREDENTIALS`, GKE workload identity, the metadata
  server). Plain-http endpoints are only accepted with `emulator`.
- **Health.** `/readyz` calls `topics.testIamPermissions` and requires
  `pubsub.topics.publish`, which also checks that the topic exists. With the emulator it reads
  the topic instead.
- **Errors.** Any non-2xx response is an error, so the event is retried.

## Delivery guarantees

At least once. Pub/Sub does not deduplicate on publish, so a retried event can be stored
twice; consumers should dedupe on the `ce-id` attribute (the CloudEvent `id`). Pub/Sub
delivery to subscribers is itself at least once unless exactly-once delivery is enabled on
the subscription.

## Required permissions

`roles/pubsub.publisher` on the topic (`pubsub.topics.publish`). The health check uses
`testIamPermissions`, which needs no extra permission.

## Tests

`go test ./plugins/gcppubsub/` runs unit tests against a fake API (including a fake token
endpoint for service account credentials). The integration test uses the emulator:

```sh
docker run -d --name tenarium-pubsub -p 18085:8085 \
  gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators \
  gcloud beta emulators pubsub start --host-port=0.0.0.0:8085
TENARIUM_TEST_PUBSUB_EMULATOR=http://localhost:18085 go test ./plugins/gcppubsub/
```
