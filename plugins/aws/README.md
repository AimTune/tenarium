# aws-events

Publishes Tenarium events to Amazon SQS, SNS or EventBridge as CloudEvents (plugin ID
`aws-events`, package `plugins/aws`). One instance has one target; configure several
instances (with different `name`s) to publish to several destinations.

```yaml
- plugin: aws-events
  name: tenant-events-queue
  config:
    target: sqs                   # sqs | sns | eventbridge
    region: eu-central-1          # default: AWS_REGION / shared config
    events: ["tenant.*"]          # glob filter; empty = all events
    # endpoint: http://localstack:4566   # endpoint override (LocalStack, VPC endpoints)
    # Credentials: static keys, a profile, or (default) the AWS default chain
    # access_key_id: ${AWS_ACCESS_KEY_ID}
    # secret_access_key: ${AWS_SECRET_ACCESS_KEY}
    # session_token: ...
    # profile: tenarium
    sqs:
      queue_url: https://sqs.eu-central-1.amazonaws.com/123456789012/tenarium-events.fifo

- plugin: aws-events
  name: tenant-events-topic
  config:
    target: sns
    sns:
      topic_arn: arn:aws:sns:eu-central-1:123456789012:tenarium-events

- plugin: aws-events
  name: tenant-events-bus
  config:
    target: eventbridge
    eventbridge:
      event_bus: tenarium         # name or ARN; default "default"
      source: acme.tenarium       # default "tenarium"; must not start with "aws."
```

## Behavior

- **SQS.** `SendMessage` with the CloudEvent JSON as the body. FIFO queues (URL ending in
  `.fifo`) get `MessageGroupId` = tenant ID (events without a tenant, `plan.*`, use `global`)
  and `MessageDeduplicationId` = event ID. Message attributes `type`, `event_id`,
  `tenant_id` and `content_type` are set.
- **SNS.** `Publish` with the CloudEvent JSON as the message and the same message attributes,
  so subscriptions can use filter policies such as `{"tenant_id": ["..."]}` or
  `{"type": [{"prefix": "tenant."}]}`. FIFO topics (`.fifo` ARN) get the same group and
  deduplication IDs as SQS.
- **EventBridge.** `PutEvents` with `Source`, `DetailType` = event type, `Detail` = the
  CloudEvent JSON and `Time` = event time. Rules can match on `detail.tenantid`,
  `detail.type` etc. A response with `FailedEntryCount > 0` is an error (the entry's error
  code and message are included), so the event is retried.
- **Health.** `/readyz` calls `GetQueueAttributes`, `GetTopicAttributes` or
  `DescribeEventBus`, which checks credentials and that the destination exists.

## Delivery guarantees

Tenarium delivers at least once and in order per subscription. FIFO queues and topics drop
retries of the same event within their five-minute deduplication interval and keep each
tenant's events ordered. Standard queues/topics and EventBridge can receive an event more
than once and do not guarantee order, so consumers should dedupe on the CloudEvent `id`
(`event_id` attribute).

## Required IAM permissions

| Target | Actions | Resource |
|---|---|---|
| sqs | `sqs:SendMessage`, `sqs:GetQueueAttributes` | the queue ARN |
| sns | `sns:Publish`, `sns:GetTopicAttributes` | the topic ARN |
| eventbridge | `events:PutEvents`, `events:DescribeEventBus` | the event bus ARN |

For a KMS-encrypted queue or topic, also `kms:GenerateDataKey` and `kms:Decrypt` on the key.

## Tests

`go test ./plugins/aws/` runs unit tests with fake clients. The integration test runs
against LocalStack (SQS, SNS and EventBridge; recent `latest` images need an auth token, the
3.x community images do not):

```sh
docker run -d --name tenarium-localstack -p 14566:4566 localstack/localstack:3.8
TENARIUM_TEST_AWS_ENDPOINT=http://localhost:14566 go test ./plugins/aws/
```
