# kafka-tenant

Gives every tenant its own namespace on a Kafka cluster (package `plugins/kafkatopic`):

- topics under a tenant prefix (`<topic_prefix><name>.<topic>`),
- prefixed ACLs that let the tenant's principal `User:<user>` use its topics, consumer groups
  and, optionally, transactional IDs, and nothing else,
- optionally a SCRAM credential for that user, with a password derived from a secret (Tenarium
  stores nothing),
- optionally Kafka client quotas and partition counts taken from the tenant's entitlements.

The plugin uses the Kafka admin protocol through franz-go (`kadm`). It works with Apache Kafka 2.7+
(SCRAM management requires KIP-554; KRaft clusters need 3.5+) and with Kafka-compatible brokers
that implement the ACL APIs. The cluster must have an authorizer enabled, for example
`authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer` on KRaft.

## Configuration

```yaml
- plugin: kafka-tenant
  config:
    brokers: [kafka-1:9092, kafka-2:9092]      # required
    client_id: tenarium
    sasl: {mechanism: SCRAM-SHA-512, username: tenarium-admin, password: ${KAFKA_ADMIN_PASSWORD}}  # PLAIN | SCRAM-SHA-256/512
    tls: {enabled: true}                       # insecure_skip_verify: false

    name_template: "tenant-{{.Slug}}"          # default; sanitized to [a-z0-9_-]
    user_template: "tenant-{{.Slug}}"          # default: the name
    topic_prefix: "prod."                      # static, before the name (default "")
    group_prefix: "prod."                      # static, for group/transactional IDs (default: topic_prefix)

    topics:                                    # created as <topic_prefix><name>.<topic name>
      - name: events
        partitions: 6                          # 0 or -1: broker default
        replication_factor: 3                  # 0 or -1: broker default
        configs: {retention.ms: "604800000", cleanup.policy: delete}
      - name: commands
    partitions_from_limit: kafka_partitions    # entitlement limit → partitions of every topic
    max_partitions: 48                         # cap for limit-derived counts (0 = none)

    acl:
      host: "*"                                # default
      topic_operations: [read, write, describe]  # default; also create, delete, alter, describe_configs, alter_configs
      group_operations: [read, describe]       # default; also delete
      transactional_ids: false                 # true: write+describe on the transactional ID prefix

    scram:                                     # optional: manage the tenant user's SCRAM credential
      mechanism: SCRAM-SHA-512                 # default; or SCRAM-SHA-256
      password_secret: ${KAFKA_TENANT_SECRET}  # required, at least 16 characters
      iterations: 8192                         # 4096-16384

    client_quotas:                             # optional: Kafka quota → entitlement limit
      producer_byte_rate: kafka_produce_bps
      consumer_byte_rate: kafka_consume_bps
      request_percentage: kafka_request_pct    # also controller_mutation_rate

    on_deprovision: delete                     # delete (default) | keep | retain
```

## Behavior

### Names and prefixes

`name_template` is a Go template over the tenant. The result is lowercased, every character
other than `a-z`, `0-9`, `_` and `-` (dots included) becomes `-`, and hyphen runs are collapsed.
The tenant then owns:

| Resource | Prefix (ACL pattern `PREFIXED`) |
|---|---|
| topics | `<topic_prefix><name>.` |
| consumer groups | `<group_prefix><name>.` |
| transactional IDs | `<group_prefix><name>.` (with `acl.transactional_ids`) |

Names never contain a dot and every prefix ends with one, so one tenant's prefix is never a
prefix of another's: `tenant-acme.` does not match `tenant-acme-corp.orders`. Names that would
make a topic name exceed Kafka's 249 characters are shortened and suffixed with a hash of the
tenant ID. Use only immutable fields (`ID`, `Slug`) in templates, since names are recomputed on
deprovision. A template that renders the same name or user for two tenants is rejected at
startup.

Applications must name their consumer groups `<group prefix>...` (for example
`tenant-acme.billing-worker`) and their transactional IDs likewise.

### Ownership

Kafka topics cannot carry arbitrary metadata, so ownership lives in the ACL store, which only
administrators can change. Each claimed prefix has a marker ACL:

```
DENY DESCRIBE on TOPIC PREFIXED <topic prefix> for User:tenarium-owner-<tenant id>
```

No client ever authenticates as that principal, so the marker has no effect on access.

- Provision creates the marker before anything else. If the prefix is marked for another
  tenant, holds retained data (`User:tenarium-retained-<id>`), or has topics without a marker,
  provisioning fails with a clear reason and nothing is changed. With `scram`, an existing SCRAM
  user of the same name is never taken over. Use a `user_template` with a tenant-specific
  prefix so that tenant slugs cannot collide with service accounts.
- Deprovision does nothing for prefixes that are not marked for the tenant.

### Provisioning

Every step converges and can be retried:

1. claim the prefix (see above),
2. set the SCRAM credential (with `scram`). The password is
   `hex(HMAC-SHA256(password_secret, tenant_id))`, available in Go as
   `kafkatopic.TenantPassword`. Changing the secret and reprovisioning rotates every password,
3. create missing topics. For existing topics, configured `configs` are set again and partitions
   are raised to the wanted count. Kafka cannot remove partitions, so a lower count is logged
   and ignored,
4. create the wanted ACLs and remove ACLs of the tenant principal on its prefixes that are no
   longer configured. Other ACLs of the principal are left alone,
5. set client quotas for the entity `user=<user>`. A limit the tenant does not have, or a
   negative one, removes the quota.

With `partitions_from_limit`, a positive limit sets the partition count of every configured
topic, capped by `max_partitions`. Without such a limit the topic's `partitions` applies.
Retry provisioning after a plan change to apply new limits; the plugin does not subscribe to
plan changes.

### Deprovisioning

In every mode the tenant loses access first: its ACLs on its prefixes, its client quotas and its
SCRAM credential are removed. Then:

- `delete` deletes every topic under the prefix, including topics the tenant created itself, and
  the consumer groups under the group prefix (best effort: groups that still have members are
  logged and expire on their own). The marker is removed last.
- `keep` leaves the topics and the ownership marker, so a new tenant with the same slug cannot
  claim them.
- `retain` leaves the topics but releases ownership: the marker becomes
  `User:tenarium-retained-<tenant id>`. Provisioning a tenant whose prefix collides then fails
  until an operator deletes the topics and that marker ACL.

## Routes

- `GET /v1/plugins/{instance}/tenants/{tenant}` (needs `tenants:read` on the tenant; 404
  otherwise) returns `brokers`, `principal`, `user`, `topic_prefix`, `group_prefix`,
  `transactional_id_prefix`, `topics` and `sasl_mechanism`. It contains no secrets.
- `GET /v1/plugins/{instance}/tenants/{tenant}/credentials` (only with `scram`; needs
  `tenants:read`, else 404, and `tenants:update`, else 403) returns `user`, `password` and
  `mechanism` with `Cache-Control: no-store`.

`/readyz` pings the brokers.

## Required permissions

The plugin's principal needs, on the cluster:

| Operation | Resource |
|---|---|
| `DESCRIBE`, `ALTER` | CLUSTER (ACLs, SCRAM users) |
| `DESCRIBE_CONFIGS`, `ALTER_CONFIGS` | CLUSTER (client quotas, only with `client_quotas`) |
| `CREATE`, `DESCRIBE`, `ALTER`, `ALTER_CONFIGS`, `DELETE` | TOPIC (all, or the configured prefixes) |
| `DESCRIBE`, `DELETE` | GROUP (deleting consumer groups) |

Being a super user (`super.users`) is the simplest way to grant this. Creating ACLs needs
`ALTER` on the cluster, which is effectively administrative access, so protect the plugin's
credentials accordingly.

## Testing

Unit tests run against an in-memory fake. The integration tests need a cluster with an
authorizer:

- `TENARIUM_TEST_KAFKA_BROKERS`: brokers the plugin uses as an administrator,
- `TENARIUM_TEST_KAFKA_SASL_BROKERS` (optional): a `SASL_PLAINTEXT` SCRAM-SHA-512 listener.
  When set, the test connects as the tenant, produces and consumes in its own namespace, and
  checks that a topic outside it is denied.

```sh
docker run -d --name tenarium-test-kafka -p 49092:9092 -p 49094:9094 \
  -e KAFKA_NODE_ID=1 -e KAFKA_PROCESS_ROLES=broker,controller \
  -e KAFKA_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093,SASL://:9094 \
  -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:49092,SASL://localhost:49094 \
  -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,SASL:SASL_PLAINTEXT \
  -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  -e KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT -e KAFKA_SASL_ENABLED_MECHANISMS=SCRAM-SHA-512 \
  -e 'KAFKA_LISTENER_NAME_SASL_SCRAM___SHA___512_SASL_JAAS_CONFIG=org.apache.kafka.common.security.scram.ScramLoginModule required;' \
  -e KAFKA_AUTHORIZER_CLASS_NAME=org.apache.kafka.metadata.authorizer.StandardAuthorizer \
  -e KAFKA_SUPER_USERS=User:ANONYMOUS -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 \
  apache/kafka:3.9.1
TENARIUM_TEST_KAFKA_BROKERS=localhost:49092 TENARIUM_TEST_KAFKA_SASL_BROKERS=localhost:49094 \
  go test ./plugins/kafkatopic/ -run Integration -v
```

The anonymous PLAINTEXT super user is for tests only.
