# Plugins

Plugins extend Tenarium. A plugin implements `sdk.Plugin` (`Manifest` and `Init`), and in
`Init` registers what it wants to take part in.

## Extension points

| Extension point | Runs | Typical use |
|---|---|---|
| **Subscribe** | asynchronously, at least once, ordered, retried, dead-lettered | publish to Kafka, send webhooks, sync to a CRM, audit logs |
| **Hook** | synchronously before a change; may modify or reject it | slug and plan policies, default labels, approvals |
| **Provisioner** | asynchronously on create (in order) and delete (in reverse); idempotent | database schema, Keycloak realm, S3 bucket, DNS |
| **Route** | HTTP under `/v1/plugins/{instance}/`, behind authentication | plugin-specific APIs and dashboards |
| **Authenticator** | for each API request | OIDC, LDAP, mTLS |
| **Authorizer** | for each API request | RBAC, OPA, ReBAC |
| **UserDirectory** | for user changes (one directory is active) | keep users in Keycloak, Auth0, LDAP |
| **Mailer** | for invitations and password resets | SMTP, SES, SendGrid |
| **Host** (used by plugins) | any time | read tenants, plans, users and entitlements; check access; suspend, resume, change plan, record usage |

Hook points: `tenant.before_create`, `tenant.before_update`, `tenant.before_suspend`,
`tenant.before_resume`, `tenant.before_delete`, `member.before_add`, `member.before_update`,
`member.before_remove`, `user.before_create`, `user.before_update`.

External (out-of-process) plugins can provide user directories and mailers too; see
[External plugins](external.md#user-directories-and-mailers).

## Runtimes

| Runtime | How it works | Choose it when |
|---|---|---|
| **Built-in (Go)** | Compiled into the binary; registers itself with `sdk.Register` in `init` | you want full Go, the best performance, or to ship a custom distribution |
| **External** | A separate process, in any language, speaking an HTTP/JSON protocol; Tenarium can start and supervise it | your team writes Python/TypeScript/…, or you want isolation and independent deploys |
| **WASM** | A sandboxed WebAssembly module (WASI) | policies supplied as data, or untrusted/tenant-supplied logic |

The same Go plugin runs built-in or external without changes. The protocol uses HTTP/JSON
rather than gRPC so that a plugin needs no code generation in any language.

Go's `plugin` package (`.so` files) is deliberately not used: it does not work on Windows,
requires plugins built with exactly the same toolchain and dependency versions, and cannot
unload a plugin.

## Plugin catalog

Every plugin compiled into the default binary (`tenarium -list-plugins`). The ID is what you
put in `plugin:`; the package is the directory under `plugins/`. Plugins documented on this
page link to their section; the others link to the README next to their code.

**Events: brokers and streams**

| ID | Package | What it does |
|---|---|---|
| [`kafka`](#kafka) | `kafka` | Publishes events to a Kafka topic, keyed by tenant ID |
| [`webhook`](#webhook) | `webhook` | POSTs events to one HTTP endpoint, signed per Standard Webhooks |
| [`nats`](https://github.com/AimTune/tenarium/blob/main/plugins/nats/README.md) | `nats` | Publishes events to NATS JetStream on per-tenant, per-type subjects |
| [`rabbitmq`](https://github.com/AimTune/tenarium/blob/main/plugins/rabbitmq/README.md) | `rabbitmq` | Publishes events to a RabbitMQ exchange with publisher confirms |
| [`aws-events`](https://github.com/AimTune/tenarium/blob/main/plugins/aws/README.md) | `aws` | Publishes events to Amazon SQS, SNS or EventBridge |
| [`gcp-pubsub`](https://github.com/AimTune/tenarium/blob/main/plugins/gcppubsub/README.md) | `gcppubsub` | Publishes events to a Google Cloud Pub/Sub topic |
| [`azure-servicebus`](https://github.com/AimTune/tenarium/blob/main/plugins/azureservicebus/README.md) | `azureservicebus` | Publishes events to an Azure Service Bus queue or topic |
| [`redis`](#redis) | `redis` | Events to Redis Streams or pub/sub, a tenant state cache, and a Redis ACL user per tenant |
| [`archive`](archive.md) | `archive` | Archives events to S3, GCS, Azure Blob or a directory, with read-back and replay |
| [`siem`](https://github.com/AimTune/tenarium/blob/main/plugins/siem/README.md) | `siem` | Exports events as an audit trail to Splunk HEC, syslog (JSON or CEF) and Elasticsearch/OpenSearch |
| [`chat-notify`](https://github.com/AimTune/tenarium/blob/main/plugins/chatnotify/README.md) | `chatnotify` | Posts messages about events to Slack and Microsoft Teams |
| [`logger`](#logger) | `logger` | Logs matching events; a template for new plugins |

**Billing, usage and CRM**

| ID | Package | What it does |
|---|---|---|
| [`stripe`](#stripe) | `stripe` | Syncs Stripe customers and subscriptions, suspends and resumes tenants from billing events, reports usage to meters |
| [`chargebee`](https://github.com/AimTune/tenarium/blob/main/plugins/chargebee/README.md) | `chargebee` | The same for Chargebee (API v2, Product Catalog 2.0) |
| [`paddle`](https://github.com/AimTune/tenarium/blob/main/plugins/paddle/README.md) | `paddle` | The same for Paddle Billing (subscriptions come from Paddle checkouts) |
| [`lago`](https://github.com/AimTune/tenarium/blob/main/plugins/lago/README.md) | `lago` | Exports closed usage periods to Lago and optionally syncs customers |
| [`openmeter`](https://github.com/AimTune/tenarium/blob/main/plugins/openmeter/README.md) | `openmeter` | Exports closed usage periods to OpenMeter as CloudEvents |
| [`orb`](https://github.com/AimTune/tenarium/blob/main/plugins/orb/README.md) | `orb` | Exports closed usage periods to Orb |
| [`hubspot`](https://github.com/AimTune/tenarium/blob/main/plugins/hubspot/README.md) | `hubspot` | Mirrors tenants as HubSpot companies and, optionally, members as contacts |
| [`salesforce`](https://github.com/AimTune/tenarium/blob/main/plugins/salesforce/README.md) | `salesforce` | Mirrors tenants as records of a Salesforce sObject (Account by default) |
| [`segment`](https://github.com/AimTune/tenarium/blob/main/plugins/segment/README.md) | `segment` | Sends tenants (group), users (identify) and events (track) to Segment |

**Provisioning: per-tenant resources**

| ID | Package | What it does |
|---|---|---|
| [`postgres-tenant`](#postgres-tenant) | `pgtenant` | A PostgreSQL schema or database (and role) per tenant, with migrations |
| [`mysql-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/mysqltenant/README.md) | `mysqltenant` | A MySQL 8 / MariaDB database and login user per tenant |
| [`mongodb-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/mongotenant/README.md) | `mongotenant` | A MongoDB database and database user per tenant |
| [`clickhouse-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/clickhousetenant/README.md) | `clickhousetenant` | A ClickHouse database, user, and optional settings profile and quota per tenant |
| [`opensearch-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/opensearchtenant/README.md) | `opensearchtenant` | An index prefix (template, alias, optional role and user) per tenant on OpenSearch or Elasticsearch |
| [`s3-tenant`](#s3-tenant) | `s3tenant` | A bucket, or a prefix in a shared bucket, per tenant on S3 or S3-compatible stores ([README](https://github.com/AimTune/tenarium/blob/main/plugins/s3tenant/README.md)) |
| [`gcs-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/gcstenant/README.md) | `gcstenant` | A Google Cloud Storage bucket or prefix per tenant |
| [`azure-blob-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/azureblob/README.md) | `azureblob` | An Azure Blob Storage container per tenant |
| [`kubernetes-tenant`](#kubernetes-tenant) | `k8stenant` | A Kubernetes namespace with quota, limit range, network policy and role bindings per tenant |
| [`kafka-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/kafkatopic/README.md) | `kafkatopic` | Prefixed Kafka topics and ACLs per tenant, optionally SCRAM credentials and quotas |
| [`rabbitmq-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/rabbitmqvhost/README.md) | `rabbitmqvhost` | A RabbitMQ virtual host, user and permissions per tenant |
| [`nats-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/natsaccount/README.md) | `natsaccount` | A NATS account (operator-mode JWT) per tenant, keys derived from the tenant ID |
| [`vault-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/vault/README.md) | `vault` | A Vault KV v2 prefix, ACL policy and optional AppRole and transit key per tenant |
| [`dns-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/dns/README.md) | `dns` | DNS records per tenant in Route 53 or Cloudflare |
| [`grafana-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/grafanatenant/README.md) | `grafanatenant` | A Grafana organization per tenant, optionally with members, quotas and data sources |
| [`iac-tenant`](https://github.com/AimTune/tenarium/blob/main/plugins/iac/README.md) | `iac` | Per-tenant infrastructure with Terraform/OpenTofu, Pulumi or Crossplane |
| [`keycloak`](#keycloak) | `keycloak` | A Keycloak realm per tenant, and/or Keycloak as the user directory |

**Authentication, authorization and user directories**

| ID | Package | What it does |
|---|---|---|
| [`oidc`](../auth.md#oidc-keycloak-auth0-entra-id-okta-dex-) | `oidc` | Authenticates API callers with OIDC/JWT bearer tokens |
| [`ldap`](../auth.md#ldap--active-directory) | `ldap` | Authenticates API callers with HTTP Basic credentials against LDAP or Active Directory |
| [`rbac`](../auth.md#rbac) | `rbac` | Role-based authorizer: roles from the principal or bindings grant action patterns |
| [`cedar`](https://github.com/AimTune/tenarium/blob/main/plugins/cedar/README.md) | `cedar` | In-process authorizer evaluating Cedar policies |
| [`opa`](https://github.com/AimTune/tenarium/blob/main/plugins/opa/README.md) | `opa` | Authorizer asking an Open Policy Agent server |
| [`openfga`](https://github.com/AimTune/tenarium/blob/main/plugins/openfga/README.md) | `openfga` | Authorizer backed by OpenFGA relationship checks, with tuple sync |
| [`spicedb`](https://github.com/AimTune/tenarium/blob/main/plugins/spicedb/README.md) | `spicedb` | Authorizer backed by SpiceDB permission checks, with relationship sync |
| [`auth0-directory`](https://github.com/AimTune/tenarium/blob/main/plugins/auth0dir/README.md) | `auth0dir` | Keeps platform users in an Auth0 database connection |
| [`entra-directory`](https://github.com/AimTune/tenarium/blob/main/plugins/entradir/README.md) | `entradir` | Keeps platform users in Microsoft Entra ID (members or B2B guests) |
| [`okta-directory`](https://github.com/AimTune/tenarium/blob/main/plugins/oktadir/README.md) | `oktadir` | Keeps platform users in an Okta org |
| [`ldap-directory`](https://github.com/AimTune/tenarium/blob/main/plugins/ldapdir/README.md) | `ldapdir` | Keeps platform users in a writable LDAP directory or Active Directory |
| [`smtp`](#smtp) | `smtp` | Sends invitation and password-reset emails through an SMTP relay |

**Policies and runtimes**

| ID | Package | What it does |
|---|---|---|
| [`policy`](#policy) | `policy` | Simple tenant rules as hooks: reserved slugs, allowed plans, default and required labels |
| [`external`](external.md) | `external` | Hosts an out-of-process plugin in any language (remote or managed) |
| [`wasm`](wasm.md) | `wasm` | Runs sandboxed WebAssembly modules as hooks and event handlers |

`plugins/all` is not a plugin: it imports every package above so they register themselves.

## Built-in plugin reference
Plugins with their own page: [archive](archive.md) (event archive to S3, GCS, Azure Blob or a directory, with read-back and replay).

### kafka

```yaml
- plugin: kafka
  config:
    brokers: [kafka-1:9092, kafka-2:9092]
    topic: tenarium.events
    events: ["tenant.*"]          # glob filter; empty = all events
    mode: structured              # structured (CloudEvent JSON value) | binary (data + ce_* headers)
    client_id: tenarium
    create_topic: {partitions: 6, replication_factor: 3}   # create it if missing
    sasl: {mechanism: SCRAM-SHA-512, username: ..., password: ${KAFKA_PASSWORD}}  # PLAIN | SCRAM-SHA-256/512
    tls: {enabled: true}
```

Records are keyed by tenant ID, so each tenant's events stay ordered within a partition. The
producer is idempotent with `acks=all`. `/readyz` checks broker connectivity.

### webhook

```yaml
- plugin: webhook
  name: billing
  config:
    url: https://billing.internal/hooks/tenarium
    secret: ${BILLING_WEBHOOK_SECRET}   # Standard Webhooks ("whsec_" + base64) or any string
    events: [tenant.created, tenant.deleted, tenant.plan_changed]
    headers: {X-Env: prod}
    timeout: 10s
    max_attempts: 20
```

The body is a CloudEvent (`application/cloudevents+json`). Requests are signed following the
[Standard Webhooks](https://www.standardwebhooks.com) spec (`webhook-id`, `webhook-timestamp`,
`webhook-signature: v1,<base64 HMAC-SHA256>`), so any Standard Webhooks library can verify them.
Responses other than 2xx are retried.

### redis

Three independent features; enable any combination.

```yaml
- plugin: redis
  config:
    addr: redis:6379
    password: ${REDIS_PASSWORD}
    key_prefix: "tenarium:"
    publish:                      # events → Redis Streams (or pub/sub)
      mode: stream                # stream | pubsub
      stream: events              # key: tenarium:events (or tenarium:events:<tenant> with per_tenant)
      events: ["tenant.*"]
      max_len: 100000             # approximate trimming
      per_tenant: false
    cache: {ttl: "0"}             # tenant state cache, see below
    acl:                          # a Redis ACL user per tenant
      username_template: "tenant-{{.Slug}}"
      key_pattern: "t:{{.Slug}}:*"
      channels: "t:{{.Slug}}:*"
      password_secret: ${REDIS_TENANT_SECRET}
      commands: "+@all -@admin -@dangerous"
      purge_keys_on_delete: false
      save: true                  # ACL SAVE after changes (needs an aclfile)
```

- **publish**: stream entries have the fields `type`, `id`, `tenant`, `seq` and `event` (the
  CloudEvent JSON). Delivery is at least once, so consumers dedupe on `id`. Pub/sub is
  fire-and-forget on Redis' side.
- **cache**: keeps `tenarium:tenant:<id>` (status, plan, labels, effective features and limits,
  version) and `tenarium:tenant-slug:<slug>` up to date, so your services can check a tenant's
  status and entitlements with one `GET` instead of calling Tenarium. Writes are guarded by the
  tenant version, so a replayed old event never overwrites newer state. Plan changes re-cache
  every tenant on the plan. Go services can use `redis.ReadTenant(ctx, client, prefix, idOrSlug)`.
  `POST /v1/plugins/redis/resync` rebuilds the cache (platform callers only).
- **acl**: each tenant gets an ACL user restricted to its key and channel patterns. The password
  is derived as `hex(HMAC-SHA256(password_secret, tenant_id))[:32]`, so your application derives
  it too (`redis.TenantPassword`), and Tenarium stores no secrets. Users are tagged with their
  tenant and never taken over or removed for another tenant. ACLs are per node: on replicas or
  Cluster, apply them on every node or manage them with ACL files.

### smtp

Sends invitation and password-reset emails (an `sdk.Mailer`, see [users](../users.md)).

```yaml
- plugin: smtp
  config:
    host: smtp.example.com
    port: 587                     # 465 with tls: implicit
    tls: starttls                 # starttls (required) | implicit | none (needs allow_insecure)
    username: apikey
    password: ${SMTP_PASSWORD}
    from: "Acme Cloud <no-reply@acme.example>"
    reply_to: support@acme.example
    headers: {List-Unsubscribe: "<mailto:unsubscribe@acme.example>"}
    timeout: 15s
```

Messages are multipart (text and HTML) with UTF-8 subjects. Header injection is rejected, and
`/readyz` checks that the server is reachable.

### postgres-tenant

```yaml
- plugin: postgres-tenant
  config:
    dsn: postgres://admin:${PG_ADMIN_PASSWORD}@app-db:5432/app
    mode: schema                    # schema (one schema per tenant) | database
    name_template: "tenant_{{.Slug}}"
    create_role: true               # NOLOGIN role owning the schema/database
    migrations_dir: /migrations     # *.sql, applied in order, tracked per tenant
    on_deprovision: rename          # drop | keep | rename (to <name>_deleted_<unix>)
```

Names longer than PostgreSQL's 63-byte limit are shortened with a hash of the tenant ID, so
two tenants never share a name. Every role, schema and database is tagged with its tenant (a
`COMMENT`): the plugin never adopts or removes an object that belongs to another tenant, for
example when a slug is reused after `on_deprovision: keep` (provisioning then fails with a clear
reason instead).

Migration files may use `{{.Schema}}`, `{{.Database}}`, `{{.Name}}`, `{{.TenantID}}` and
`{{.Slug}}`. A migration runs in a transaction with `search_path` set to the tenant schema (and,
with `create_role`, as the tenant role, so the objects it creates belong to it). New files are
applied to existing tenants the next time they are provisioned. `GET
/v1/plugins/{instance}/tenants/{tenant}` returns a tenant's schema or database and its role.

### keycloak

```yaml
- plugin: keycloak
  config:
    url: http://keycloak:8080
    username: admin                  # or client_id + client_secret (client_credentials)
    password: ${KEYCLOAK_ADMIN_PASSWORD}
    realm_template: "tenant-{{.Slug}}"
    client: {client_id: app, redirect_uris: ["https://app.example.com/*"], web_origins: ["+"]}
    delete_realm_on_deprovision: true
    sync_members: true               # members become realm users with VERIFY_EMAIL/UPDATE_PASSWORD
    sync_status: true                # suspended tenant → realm disabled
    provision_realms: true           # false: only the user directory below
    users:                           # optional: Keycloak as Tenarium's user directory
      realm: platform
      client_id: tenarium            # enables password verification (direct grant)
      client_secret: ${KC_SECRET}
      send_invitation: true
```

With a `users` block, set `users.directory: keycloak` in Tenarium's configuration to keep user
identities and passwords in Keycloak. See [users](../users.md).

### kubernetes-tenant

Gives every tenant its own Kubernetes namespace with a ResourceQuota, a LimitRange, a
NetworkPolicy and RoleBindings (package `plugins/k8stenant`).

```yaml
- plugin: kubernetes-tenant
  config:
    kubeconfig: ""                    # empty: in-cluster config, else $KUBECONFIG / ~/.kube/config
    context: ""                       # kubeconfig context
    qps: 20                           # client rate limit (client-go defaults when 0)
    burst: 40
    name_template: "tenant-{{.Slug}}" # default; sanitized to a DNS-1123 label
    labels: {team: "{{.Slug}}"}       # extra namespace labels (templates over the tenant)
    annotations: {owner: "{{.Name}}"}
    quota:                            # ResourceQuota resource → Tenarium limit name
      requests.cpu: cpu_cores
      requests.memory: memory_gib
      pods: pods
    quota_units: {memory_gib: Gi}     # suffix appended to the limit value
    limit_range:                      # default container requests/limits
      default: {cpu: 500m, memory: 512Mi}
      default_request: {cpu: 100m, memory: 128Mi}
    network_policy: isolate           # isolate (default) | none
    allow_from_namespace_labels:      # also admit ingress from these namespaces
      kubernetes.io/metadata.name: ingress-nginx
    role_bindings:                    # bind a ClusterRole to a group or a user (exactly one)
      - role: edit
        group: "tenant:{{.Slug}}:developers"
      - name: tenarium-viewer         # default name: tenarium-<role>
        role: view
        user: "{{.Slug}}-auditor"
    on_deprovision: delete            # delete (default) | keep
    suspend_scale_to_zero: true
```

- **Provision** creates the namespace (or updates its labels and annotations) and then
  converges `tenarium-quota` (ResourceQuota), `tenarium-defaults` (LimitRange),
  `tenarium-isolate` (NetworkPolicy) and the RoleBindings. Every step is idempotent. Objects
  whose configuration was removed are deleted if the plugin created them. RoleBindings the
  plugin created that are no longer configured are deleted too.
- **Names.** Names longer than 63 characters are shortened and suffixed with a hash of the
  tenant ID. Use only immutable fields (`ID`, `Slug`) in `name_template`: the name is
  recomputed on deprovision and on events. A template that renders the same name for two
  tenants is rejected at startup.
- **Ownership.** The namespace and every object in it carry the labels
  `app.kubernetes.io/managed-by: tenarium`, `tenarium.io/tenant-id`, `tenarium.io/tenant-slug`
  and `tenarium.io/plan`; these keys cannot be set through `labels`. A namespace that exists
  without the tenant-ID label, or with another tenant's ID, is never adopted (provisioning
  fails) and never deleted.
- **Quota.** Each `quota` entry takes the tenant's effective limit of that name, appends
  `quota_units[limit]`, and sets it as the ResourceQuota's hard limit. Limits the tenant does
  not have (or negative ones) are left out, which means unlimited. If nothing is limited, no
  ResourceQuota is created.
- **Network policy.** `isolate` allows ingress only from pods in the same namespace and from
  namespaces that match `allow_from_namespace_labels`. Egress is not restricted.
- **Events.** On `tenant.updated` and `tenant.plan_changed`, the namespace labels, quota,
  limit range, network policy and bindings are synced again. With `suspend_scale_to_zero`,
  `tenant.suspended` scales every Deployment and StatefulSet in the namespace to zero and keeps
  the previous replica count in the `tenarium.io/replicas-before-suspend` annotation.
  `tenant.resumed` restores it. Handlers act on the tenant's current state, so a replayed event
  does not undo a later change.
- **Deprovision.** `delete` deletes the namespace (foreground propagation). `keep` leaves it
  in place and adds the annotation `tenarium.io/deleted-at`.
- `GET /v1/plugins/{instance}/tenants/{tenant}` returns the namespace, its phase (`Active`,
  `Terminating`, `Missing`, or `Conflict` if another owner holds the name) and the quota's hard
  and used values. `/readyz` checks that the API server can be reached.

The service account needs these permissions (a ClusterRole bound with a ClusterRoleBinding):

```yaml
rules:
  - apiGroups: [""]
    resources: [namespaces]
    verbs: [get, create, update, delete]
  - apiGroups: [""]
    resources: [resourcequotas, limitranges]
    verbs: [get, create, update, delete]
  - apiGroups: [networking.k8s.io]
    resources: [networkpolicies]
    verbs: [get, create, update, delete]
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [rolebindings]
    verbs: [get, list, create, update, delete]
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [clusterroles]
    verbs: [bind]
    resourceNames: [edit, view]       # the roles named in role_bindings
  - apiGroups: [apps]                 # only with suspend_scale_to_zero
    resources: [deployments, statefulsets]
    verbs: [get, list, update]
```

Kubernetes only lets a subject create a RoleBinding to a ClusterRole if it holds the
role's permissions or has the `bind` verb on that role. The `bind` rule above covers this.

### s3-tenant

Gives every tenant its own bucket, or its own key prefix in a shared bucket, on Amazon S3 or an
S3-compatible store such as MinIO, Ceph RGW or Cloudflare R2 (package `plugins/s3tenant`).

```yaml
- plugin: s3-tenant
  config:
    endpoint: s3.eu-central-1.amazonaws.com   # host[:port], no scheme (required)
    region: eu-central-1
    access_key: ${S3_ACCESS_KEY}              # required
    secret_key: ${S3_SECRET_KEY}              # required
    secure: true                              # HTTPS (default true)
    mode: bucket                              # bucket (default) | prefix
    # bucket: shared-tenant-data              # the existing shared bucket; prefix mode only
    name_template: "tenant-{{.Slug}}"         # default
    versioning: true                          # bucket mode only
    object_lock: false                        # bucket mode only; at creation, implies versioning
    lifecycle_expire_days: 0                  # bucket mode only; 0 = never
    quota_from_limit: storage_gb              # limit recorded as tag tenarium-quota-gb
    on_deprovision: delete                    # delete (default) | keep | retain
    policy_template: |                        # bucket mode only; must render valid JSON
      {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:role/tenant-{{.Tenant.Slug}}"},
        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        "Resource": "arn:aws:s3:::{{.Bucket}}/*"}]}
```

- **Names.** Rendered names are sanitized to valid bucket names: lowercase letters, digits and
  hyphens, 3 to 63 characters. Dots are also replaced because they break virtual-hosted-style
  requests over TLS. Names that are too short or too long get a hash of the tenant ID. As with
  the other provisioners, use only `ID` and `Slug` in `name_template`. In prefix mode the
  tenant's prefix is `<name>/`.
- **Ownership.** A bucket is tagged `tenarium-tenant-id=<id>`. A prefix gets a marker object
  `<name>/.tenarium-owner` whose content is the tenant ID. Resources marked for another tenant
  are never adopted or deleted. An unmarked bucket or prefix is adopted only if it is empty,
  which is what an interrupted provisioning run leaves behind.
- **Bucket options.** In bucket mode, `versioning` enables versioning, `object_lock` creates
  the bucket with Object Lock, and `lifecycle_expire_days` maintains a lifecycle rule named
  `tenarium-expire` that expires objects (and noncurrent versions when versioning or object
  lock is on) after N days. Other rules are kept. `policy_template` is a template over
  `{Tenant, Bucket, Prefix}`. In prefix mode these options are rejected because they would
  apply to every tenant in the bucket. Configure the shared bucket directly instead.
- **Quota.** S3 has no storage quotas. With `quota_from_limit`, the tenant's limit of that
  name (read as gigabytes) is written as the bucket tag `tenarium-quota-gb` (in prefix mode, as
  user metadata on the owner marker) for your own tooling to enforce. Unlimited tenants get no
  tag. The value is written when the tenant is provisioned. The plugin does not subscribe to
  plan changes, so retry provisioning to update it.
- **Deprovision.** `delete` removes every object, version and delete marker, and then the
  bucket. In prefix mode the owner marker is removed last, so an interrupted run can be retried.
  `keep` changes nothing, and the ownership marker stays, so a new tenant with the same slug
  cannot take over the data. `retain` keeps the data but releases ownership: the bucket tag
  is replaced by `tenarium-deleted-at` and `tenarium-deleted-tenant-id`, or in prefix mode the
  marker is replaced by `<name>/.tenarium-retained`. Provisioning a tenant whose name collides
  with retained data then fails until an operator moves or removes the data.
- `GET /v1/plugins/{instance}/tenants/{tenant}` returns `mode`, `bucket`, `prefix` and
  `endpoint`. `/readyz` lists buckets (bucket mode) or checks that the shared bucket exists
  (prefix mode).

IAM permissions for bucket mode (resource `arn:aws:s3:::tenant-*` and `arn:aws:s3:::tenant-*/*`
with the default template):

```
s3:ListAllMyBuckets                                         (readiness check, resource "*")
s3:CreateBucket  s3:DeleteBucket  s3:ListBucket  s3:ListBucketVersions
s3:GetBucketTagging  s3:PutBucketTagging
s3:GetBucketVersioning  s3:PutBucketVersioning
s3:GetLifecycleConfiguration  s3:PutLifecycleConfiguration  (lifecycle_expire_days)
s3:PutBucketPolicy                                          (policy_template)
s3:PutBucketObjectLockConfiguration                         (object_lock)
s3:DeleteObject  s3:DeleteObjectVersion                     (on_deprovision: delete)
```

For prefix mode, grant `s3:ListBucket`, `s3:ListBucketVersions` and `s3:GetBucketVersioning` on
the shared bucket, and `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` and
`s3:DeleteObjectVersion` on its objects. Objects under Object Lock retention cannot be deleted
before the retention ends, so `on_deprovision: delete` fails for them until then.

### stripe

Keeps Stripe customers and subscriptions in step with tenants, and suspends or resumes tenants
based on Stripe billing events. It calls the Stripe REST API directly.

```yaml
- plugin: stripe
  config:
    api_key: ${STRIPE_API_KEY}          # sk_... or restricted rk_... (required)
    webhook_secret: ${STRIPE_WHSEC}     # whsec_..., the endpoint's signing secret (required)
    plans:                              # Tenarium plan ID → Stripe price ID
      pro: price_1PxyzPro
      enterprise: price_1PxyzEnt
    create_customers: true              # default; false: only use customers already tagged
    trial_days: 14
    collection_method: charge_automatically   # default | send_invoice
    # days_until_due: 30                # send_invoice only (default 30)
    cancel_at_period_end_on_delete: false
    suspend_on:                         # default shown
      - customer.subscription.deleted
      - customer.subscription.paused
    suspend_on_past_due: true           # also suspend on past_due / unpaid
    resume_on_payment: true             # default
    sync_plan_from_stripe: true         # default
    meters:                             # usage metric -> Stripe meter event name
      api_calls: api_requests
    timeout: 15s                        # per API request (default)
    # api_base: https://api.stripe.com  # default
```

Tenarium to Stripe (event subscription `sync`):

- `tenant.created` finds or creates the tenant's customer. If the tenant's plan is in `plans`,
  it also creates a subscription to that price.
- `tenant.plan_changed` swaps the subscription's price (with prorations), creates a
  subscription if there is none, or cancels it if the new plan is not in `plans`.
- `tenant.updated` copies a changed name or slug to the customer.
- `tenant.deleted` cancels the tenant's subscriptions, either immediately or with
  `cancel_at_period_end_on_delete` at the end of the period. The customer is kept for its
  billing history.

The plugin stores nothing locally. Customers and subscriptions carry the tenant ID in
`metadata.tenarium_tenant_id`, and customers also carry `metadata.tenarium_slug`. Customers
are looked up with Stripe's search API, which is eventually consistent. Creations therefore use
idempotency keys derived from the tenant and event IDs, so redelivered events converge on the
same objects. Other subscriptions of the customer, such as add-ons whose price is not in `plans`
and which are not tagged with the tenant, are left alone.

Stripe to Tenarium (webhook):

- Events listed in `suspend_on` suspend the tenant with the status reason
  `billing: <event type>`. A subscription event is ignored if the subscription has become active
  again since. `customer.subscription.deleted` is also ignored if the customer has another
  active plan subscription.
- With `suspend_on_past_due`, a subscription that becomes `past_due` or `unpaid` suspends the
  tenant.
- With `resume_on_payment`, `invoice.paid` and a subscription that becomes `active` or
  `trialing` resume the tenant, but only if its status reason starts with `billing:`.
  `invoice.paid` is skipped while the invoice's subscription is in any other state, for example
  while other invoices are still open. Tenants suspended for other reasons stay suspended.
- With `sync_plan_from_stripe`, a subscription whose price changed in Stripe (created, or
  updated with changed items) moves the tenant to the plan mapped to that price. Plan
  changes rejected by a hook are logged and skipped.
- Tenants on a plan without a price are never suspended for billing, so canceling the
  subscription after a downgrade to a free plan is harmless.

Usage to Stripe (event subscription `meters`, only with `meters` configured):

- Each `tenant.usage_period_closed` event of a metric listed in `meters` is sent as a
  [billing meter event](https://docs.stripe.com/billing/subscriptions/usage-based) to the
  mapped meter: `payload[value]` is the period total, `payload[stripe_customer_id]` the
  tenant's customer, and the timestamp is one second before the period end, so the usage
  lands on the right invoice. Configure the meter with `sum` aggregation and attach a metered
  price to the plan's subscription.
- The identifier and idempotency key are `tenarium-<tenant>-<metric>-<period>`, so a
  redelivered event is never billed twice.
- Zero totals are not sent. If the tenant has no customer while `create_customers` is on, the
  delivery fails (and ends in the dead-letter queue after retries) instead of dropping usage;
  with `create_customers: false` such tenants are skipped.
- Periods come from `usage.metrics` (see [tenant lifecycle](../tenants.md#usage-periods-soft-limits-and-billing-export)):
  a metric with `period: month` is reported once a month. Restricted keys also need write
  access to meter events.

Webhook setup: in the Stripe dashboard (Developers → Webhooks), add an endpoint with the URL

```
https://<tenarium-host>/v1/plugins/stripe/public/webhook
```

Replace `stripe` with the instance `name` if you set one. Public plugin routes are mounted under
`/v1/plugins/{instance}/public/` outside the authentication chain. The plugin verifies the
`Stripe-Signature` header with `webhook_secret` itself and accepts timestamps up to 5 minutes
old. While a secret is being rolled, any matching `v1` signature is accepted. Subscribe the
endpoint to `customer.subscription.created`, `customer.subscription.updated`,
`customer.subscription.deleted`, `customer.subscription.paused`, `invoice.paid`, and any other
types in `suspend_on`. Other event types are acknowledged and ignored. A failure returns 500 so
Stripe retries. Event IDs already processed are remembered in memory (the last 10,000 per
replica) and answered as duplicates. Bodies are limited to 1 MiB.

A restricted key (`rk_...`) needs write access to Customers and Subscriptions and read access
to Balance, which the readiness check calls (`GET /v1/balance`).
`GET /v1/plugins/{instance}/tenants/{tenant}` returns the tenant's `customer_id`,
`subscription_id`, `status`, `price` and `current_period_end`, or 404 if the tenant has no
customer.

### oidc, ldap, rbac

See [Authentication and authorization](../auth.md).

### policy

```yaml
- plugin: policy
  config:
    reserved_slugs: [www, admin, api]
    allowed_plans: [free, pro, enterprise]
    default_plan: free
    default_labels: {managed-by: tenarium}
    required_labels: [region]
```

### external

Hosts an out-of-process plugin. See [External plugins](external.md).

### wasm

Runs a WebAssembly module as hooks or event handlers. See [WebAssembly plugins](wasm.md).

### logger

Logs matching events (`events: ["tenant.*"]`). A good template for new plugins.
