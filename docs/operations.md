# Operations

## Deploying

**Docker**

```sh
docker run -p 8080:8080 -v $PWD/config.yaml:/etc/tenarium/config.yaml:ro \
  -e TENARIUM_API_KEY=... ghcr.io/aimtune/tenarium:latest
```

The image is distroless, runs as non-root and needs no writable filesystem. It is about 43 MB.

**Kubernetes (Helm)**

```sh
helm install tenarium deploy/helm/tenarium \
  --set secretEnv.TENARIUM_API_KEY=$(openssl rand -hex 24) \
  --set secretEnv.TENARIUM_DATABASE_URL='postgres://tenarium:...@db:5432/tenarium?sslmode=require'
```

The chart's `config:` value is the Tenarium config file. Secrets are passed as environment
variables (`secretEnv`, or your own Secret via `existingSecret`) and referenced from the config
as `${NAME}`. The chart defaults to 2 replicas, a PodDisruptionBudget, a read-only root
filesystem, liveness and readiness probes, and an optional ServiceMonitor and HPA.

**docker compose**: see the repository's `docker-compose.yaml` for a full local stack with
PostgreSQL, Redpanda and (with `--profile keycloak`) Keycloak.

## PostgreSQL

- Tenarium creates and migrates its schema at startup (an advisory lock makes concurrent starts
  safe). Give it its own database, or a user whose `search_path` points at a dedicated schema.
- Back up the database as usual. The event log is part of the state: restoring a backup rewinds
  the subscription cursors along with everything else, so after a restore subscribers may get
  some events again. They are idempotent by contract.
- The event log grows until `events.retention` is set. Each tenant event stores the tenant
  before and after the change, so plan disk space accordingly, and archive events with a plugin
  (kafka, webhook, siem) if you need them longer than the retention.
- With [managed certificates](tls.md), certificates and the ACME account key live in the `kv`
  table: back it up with the rest, or every hostname is issued again after a restore.

## Scaling and high availability

Run as many replicas as you like against one database. All replicas serve the API. Each event
subscription is processed by one replica at a time under a lease (`events.lease_ttl`, default
15s); when a replica dies another takes over within that time. Set `events.instance_id` to the
pod name so the lease holder is easy to identify.

Besides subscriptions, every replica runs a few background jobs. They are safe to run
everywhere at once:

| Job | What it does | Config |
|---|---|---|
| Scheduler | runs due [scheduled actions](tenants.md#scheduled-actions-and-trials); each action is claimed by one replica, and re-run after 5 minutes if that replica died mid-way. Also closes ended [usage periods](tenants.md#usage-periods-soft-limits-and-billing-export) and, at most once an hour, [purges deleted tenants](privacy.md#purging-deleted-tenants) | `scheduler.interval` (0 disables it on that replica), `tenants.purge_after` |
| Event retention | deletes events older than the retention **only once every subscription has processed them**, so a stuck subscriber holds events back instead of losing them | `events.retention`, `events.prune_interval` |
| Signing keys | reloads keys every minute, rotates on schedule, retires keys whose tokens have all expired | `auth.tokens.rotation_period` |
| Webhook log pruning | drops tenant webhook deliveries older than the retention | `webhooks.delivery_retention` |

Adding a plugin or enabling tenant webhooks creates a new subscription. Webhooks start at the
end of the log; other new subscriptions start from the oldest retained event unless they ask to
start at the end.

Several regions are covered in [multi-region deployments](multi-region.md).

## Health and metrics

- `GET /healthz`: liveness (the process is up).
- `GET /readyz`: readiness. Checks the store and every plugin that implements a health check
  (for example Kafka, Keycloak or the target PostgreSQL), and returns 503 if one fails. The
  response only says `ok` or `fail` per check; details go to the log, since the endpoint is
  unauthenticated.
- `GET /metrics`: Prometheus metrics.

| Metric | Meaning |
|---|---|
| `tenarium_http_requests_total{method,route,status}` | API traffic |
| `tenarium_http_request_duration_seconds{method,route}` | API latency |
| `tenarium_event_deliveries_total{subscription}` | successful deliveries |
| `tenarium_event_delivery_failures_total{subscription}` | failed attempts (retried) |
| `tenarium_dead_letters_total{subscription}` | events given up on |
| `tenarium_subscription_lag_events{subscription}` | events not yet processed |
| `tenarium_subscription_lease_held{subscription}` | 1 on the replica processing it |
| `tenarium_event_delivery_duration_seconds{subscription}` | handler latency |
| `tenarium_hook_rejections_total{point,plugin}` | operations refused by hooks |
| `tenarium_provisioning_runs_total{operation,result}` | provisioning outcomes |

Suggested alerts:

- `increase(tenarium_dead_letters_total[15m]) > 0`
- `max by (subscription) (tenarium_subscription_lag_events) > 1000` for 10m
- `sum by (subscription) (tenarium_subscription_lease_held) == 0` for 5m (nobody processing)
- `increase(tenarium_provisioning_runs_total{result="failure"}[1h]) > 0`

## Tracing

With `tracing.enabled`, Tenarium exports OpenTelemetry traces over OTLP/HTTP (to
`tracing.endpoint`, or as set by the standard `OTEL_EXPORTER_OTLP_*` variables):

- a server span per API request, named after the route (`GET /v1/tenants/{id}`) and continuing
  incoming W3C `traceparent` headers; health checks and metrics scrapes are not traced;
- a consumer span per event delivery attempt (`deliver <subscription>`, with event type, ID,
  sequence number and tenant), which shows plugin handler time and failures;
- client spans for tenant webhook calls and SSO provider requests, which carry `traceparent`
  to the receiver.

Sampling follows the parent when there is one, otherwise `tracing.sample_ratio` (default 1).
Events store the W3C trace context of the request that caused them (`traceparent` and
`tracestate`, the CloudEvents distributed tracing extension). A delivery span starts a new trace
with a **link** to that request's span rather than a parent, since delivery is asynchronous and
may happen several times; external plugins receive the attributes too.

## Dead letters

When a subscriber gives up on an event, the event lands in the dead-letter queue, visible in
the UI (Dead letters) or at `GET /v1/dead-letters`. Fix the cause, then **replay** (deliver to
that subscription again; it is removed on success) or **discard** it.

## Replaying a time range

A consumer that *acknowledged* events it then mishandled (a bug, a wiped downstream store)
leaves nothing in the dead-letter queue. Redeliver the stored events of a time range to that one
subscription instead:

```sh
curl -sX POST $API/v1/events/replay -H "$AUTH" -d '{
  "subscription": "kafka/publish",
  "since": "2026-10-10T08:00:00Z", "until": "2026-10-10T12:00:00Z",
  "types": ["tenant.*"], "tenant_ids": ["<tenant-id>"]}'
# → {"matched": 412, "delivered": 410, "dead_lettered": 2}
```

- `since` is required and must be before `until`; `until` (default: now), `types` (globs) and `tenant_ids` narrow the
  range, and the subscription's own event filter applies on top. Subscription names are
  `<plugin-instance>/<name>` as listed by `GET /v1/plugins`; an unknown one answers 409
  `unknown_subscription`.
- Events are delivered oldest first, each tried **once**; failures become dead letters
  (`dead_lettered`). The subscription's cursor does not move, and its normal delivery continues
  in parallel, so handlers must be idempotent (they are by contract).
- One call replays at most 10,000 events; `truncated: true` means there were more, so call
  again with `since` set after the last replayed event.
- It needs `deadletters:replay`.
- Only events still in the database can be replayed. Events pruned by `events.retention` must
  come from an archive: the [`archive` plugin](plugins/archive.md) reads archived events back by
  time range and replays them to an HTTP endpoint (not to a subscription).

## Logs

Structured logs go to stderr (`log.format: json` in production). Request failures include the
`request_id` that was returned to the client in `X-Request-ID`. Output from managed external
plugins appears in Tenarium's log with `plugin=<instance>`.

## Reloading the configuration

Some settings can change without a restart. Edit the configuration file, then trigger a reload:

```sh
kill -HUP <pid>                                       # or: kubectl exec ... -- kill -HUP 1
curl -sX POST $API/v1/admin/reload -H "$AUTH"         # platform callers only (config:reload)
# → {"applied": ["log.level", "plugins.billing"], "restart_required": ["auth", "plugins.kafka"],
#    "failed": {"plugins.alerts": "events and max_attempts take effect after a restart"}}
```

Both re-read the file Tenarium was started with (`-config` or `TENARIUM_CONFIG`, with `${VAR}`
expanded again). Without a configuration file, SIGHUP is ignored and the endpoint answers 404; a
file that does not parse answers 400 `reload_failed` and changes nothing. SIGHUP reports its
result in the log (`configuration reloaded`).

**Applied live:**

- `log.level`;
- `auth.rate_limit` (the per-IP limit of the sign-in endpoints; `0` turns it off);
- `tenants.regions` and `tenants.default_region` (existing tenants keep their region even if it is
  no longer listed);
- `usage.metrics` (periods, overage policies and thresholds; a counter switches to the new period
  on its next increment);
- the `config` of plugin instances whose plugin implements `sdk.Reconfigurer`: `webhook`,
  `smtp`, the billing plugins (`stripe`, `paddle`, `chargebee`), CRM and metering (`hubspot`,
  `salesforce`, `segment`, `lago`, `orb`, `openmeter`), authorizers and policies (`cedar` and `opa`
  policies reload live, `openfga`, `spicedb`, `policy`), `chatnotify`, `siem`, and the publishers
  (`kafka`, `nats`, `rabbitmq`, `aws`, `gcppubsub`, `azureservicebus`; a new broker connection is
  opened and checked before the switch, and the old one is closed after its in-flight publishes).
  Credentials, endpoints, templates and policies change live; settings that decide subscriptions
  (event filters, attempts, which handlers exist) are reported as failed with the reason.
  The new config is checked against the plugin's schema first.

**Reported in `restart_required`** (the running value stays until the next restart): every
other setting that changed (the rest of `server`, `store`, `auth`, `tenants`, ...),
`log.format`, plugin instances that were added, removed, enabled or disabled, or whose `plugin`
or `scope` changed, and config changes of plugins that do not implement `Reconfigurer`.

**Reported in `failed`:** changes a plugin rejected (invalid values, or settings it cannot
change live) and an invalid log level, with the reason. The old setting stays in effect.

Each change is applied completely or not at all; nothing is half-applied. Reloads are per
process: with several replicas, reload each one (for example a rolling SIGHUP across the pods,
or calling the endpoint on each replica rather than through the load balancer). Replicas that
were not reloaded keep the old values until they are.

## Upgrades

Migrations only move forward and run automatically. During a rolling upgrade old and new
replicas share the database briefly; migrations in a minor release stay compatible with the
previous minor version, and the changelog will call out any exception. Read it before skipping
versions.

## Security checklist

- Use OIDC or LDAP for people and long, random API keys for services. Rotate keys by adding the
  new one, switching clients over, then removing the old one.
- Configure `rbac` (or another authorizer) so that not every authenticated caller is an admin.
- Terminate TLS in front of Tenarium (ingress or load balancer), or let Tenarium serve HTTPS
  itself with a static certificate or [ACME](tls.md).
- External plugins in remote mode need a strong `secret` and should be reachable only from
  Tenarium.
- Treat WASM modules as configuration: review them like code even though they are sandboxed.
- Tenant webhooks and SSO providers are URLs chosen by tenants. Leave
  `webhooks.allow_private_networks`, `webhooks.allow_http` and `auth.sso.allow_private_issuers`
  off in production, so tenants cannot reach internal services.
- Set `tenants.reserved_domains` to your own domains so tenants cannot claim them.
- Webhook secrets, SSO client secrets, TOTP secrets and token signing keys are stored in the
  database. Encrypt them with a KMS ([`secrets`](secrets.md)), restrict database access and
  encrypt backups. Rotate signing keys (`auth.tokens.rotation_period`), and retire a leaked key
  at once with `DELETE /v1/signing-keys/{kid}`.
- Consider `tenants.deletion_grace_period` so a mistaken deletion can be undone, and
  `tenants.purge_after` so deleted tenants' data does not stay forever ([data
  protection](privacy.md)).
- Keep `auth.impersonation.require_consent` on unless your support process covers consent
  otherwise; every impersonated action is audited with both identities.
- `auth.rate_limit` counts per replica (in memory). With N replicas a client gets up to N times
  the limit; rate-limit at the edge as well.
