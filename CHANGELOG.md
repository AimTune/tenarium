# Changelog

## Unreleased

First public version.

- Tenant lifecycle with hierarchy, labels, schema-validated settings, optimistic locking and
  idempotent creates.
- Plans, entitlements, per-tenant overrides, usage quotas, members and invitations.
- PostgreSQL store with a gap-free transactional outbox; in-memory store for development.
- Event dispatcher with per-subscription cursors, retries, dead-letter queue, replay, and leases
  for running several replicas.
- Authentication (API keys, OIDC, LDAP) and authorization (RBAC, built-in tenant scope).
- Plugin SDK with built-in, external (HTTP/JSON) and WASM runtimes; Go, TypeScript and Python
  SDKs; `tenarium-build` for custom binaries.
- Plugins: kafka, webhook, postgres-tenant, keycloak, oidc, ldap, rbac, policy, external, wasm,
  logger.
- Admin UI, OpenAPI 3.1 spec, Prometheus metrics, Docker image and Helm chart.
- Users: platform-wide users with memberships, invitations, password reset, lockout, per-IP
  rate limiting, Tenarium-issued JWTs with rotating refresh tokens, OIDC discovery and JWKS,
  built-in role tables, `user.*` hooks and events, and pluggable user directories
  (`UserDirectory`) and mailers (`Mailer`).
- Plugins: redis (streams, tenant cache, ACL per tenant), smtp, and a Keycloak user directory.
- Tenant lifecycle: scheduled actions (`suspend`, `resume`, `set_plan`, `delete`) and trials
  set up at creation; soft deletion with `tenants.deletion_grace_period` and
  `POST /v1/tenants/{id}/restore`; `tenants:purge` for immediate deletion.
- Custom domains with DNS TXT verification, `/v1/domains/resolve` and an on-demand TLS check;
  `tenants.reserved_domains`.
- Tenant and platform API keys (`tnr_...`): hashed, expiring, role-limited, tenant-scoped.
- Two-factor authentication: TOTP with replay protection and recovery codes; admin reset.
- Per-tenant OpenID Connect single sign-on: email domains proven by verified domains,
  auto-provisioning, enforcement with a break-glass path, PKCE, nonce and SSRF protection.
- Self-service tenant webhooks: Standard Webhooks signatures, retries, delivery log,
  redelivery, test events, secret rotation, auto-disabling and SSRF protection.
- Audit trail API (`/v1/audit`, `/v1/tenants/{id}/audit`); event retention that never drops
  unprocessed events.
- Signing key API (`/v1/signing-keys`), automatic rotation and retirement, reload on unknown
  key IDs across replicas.
- OpenTelemetry tracing (OTLP/HTTP) for API requests, event deliveries and outgoing calls.
- Plugins: stripe (customer and subscription sync, dunning, plan sync from Stripe),
  s3-tenant (bucket or prefix per tenant), kubernetes-tenant (namespace, quotas, network
  policy, RBAC).
- Go API client (`pkg/client`), `tenariumctl` CLI, and tenant middleware for Go
  (`pkg/tenantmw`), TypeScript and Python.
- Usage periods (daily, monthly, yearly counters with history), soft limits (`overage:
  allow`), threshold events (`tenant.usage_threshold_reached`) and exactly-once
  `tenant.usage_period_closed` events; `GET /v1/tenants/{id}/usage/{metric}/history`.
- Stripe plugin: usage export to Stripe billing meters (`meters`).
- SCIM 2.0 per tenant (`/v1/tenants/{id}/scim/v2`): users as memberships, groups as tenant groups,
  PatchOp including Entra ID quirks; suspended memberships (`active: false`).
- Admin UI: schedule, domains, API keys, webhooks (with delivery log), SSO and audit tabs per
  tenant; audit, signing key and account security (two-factor) pages; restore banner for
  tenants pending deletion.
- Identity: passkeys (WebAuthn) as second factor and for passwordless sign-in; per-tenant SAML
  SSO next to OIDC; custom tenant roles built from the action list and groups, with escalation
  prevention (also for member roles); impersonation with consent, time limits and an audited
  actor; magic-link sign-in; social login (Google, GitHub, Microsoft, any OIDC provider);
  breached-password check (HIBP k-anonymity); email change with confirmation; session and
  device list with remote sign-out.
- Tenarium as an OpenID Connect provider: authorization code + PKCE, consent, first-party
  clients, userinfo, discovery; refresh tokens bound to their client.
- Authorizer plugins for OpenFGA, SpiceDB, OPA and Cedar.
- Commercial: plan revisions and grandfathering, add-ons, percentage/cohort feature rollouts
  (`/v1/rollouts`, `rollout.*` events), billing-cycle usage periods (`period: cycle`,
  `billing_anchor`); metering exports to Lago, Orb, OpenMeter and Stripe meter events; Paddle and
  Chargebee plugins.
- Tenant lifecycle: data residency (`tenants.regions`, region-scoped plugins,
  `POST /v1/tenants/{id}/move`), tenant templates and cloning, maintenance windows (read-only for
  tenant callers), branding (with a public endpoint for sign-in pages) and health scores.
- GDPR: tenant and user export, user erasure with event redaction, purge of deleted tenants.
- Managed certificates via ACME (`server.tls`); KMS envelope encryption of signing keys, MFA
  secrets, webhook and SSO secrets and the key-value table (`secrets`).
- Events: schema registry (`/v1/event-schemas`), W3C trace context on events with producer
  links on delivery spans, replay by time range (`POST /v1/events/replay`), and the `archive`
  plugin (S3, GCS, Azure Blob or files; read-back and signed replay).
- Plugins: NATS JetStream, RabbitMQ, SQS/SNS/EventBridge, Google Pub/Sub and Azure Service Bus
  publishers; GCS, Azure Blob, per-tenant IAM, Route 53/Cloudflare DNS, Vault, Kafka topics,
  RabbitMQ vhosts, NATS accounts, MySQL, MongoDB, ClickHouse, OpenSearch and Grafana
  provisioners; generic IaC provisioner (Terraform/OpenTofu/Pulumi/Crossplane); SIEM export;
  Slack/Teams notifications; HubSpot, Salesforce and Segment sync; Auth0, Entra ID, Okta and
  LDAP user directories.
- External plugins (and the TypeScript/Python SDKs) can provide user directories and mailers.
- Config hot reload (SIGHUP, `POST /v1/admin/reload`): log level and plugins implementing
  `sdk.Reconfigurer` (webhook, smtp) apply live; other changes are reported as needing a restart.
- Generated TypeScript and Python API clients; gateway (Envoy, NGINX, Traefik) with per-tenant
  cells and rate limits; PostgreSQL row-level security helpers; Kubernetes operator and
  Terraform provider.
- Admin UI: dashboard, roles and groups, passkeys, SAML, GDPR, impersonation, OAuth clients,
  event schemas, rollouts, plan revisions, placement, templates, cloning, maintenance, branding,
  health, sessions and social/magic-link sign-in; English and Turkish. Documentation website (Docusaurus) at https://tenarium.aimtune.dev.
- Testing: fuzzing of the API validation, plugin protocol and SSRF guard, k6 load tests and
  chaos tests for failover.
- Multi-region: tenant region in access tokens (`region` claim) and `/v1/domains/resolve`; lease
  affinity (`events.region`); read replicas for list queries (`store.read_dsn`); shared auth rate
  limits (`auth.rate_limit_shared`); region moves with reprovisioning (`reprovision: true`);
  usage grants for regional quota shares, with `client.Allowance` in the Go client.
- Events carry the CloudEvents `dataschema` attribute.
- `tenarium -reencrypt` re-encrypts every stored secret after a key rotation or provider change.
- Config reload also applies `auth.rate_limit`, `tenants.regions` and `usage.metrics`, and 22
  plugins apply their configuration live (billing, CRM, metering, authorizers, notifications,
  SIEM and the message publishers).
- Admin UI browser tests (Playwright) in CI.
- Admin UI: table rows are keyboard accessible (links and buttons in the first cell, Enter/Space
  for row details); the events page keeps focus and open details while it refreshes; SSO sign-in
  explains a missing connection in the form; browser tests for passkeys (virtual authenticator),
  tenant OIDC SSO and social sign-in against a fake identity provider.
- Go client and `tenariumctl`: regions, add-ons, templates, branding, billing anchor, moves,
  cloning, maintenance windows, health, plan revisions and grandfathering, rollouts and templates.
- Terraform provider: tenant `add_ons`, `region` (moves instead of replacing), `billing_anchor`,
  `branding`, `plan_revision` and `template`; `grandfather_on_update` on plans; new
  `tenarium_rollout` and `tenarium_tenant_template` resources and `tenarium_plan_revisions` /
  `tenarium_tenant_health` data sources. Operator: the same tenant fields with region, maintenance
  and health in status, and new `Rollout` and `TenantTemplate` resources.
- Billing anchors can be removed (`clear_billing_anchor`; `--clear-billing-anchor` in
  `tenariumctl`, `billing_anchor = ""` in Terraform, removing `billingAnchor` in the operator).
- The operator takes over a remote rollout or template identical to its spec (e.g. after a lost
  status write) without the adopt annotation; its API package no longer depends on
  controller-runtime.
- Helm chart: `events.instance_id` defaults to the pod name; `read_dsn` and `events.region` are
  documented in the values. Website build-time dependencies no longer have critical advisories.
