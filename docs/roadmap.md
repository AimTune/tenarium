# Roadmap

## Done

- Tenant lifecycle, hierarchy, labels, JSON-Schema-validated settings, optimistic locking,
  idempotent creates; plans, entitlements, overrides, usage quotas
- Users and memberships: invitations, password reset, lockout, rate limiting, Tenarium JWTs with
  rotating refresh tokens, OIDC discovery/JWKS, built-in role tables, pluggable user directories
  (internal, Keycloak) and mailers (SMTP)
- Transactional outbox on PostgreSQL with gap-free ordering; dispatcher with per-subscription
  cursors, retries, dead letters, replay and leases for multiple replicas
- Authentication (API keys, user tokens, OIDC, LDAP), authorization (built-in tenant scope and
  roles, RBAC plugin)
- Plugin SDK with nine extension points; built-in, external (HTTP/JSON, any language) and WASM
  runtimes; Go, TypeScript and Python SDKs; `tenarium-build`
- Plugins: kafka, webhook, redis, postgres-tenant, keycloak, oidc, ldap, rbac, policy, smtp,
  external, wasm, logger
- Admin UI, OpenAPI 3.1, Prometheus metrics, Docker image, Helm chart, CI
- Scheduled actions and trials; soft delete with grace period and restore
- Custom domains with DNS TXT verification, on-demand TLS check and host resolution
- Tenant and platform API keys (scoped, hashed, expiring, role-limited)
- Two-factor authentication (TOTP, recovery codes); per-tenant OIDC single sign-on with
  verified email domains, auto-provisioning and enforcement
- Self-service tenant webhooks with Standard Webhooks signatures, delivery log, redelivery and
  SSRF protection
- Audit trail API; event retention; signing key rotation API and automatic rotation;
  OpenTelemetry tracing
- Plugins: stripe (billing sync and dunning), s3-tenant, kubernetes-tenant
- Go API client, `tenariumctl` CLI, tenant middleware for Go, TypeScript and Python
- Usage periods, soft limits, threshold and period-closed events; usage export to Stripe meters
- SCIM 2.0 provisioning per tenant (users as memberships, groups as roles)
- Admin UI views for schedules, domains, API keys, webhooks, SSO, audit, signing keys and
  two-factor authentication

- Passkeys (WebAuthn), per-tenant SAML SSO, custom tenant roles and groups, impersonation with
  consent, Tenarium as a full OpenID Connect provider (authorization code + PKCE, consent)
- Magic links, social login, breached-password check (HIBP k-anonymity), email-change
  verification, session and device list
- Authorizer plugins: OpenFGA, SpiceDB, OPA, Cedar; Auth0, Entra ID, Okta and LDAP user
  directories; user directories and mailers for external plugins
- Metering exports to Lago, Orb, OpenMeter and Stripe meter events; billing-cycle usage periods;
  plan revisions and grandfathering, add-ons; Paddle and Chargebee plugins
- Managed certificates (ACME), data residency (regions, region-scoped plugins, region moves),
  GDPR tooling (export, erasure, purge), feature rollouts
- Tenant templates and cloning, maintenance windows (for migrations between regions or cells),
  branding, tenant health scores
- Provisioners: GCS, Azure Blob, per-tenant IAM, DNS (Route 53, Cloudflare), Vault, Kafka topics,
  RabbitMQ vhosts, NATS accounts, generic IaC (Terraform/OpenTofu/Pulumi/Crossplane), MySQL,
  MongoDB, ClickHouse, OpenSearch, Grafana
- Events: archive to object storage with read-back and replay, replay by time range, schema
  registry, trace context on events; publishers for NATS JetStream, RabbitMQ,
  SQS/SNS/EventBridge, Google Pub/Sub, Azure Service Bus; Slack/Teams, HubSpot, Salesforce,
  Segment; SIEM export of the audit trail
- Generated TypeScript and Python clients, gateway (Envoy, NGINX, Traefik), PostgreSQL row-level
  security helpers, Kubernetes operator, Terraform provider
- KMS envelope encryption of stored secrets, config and plugin hot reload, k6 load tests,
  fuzzing, chaos tests
- Admin UI dashboards, i18n (English, Turkish), docs site; multi-region design
  ([multi-region.md](multi-region.md))
- Multi-region building blocks: region claim in tokens and domain resolution, lease affinity
  (`events.region`), read replicas for lists, shared rate limits, region moves with
  reprovisioning, regional quota shares (usage grants and the Go `Allowance`)
- CloudEvents `dataschema` on every event, bulk re-encryption (`tenarium -reencrypt`), live reload
  of rate limits, regions, usage policies and 22 plugins, admin UI browser tests (Playwright)
- Browser tests for passkeys, tenant OIDC SSO and social sign-in; keyboard access to table rows;
  Docusaurus website (tenarium.aimtune.dev) with an English and Turkish UI and an API reference

## Ideas

Open items; open an issue first for larger ones.

| Item | Notes |
|---|---|
| Control-plane data residency | Partition users, members and events by region (per-region stores and a global directory). Until then, run one deployment per jurisdiction; see [multi-region.md](multi-region.md) |
