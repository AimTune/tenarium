# Tenarium threat model

Tenarium is a multi-tenant SaaS control plane: it stores tenants, plans and usage, users and
their memberships, issues tokens, runs single sign-on, and drives plugins (provisioners,
publishers, authorizers, billing sync) through a transactional event outbox. A compromise
usually means crossing a tenant boundary, gaining platform rights, or reaching internal
networks from the server.

## Actors and trust

| Actor | Trust |
|---|---|
| Unauthenticated internet clients | Untrusted. Reach `/v1/auth/*`, `/oauth/*`, SAML ACS and metadata, `/v1/domains/check`, `/healthz`, `/readyz`, `/.well-known/*`, public plugin routes, the admin UI's static files. |
| Tenant-scoped callers (tenant API keys, tenant user tokens, SCIM tokens) | Untrusted with respect to other tenants and to platform-only actions. They must never act outside their tenant subtree or perform `plans:write`, `usage:write`, `tenants:purge`, `tenants:move`, `signingkeys:*`, `oauthclients:*`, `config:reload`, `users:impersonate`, `data:erase`. |
| Tenant members with custom roles or groups | Must not hold actions they were not granted; role, group, member and API key creation must not escalate beyond the caller's own actions. |
| Impersonating support staff | Trusted for the impersonated session only, within the denied-action list (`internal/authz`). |
| Platform callers (platform API keys, platform users) | Trusted operators. Abuse by them is out of scope except where it breaks other guarantees (e.g. secrets leaking in plaintext). |
| External identity providers (OIDC/SAML/social), DNS answers | Untrusted input: tokens, assertions, discovery documents, metadata, TXT records. |
| External plugins (HTTP/JSON protocol) and WASM plugins | Untrusted: their replies are parsed defensively (`plugins/external`, `pkg/extplugin`, `plugins/wasm`). |
| Built-in Go plugins and the server configuration file | Trusted code/configuration. |
| Webhook, replay and SIEM targets configured by tenants | Untrusted destinations; outbound requests must not reach internal addresses (`internal/netguard`). |

## Adversarial inputs (in scope)

- HTTP request bodies, paths, query strings and headers of every `/v1` route (see
  `internal/api/openapi.yaml`), including idempotency keys, `If-Match`, JSON merge patches of
  tenant settings and SCIM PatchOps.
- Tokens: Tenarium access and refresh tokens, magic-link tokens, action tokens (invitation,
  password reset, email change), OAuth authorization codes, PKCE verifiers, signed SSO/WebAuthn
  state.
- SSO: OIDC discovery/JWKS/ID tokens, SAML responses and metadata, social provider responses
  (including GitHub's user/email APIs).
- WebAuthn registration and assertion responses.
- Event payloads delivered to plugins and back from external plugins; WASM module behaviour.
- Custom domain hostnames and DNS TXT verification.
- Configuration reload (`POST /v1/admin/reload`) only by platform callers.

## Properties to check

1. **Tenant isolation**: no read or write of another tenant's data, members, usage, events,
   audit log, webhooks, SSO configuration or API keys from a tenant-scoped principal, including
   via list filters, pagination cursors, child tenants, clone/template flows and plugin routes.
2. **Authorization**: platform-only actions stay platform-only; maintenance windows make tenants
   read-only for their own callers; custom roles cannot exceed the granter's actions.
3. **Authentication**: token signature/audience/expiry checks, refresh-token rotation and reuse
   detection, refresh tokens bound to their OAuth client, single-use codes and links, lockout,
   MFA requirements for password, magic-link and social sign-in, SSO domain enforcement.
4. **SSRF**: webhook deliveries, SSO discovery, SAML metadata fetches, archive replay targets and
   external plugin calls must not reach loopback, private, link-local or metadata addresses
   unless explicitly allowed by configuration, including via redirects and DNS rebinding.
5. **Secrets at rest**: signing keys, MFA secrets, webhook/SSO secrets and the key-value table
   are encrypted when a `secrets` provider is configured; no plaintext secrets in logs, events,
   exports or API responses (API key hashes, client secrets after creation).
6. **Quota and billing integrity**: usage limits cannot be bypassed by concurrency, negative
   deltas from tenant callers, usage grants, or plan revision/add-on manipulation.
7. **Event integrity**: events are committed with the state change (outbox); a tenant cannot
   inject or suppress events of another tenant.
8. **Parsing robustness**: no panics or unbounded resource use from untrusted input (body size
   limits, JSON depth, SAML XML, WASM limits).

## Out of scope

- Denial of service by platform administrators or by misconfiguration of the server.
- Volumetric DoS without an amplification or algorithmic flaw.
- Issues only reachable with `allow_private_issuers`, `allow_http` or other options documented
  as development-only.
- Code under `tests/`, `examples/`, `tools/`, `website/` and `*_test.go`.
- The Kubernetes operator, Terraform provider and SDKs, unless the issue lets a remote party
  compromise a Tenarium server or another tenant.
- Missing hardening headers on the admin UI without a demonstrated exploit.

## Severity guidance

- **Critical**: unauthenticated takeover (token forgery, authentication bypass), cross-tenant
  write, remote code execution, SSRF to cloud metadata with credential theft.
- **High**: cross-tenant read, privilege escalation to platform rights, SSO or MFA bypass,
  plaintext disclosure of stored secrets.
- **Medium**: escalation within a tenant (beyond granted actions), quota bypass, SSRF limited to
  internal reachability, stored XSS in the admin UI.
- **Low**: information disclosure without sensitive data, issues needing unlikely configuration.

## Reports

Please include the affected route or package, a minimal reproduction (an HTTP sequence or a Go
test against `internal/store/memory`), and the property above it breaks. Findings that share the
same root cause should be reported once. Patches are welcome as a diff against `main`.

## Building and testing offline

`.oss-scanner/Dockerfile` downloads every Go module and builds all binaries. In the container:
`go test ./...` runs the unit and end-to-end tests with the in-memory store (integration tests
that need PostgreSQL, Redis or S3 are skipped without their `TENARIUM_TEST_*` variables).
