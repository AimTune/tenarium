# Authentication and authorization

There are three different questions here. Keep them apart:

1. **Who is calling the Tenarium API?** (operators, backend services, tenant admins). This is
   authentication, done by authenticators.
2. **What may that caller do?** This is authorization: the built-in tenant-scope rule plus
   authorizer plugins.
3. **How do a tenant's own end users sign in to your product?** That is your application's
   identity provider. Tenarium manages it as a per-tenant resource, for example by provisioning
   a Keycloak realm per tenant (see below).

## Authentication

Every `/v1` request goes through a chain of authenticators, in this order:

1. the built-in API key authenticator (`server.api_keys`, `Authorization: Bearer <key>`);
2. Tenarium user tokens (`core/token`), issued by `POST /v1/auth/token`; see
   [users](users.md) for sign-in, sessions and the built-in role tables;
3. API keys created through the API (`core/key`, secrets starting with `tnr_`), scoped to a
   tenant or platform-wide; see [tenant API keys](tenants.md#tenant-api-keys);
4. plugin authenticators, in plugin order.

Each authenticator either accepts the request (returning a principal), says it has **no
credentials it understands** (the next one is tried), or rejects it (401). So API keys and
OIDC tokens, which are both bearer tokens, coexist: the API key authenticator ignores tokens
that are not one of its keys, and the OIDC plugin ignores tokens that are not JWTs from its
issuer.

The resulting **principal** has a `subject`, `kind` (user/service), the `authenticator` that
accepted it, optional `tenant_id`, `roles` and `claims`. It is available to handlers, hooks
(`sdk.PrincipalFrom(ctx)`), plugin routes and authorizers, and is recorded as the `actor` of
every event. `GET /v1/me` returns it.

Requests without credentials are rejected, unless `server.allow_anonymous: true` is set
(development only); invalid credentials are always rejected.

### OIDC (Keycloak, Auth0, Entra ID, Okta, Dex, …)

```yaml
- plugin: oidc
  name: keycloak
  config:
    issuer: https://sso.example.com/realms/platform
    audience: tenarium                  # expected aud (alias: client_id)
    roles_claim: realm_access.roles     # dotted path; Keycloak default
    groups_claim: groups                # optional, merged into roles
    role_mapping: {platform-admin: admin, support: viewer}   # optional; unmapped roles dropped
    tenant_claim: tenant                # optional; ID or slug → tenant-scoped principal
    allow_missing_tenant: false         # see below
    clock_skew: 30s
```

With `tenant_claim` set, a token whose claim is missing, empty or holds more than one value is
**rejected**, so a token can never silently become platform-wide. Set
`allow_missing_tenant: true` if platform staff sign in through the same issuer without the
claim.

Discovery happens lazily, so Tenarium starts even if the IdP is down. Configure one instance per
issuer. Set `jwks_url` to skip discovery.

### LDAP / Active Directory

```yaml
- plugin: ldap
  config:
    url: ldaps://ldap.example.com:636
    bind_dn: cn=tenarium,ou=services,dc=example,dc=com
    bind_password: ${LDAP_PASSWORD}
    user_base_dn: ou=people,dc=example,dc=com
    user_filter: (uid=%s)               # AD: (sAMAccountName=%s)
    group_attribute: memberOf           # or group_base_dn + group_filter
    role_mapping: {tenarium-admins: admin, helpdesk: viewer}
    tenant_attribute: tenantSlug        # optional
    cache_ttl: 60s
```

Callers send HTTP Basic credentials. Successful logins are cached briefly (keyed by a hash of
the username and password) to avoid an LDAP round trip on every request.

### Custom authenticators

Implement `sdk.Authenticator` in a Go plugin, or an `authenticate` handler in an external
plugin (any language): mTLS, signed service tokens, session cookies, and so on.

## Authorization

For every request Tenarium computes an **action** (such as `tenants:update` or `members:write`)
and a **resource** (type, ID and the tenant it belongs to), then decides:

1. **Tenant scope (built in, cannot be relaxed).** A principal with a `tenant_id` can only act
   on that tenant and its descendants. The only tenant-less actions it may perform are reading
   plans and calling plugin routes. It can never perform platform-only actions (table below).
   Listing tenants without a `parent_id` returns only its own tenant.
2. **Built-in role tables.** Callers signed in with Tenarium tokens (`core/token`) or database
   API keys (`core/key`) must also be allowed by their roles: the [built-in
   tables](users.md#built-in-roles) and the tenant's [custom roles](#tenant-roles-and-groups).
3. **Authorizer plugins.** With none configured, every caller that passed the steps above is
   allowed. Otherwise any `deny` wins, and at least one `allow` is required.

Actions (`GET /v1/actions` lists them):

| Resource | Actions |
|---|---|
| tenants | `tenants:create`, `read`, `update`, `delete`, `suspend`, `resume`, `provision`, `purge`, `move` |
| members, usage, plans | `members:read\|write`, `usage:read\|write`, `plans:read\|write` |
| events | `events:read`, `deadletters:read`, `deadletters:replay` |
| plugins | `plugins:read`, `plugins:route` |
| users | `users:read`, `users:write`, `users:impersonate` |
| tenant configuration | `apikeys:read\|write`, `domains:read\|write`, `webhooks:read\|write`, `sso:read\|write`, `roles:read\|write`, `groups:read\|write` |
| data protection | `data:export`, `data:erase` |
| platform | `signingkeys:read\|write`, `oauthclients:read\|write`, `config:reload` |

**Platform-only** actions, which no tenant-scoped principal can hold whatever its roles:
`plans:write` (which includes changing a tenant's plan, add-ons, features or limits, pinning a
plan revision and managing rollouts), `usage:write` (a negative delta would release quota),
`tenants:purge` (skipping the deletion grace period), `tenants:move` (changing a tenant's region),
`signingkeys:*`, `oauthclients:*`, `config:reload`, `users:impersonate` and `data:erase`.

**Impersonated sessions** (see [impersonation](users.md#impersonation)) are refused
`apikeys:write`, `data:export`, `data:erase`, `sso:write`, `users:impersonate`, `users:write`,
`signingkeys:write`, `webhooks:write` and `roles:write`, and cannot use the `/v1/me` endpoints
that manage the user's own credentials.

Creating a tenant with a `plan`, `features` or `limits` also requires `plans:write`. A child
tenant created without a plan inherits its parent's plan.

**Plugin routes** require `plugins:route` (resource: the plugin instance). Tenant-scoped callers
may reach plugin routes, so a route that returns tenant data must check access itself with
`r.Host().Authorize(ctx, sdk.ActionTenantsRead, resource)`, which applies exactly the rules
above.

### RBAC

```yaml
- plugin: rbac
  config:
    roles:
      admin:    ["*"]
      operator: ["tenants:*", "members:*", "usage:*", "plans:read", "events:read", "deadletters:*"]
      viewer:   ["*:read"]
      tenant-admin: ["tenants:read", "tenants:update", "tenants:create", "members:*", "usage:read"]
    bindings:                       # roles for specific principals
      "core/api-key:api-key-0": [admin]
    tenant_roles: [tenant-admin]    # given to every tenant-scoped principal
    default_roles: []
    deny_unknown: false             # true: deny instead of abstain when nothing matches
```

Roles come from the principal (as mapped by the OIDC or LDAP plugin) and from `bindings`.
Patterns use glob syntax.

For tenant-aware policies there are also the `cedar`, `opa`, `openfga` and `spicedb` authorizer
plugins (see the [plugin list](plugins/README.md#plugin-catalog)).

### Tenant roles and groups

Besides the built-in member roles (`tenants.member_roles`), each tenant can define its own roles
and group its members. Tenant owners and admins manage both (`roles:read|write`,
`groups:read|write`).

```sh
# a role is a set of action patterns (path.Match globs over GET /v1/actions)
curl -sX PUT $API/v1/tenants/acme/roles/billing-admin -H "$AUTH" \
  -d '{"description":"Reads usage, manages webhooks","actions":["usage:read","webhooks:*","tenants:read"]}'
curl -s $API/v1/tenants/acme/roles -H "$AUTH"          # built-in (built_in: true) and custom roles

# members can hold a custom role directly ...
curl -sX PATCH $API/v1/tenants/acme/members/<member> -H "$AUTH" -d '{"role":"billing-admin"}'
# ... or get extra roles through groups
curl -sX POST $API/v1/tenants/acme/groups -H "$AUTH" -d '{"name":"Finance","roles":["billing-admin"]}'
curl -sX PUT $API/v1/tenants/acme/groups/Finance/members/<member> -H "$AUTH"
```

- Role names are lowercase identifiers and cannot shadow a built-in role. A role has 1 to 100
  patterns, and each pattern must match at least one built-in action.
- A member's **effective roles** are its own role plus the roles of every group it belongs to.
  Like built-in roles, they are re-read on every request, so changing a member's groups or
  editing a role takes effect at once (the `roles` claim inside the access token is only a
  snapshot for other services).
- Groups are addressed by ID or (case-insensitive) name. Removing a member from the tenant
  removes it from its groups. A role still used by a member, a group or an active API key cannot
  be deleted (409).
- Custom roles are checked like built-in ones: through the built-in role tables for `core/token`
  and `core/key` callers, with the tenant-scope and platform-only rules above. A custom role
  can never grant a platform-only action to a tenant user.
- Tenant API keys may carry custom roles too.

**Escalation prevention.** Nobody can hand out more than they hold. Defining a role
(`PUT .../roles/{role}`), giving a member a role (`POST`/`PATCH .../members`), giving a group
roles, adding a member to a group, and creating an API key, a tenant from a
[template](tenants.md#tenant-templates) or a [clone](tenants.md#cloning-tenants) with custom
roles each check that the caller is allowed **every action** the roles cover on that tenant;
otherwise the answer is 403 `cannot grant <action>`.

Changes emit `role.updated`, `role.deleted`, `group.created`, `group.updated` and
`group.deleted`. [SCIM](tenants.md#scim-provisioning) groups whose name is not a role map onto
these groups.

### Policies in hooks

Authorizers decide on actions. For rules that depend on the data, such as "only admins may move
a tenant to the enterprise plan", use a hook and read the caller with `sdk.PrincipalFrom(ctx)`.

## Tenant administrators: a worked example

Goal: customers' admins manage their own organization and its workspaces through Tenarium,
signing in with your Keycloak.

1. Put a `tenant` claim (the organization slug) in the tokens of customer admins.
2. Configure `oidc` with `tenant_claim: tenant`, and `rbac` with
   `tenant_roles: [tenant-admin]`.
3. Customer admins can now create workspaces (`POST /v1/tenants` with `parent_id`), manage
   members and read usage within their subtree. They cannot see other customers, change plans,
   or record usage.

## End-user identity per tenant

To give each tenant its own login (an isolated realm, or the customer's own SAML/OIDC IdP):

- The `keycloak` plugin provisions a realm per tenant (`tenant-{slug}`), optionally with an
  OIDC client. It mirrors members as realm users, disables the realm while the tenant is
  suspended, and deletes it when the tenant is deleted. `GET /v1/plugins/keycloak/realms/{tenant}`
  returns the realm's issuer URL for your application.
- Keep per-tenant IdP settings (such as a customer's federation metadata) in tenant `settings`,
  validated with `tenants.settings_schema`, and react to `tenant.updated` events in a plugin
  that configures the IdP.

To make Tenarium itself the sign-in service of your applications (authorization code + PKCE,
consent, userinfo), see [the OpenID provider](oidc-provider.md). To let users sign in to
Tenarium with Google, GitHub or Microsoft accounts, see [social login](#social-login).

## Single sign-on per tenant

Tenants can sign their users in with their own identity provider, over OpenID Connect (Entra
ID, Okta, Google Workspace, Keycloak, ...) or [SAML 2.0](#saml), configured through the API,
without a plugin:

```sh
# 1. prove control of the email domain (TXT record), see tenants.md#custom-domains
curl -sX POST $API/v1/tenants/acme/domains -H "$AUTH" -d '{"hostname":"acme.com"}'
curl -sX POST $API/v1/tenants/acme/domains/acme.com/verify -H "$AUTH"
# 2. register <users.public_url>/v1/auth/sso/callback at the provider, then
curl -sX PUT $API/v1/tenants/acme/sso -H "$AUTH" -d '{
  "issuer": "https://login.microsoftonline.com/<tenant>/v2.0",
  "client_id": "...", "client_secret": "...",
  "domains": ["acme.com"], "auto_provision": true, "default_role": "member", "enforce": false}'
```

Users start at `GET /v1/auth/sso/start?tenant=acme` (or `?email=ann@acme.com` to pick the
connection by domain; `GET /v1/auth/sso/discover?email=` tells a login form whether to show the
SSO button). After the provider, the browser comes back to `return_to` (default
`<public_url>/ui/`; other origins must be listed in `auth.sso.allowed_redirects`) with the
session in the URL fragment: `#access_token=...&refresh_token=...&expires_in=...&tenant_id=...`,
or `#error=sso_rejected|idp_error|sso_failed`.

Rules that keep this safe:

- A connection can only claim **email domains that are verified domains of its tenant**, and a
  domain belongs to one connection. The provider's assertions are accepted only for those
  domains, and an explicit `email_verified: false` is refused.
- SSO sessions are always **scoped to the tenant** with the membership role. Platform roles are
  never granted through a tenant's provider.
- Unknown users and missing memberships are created only with `auto_provision` (role
  `default_role`); otherwise an admin must invite them first. Invited users and memberships are
  activated by their first SSO sign-in. Disabled users and other membership states are refused.
- The flow uses authorization code + PKCE + nonce; the state lives in a short-lived, signed,
  HttpOnly cookie bound to the browser. Issuer discovery and token requests go through the same
  SSRF guard as [tenant webhooks](webhooks.md#security) (`auth.sso.allow_private_issuers` lifts
  it for development).
- With `enforce: true`, password sign-in is refused (403 `sso_required`) for every address of
  the domains, whether or not the account exists. Platform users signing in without a tenant
  are exempt, so operators keep a break-glass path.
- Tenarium's own two-factor authentication does not apply to SSO sign-ins; that is the
  provider's job.

Configuring SSO needs `sso:read` / `sso:write` (tenant owners and admins have both). Changes emit
`sso.updated` and `sso.deleted` (without the client secret or SAML metadata). SSO needs
Tenarium tokens (`auth.tokens.enabled`) and can be turned off with `auth.sso.enabled: false`.
A tenant has one connection; `PUT` replaces it, and `"enabled": false` keeps it configured but
unused. `default_role` may be a [custom role](#tenant-roles-and-groups).

### SAML

With `"protocol": "saml"` the tenant becomes a SAML 2.0 service provider. Give Tenarium the
identity provider's metadata, inline or as a URL that is fetched once when the connection is
saved (through the same SSRF guard):

```sh
curl -sX PUT $API/v1/tenants/acme/sso -H "$AUTH" -d '{
  "protocol": "saml",
  "saml_metadata_url": "https://idp.acme.com/app/abc/sso/saml/metadata",
  "domains": ["acme.com"], "auto_provision": true}'
```

Then configure the identity provider with the tenant's service provider values (`<tenant-id>`
is the tenant's ID, not its slug):

| | |
|---|---|
| Entity ID and metadata | `<users.public_url>/v1/auth/sso/saml/<tenant-id>/metadata` |
| ACS URL (HTTP-POST) | `<users.public_url>/v1/auth/sso/saml/<tenant-id>/acs` |
| Name ID | any format; an email-shaped name ID is used when no email attribute is sent |

- Sign-in starts at the same `GET /v1/auth/sso/start` and ends with the same URL fragment as
  OIDC. Only SP-initiated sign-in is accepted (IdP-initiated responses are refused), and the
  response must answer the request Tenarium sent.
- Assertions must be signed by the identity provider. Tenarium does not sign requests and does
  not accept encrypted assertions, so it needs no SAML key pair.
- The email comes from `saml_email_attribute` if set, otherwise from the common attribute names
  (`email`, `mail`, `emailAddress`, the WS-Federation and `urn:oid:0.9.2342.19200300.100.1.3`
  names); the display name from `saml_name_attribute`, `displayName`, `name`, `cn`,
  `commonName` or `urn:oid:2.5.4.3` (and the WS-Federation and `urn:oid:2.16.840.1.113730.3.1.241`
  names). The same
  verified-domain, provisioning and enforcement rules as for OIDC apply.
- Over https the state cookie is `SameSite=None; Secure`, because the identity provider posts
  back cross-site.
- After the identity provider rotates its signing certificate, save the connection again
  (with `saml_metadata_url` or the new `saml_metadata`) so Tenarium picks up the new metadata.

## Social login

Users can also sign in to Tenarium with Google, GitHub, Microsoft or any OpenID Connect provider
configured by the platform (unlike [tenant SSO](#single-sign-on-per-tenant), which each tenant
configures for its own domains). The result is a normal Tenarium session.

```yaml
auth:
  social:                              # needs auth.tokens.enabled
    public_url: ""                     # default users.public_url
    allowed_redirects: [https://app.example.com]   # origins return_to may use besides public_url
    allow_private_issuers: false       # development only: http and internal addresses
    providers:                         # shown in this order
      - name: google                   # used in URLs: [a-z0-9][a-z0-9_-]{0,31}
        type: google                   # google | github | microsoft | oidc
        client_id: ...
        client_secret: ${GOOGLE_CLIENT_SECRET}
        auto_create: true              # create unknown users (otherwise they must exist)
        allowed_domains: [acme.io]     # optional: only these email domains
      - name: github
        type: github
        client_id: ...
        client_secret: ${GITHUB_CLIENT_SECRET}
        # auth_url, token_url, api_url: GitHub Enterprise Server
      - name: microsoft
        type: microsoft
        tenant: contoso.onmicrosoft.com  # tenant ID or domain; or organizations | common | consumers
        client_id: ...
        client_secret: ${ENTRA_CLIENT_SECRET}
      - name: okta
        type: oidc
        label: Okta                    # button text (default from the type, or the name)
        issuer: https://acme.okta.com
        client_id: ...
        client_secret: ...
        scopes: [openid, email, profile]   # default; GitHub: read:user, user:email
```

Register this redirect URI at each provider:
`<public_url>/v1/auth/social/<name>/callback`.

| Endpoint | Purpose |
|---|---|
| `GET /v1/auth/social` | `{"providers": [{"name", "label", "type"}]}` for the sign-in page |
| `GET /v1/auth/social/{name}/start?tenant=&return_to=&login_hint=` | redirects to the provider |
| `GET /v1/auth/social/{name}/callback` | the provider's redirect target |

After sign-in the browser returns to `return_to` (default `<public_url>/ui/`; other origins
must be in `allowed_redirects`) with the session in the URL fragment, exactly like SSO:
`#access_token=...&refresh_token=...&token_type=Bearer&expires_in=...&tenant_id=...`, or
`#error=<code>`. Like the rest of `/v1/auth/`, these endpoints are rate limited.

**Which identities are accepted.**

- The flow is authorization code with PKCE; OIDC types also use a nonce, and the state lives in
  a signed, HttpOnly cookie bound to the browser.
- The email must be **verified by the provider**, otherwise `error=email_unverified`. Google and
  generic OIDC providers must send `email_verified: true`. GitHub uses the account's primary
  email and its `verified` flag (via `/user/emails`). **Microsoft Entra ID does not send
  `email_verified`**: Tenarium accepts its `email` claim only when the optional claim
  `xms_edov` (email domain owner verified) is true. Add `xms_edov` (and `email`) as optional
  claims of the ID token in the app registration's *Token configuration*, or sign-ins fail with
  `email_unverified`. For Microsoft, the ID token's issuer is checked against the directory
  (`{tenantid}` is resolved for multi-tenant endpoints).
- With multi-tenant Microsoft endpoints (`organizations`, `common`, `consumers`) any Microsoft
  account can authenticate, so set `allowed_domains`. Outside them the answer is
  `error=domain_not_allowed`.
- Users are matched by email. Unknown users are created (active, email verified, no password)
  only with `auto_create`; otherwise `error=access_denied`. Invited users are activated. Disabled
  users get `access_denied`, locked accounts `account_locked`.

**Policy.**

- **Tenant SSO wins.** If the email's domain belongs to a tenant that [enforces
  SSO](#single-sign-on-per-tenant), social sign-in is refused with `error=sso_required`, whether
  or not a tenant was asked for.
- **Two-factor authentication.** Users with TOTP enabled cannot finish a social sign-in
  (`error=mfa_required`): the flow does not ask for a code. They sign in with password and code,
  or with a passkey.
- `?tenant=` scopes the session to a tenant the user is an active member of. Without it, only
  users with platform roles get a session (`error=tenant_required` otherwise).
- Other error codes: `idp_error` (the provider failed or the token was invalid),
  `server_error`.

## Signing keys

Tenarium signs user tokens with ES256 keys stored in the database (so every replica uses the
same keys) and publishes the public parts at `/.well-known/jwks.json`. The newest key signs;
older keys keep verifying until every token they signed has expired, then they are deleted.

| | |
|---|---|
| `GET /v1/signing-keys` | list keys (`kid`, `created_at`, `active`) |
| `POST /v1/signing-keys/rotate` | add a new active key now |
| `DELETE /v1/signing-keys/{kid}` | retire a key immediately (after a leak); tokens it signed stop working. The active key cannot be retired: rotate first |

`auth.tokens.rotation_period` (e.g. `720h`) rotates automatically. Replicas reload keys every
minute and whenever they see an unknown `kid`. Services verifying tokens should refresh their
JWKS cache on an unknown `kid` (the [tenant middleware](middleware.md) does). These endpoints
are platform-only (`signingkeys:read` / `signingkeys:write`); rotations are audited as
`signing_key.rotated` / `signing_key.retired`.
