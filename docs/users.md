# Users

Tenarium manages the people who sign in: platform staff and the members of your tenants. A
user is platform-wide; access to tenants comes from **memberships** (a user can be a member of
many tenants, with one role in each).

```
user ada@acme.io ──┬── member of "acme"        (role: owner)
                   └── member of "acme-labs"   (role: viewer)
```

## Where identities live: user directories

| Directory | Passwords stored in | Sign-in | Configure |
|---|---|---|---|
| `internal` (default) | Tenarium (argon2id) | `POST /v1/auth/token` → Tenarium JWT | nothing |
| `keycloak` plugin | Keycloak | Keycloak login (OIDC), optionally also `POST /v1/auth/token` | `users.directory: <instance>` |
| `auth0-directory`, `entra-directory`, `okta-directory`, `ldap-directory` plugins | Auth0, Entra ID, Okta, LDAP / Active Directory | see the [plugin list](plugins/README.md#plugin-catalog) | same |
| any plugin implementing `sdk.UserDirectory` | that system | depends | same |

Tenarium always keeps a row per user (for memberships and auditing). With an external
directory, every change (create, rename, disable, delete, set password) is applied there first;
if that fails, nothing changes locally. A user's `external_id` is their ID in the directory,
which is also the `sub` of the directory's tokens. When such a token arrives through the `oidc`
plugin, Tenarium links it to the user, so disabling the user in Tenarium locks them out even
while their Keycloak token is still valid.

```yaml
users:
  directory: keycloak            # plugin instance name; default "internal"

plugins:
  - plugin: keycloak
    config:
      url: http://keycloak:8080
      username: admin
      password: ${KEYCLOAK_ADMIN_PASSWORD}
      provision_realms: false    # only the directory, no realm per tenant
      users:
        realm: platform
        create_realm: true
        client_id: tenarium      # optional: lets Tenarium verify passwords (direct grant)
        client_secret: ${KEYCLOAK_TENARIUM_SECRET}
        send_invitation: true    # Keycloak emails the setup link (needs SMTP in the realm)
  - plugin: oidc                 # accept Keycloak tokens on the API
    config:
      issuer: http://keycloak:8080/realms/platform
      audience: tenarium
```

## Lifecycle

```
invited ──set password / accept invitation──▶ active ◀──enable── disabled
                                                 └────disable────────▲
```

- **Creating a user** (`POST /v1/users`) without a password invites them: they get an email
  with a link (`/ui/#/accept/<token>`, valid for `users.invitation_ttl`, default 7 days). With
  a password the user is active right away.
- **Adding a member by email** (`POST /v1/tenants/{id}/members`) creates and invites the user if
  the email is unknown, or links the existing user. The membership is `invited` until the user
  is active, then becomes `active` automatically, in every tenant they were invited to.
- **Disabling** a user blocks sign-in, revokes their sessions and invalidates their access
  tokens immediately (every request re-checks the user).
- **Deleting** a user removes their memberships, credentials and sessions (and the identity in
  an external directory).

## Signing in with Tenarium tokens

```sh
# platform staff (users with platform roles)
curl -X POST $API/v1/auth/token -d '{"grant_type":"password","email":"root@example.com","password":"..."}'
# a tenant member: the token is scoped to the tenant and carries the membership role
curl -X POST $API/v1/auth/token -d '{"grant_type":"password","email":"ada@acme.io","password":"...","tenant":"acme"}'
# refresh (the refresh token rotates on every use)
curl -X POST $API/v1/auth/token -d '{"grant_type":"refresh_token","refresh_token":"..."}'
```

The response is `{access_token, token_type: "Bearer", expires_in, refresh_token, tenant_id}`.

- **Access tokens** are ES256 JWTs (`iss`, `sub` = user ID, `aud`, `tid` = tenant, `roles`,
  `email`), valid for `auth.tokens.access_ttl` (default 15 minutes). Your own services can verify
  them with any OIDC library: discovery is at `/.well-known/openid-configuration` and the keys
  at `/.well-known/jwks.json`. Signing keys are generated on first start and stored in the
  database, so all replicas share them.
- **Refresh tokens** are opaque, stored only as hashes, valid for `auth.tokens.refresh_ttl`
  (default 30 days), and rotate on every use. Presenting an already-used refresh token means it
  was copied, so the whole session is revoked.
- **Roles are always current.** Tenarium re-reads the user and membership on every request, so
  demoting or removing a member takes effect immediately, not at token expiry.

### Built-in roles

Users signed in with Tenarium tokens are always checked against built-in role tables, even
when no authorizer plugin is configured, so a tenant `viewer` can never delete their tenant.

| Role | Context | Allows |
|---|---|---|
| `admin` | platform | everything |
| `viewer` | platform | every `*:read` action |
| `owner`, `admin` | tenant | read, update the tenant, create child tenants, manage members, read usage and the tenant's events and audit trail, manage the tenant's API keys, domains, webhooks, SSO, [custom roles and groups](auth.md#tenant-roles-and-groups), [export the tenant's data](privacy.md#exports) |
| `member`, `viewer` | tenant | read the tenant, members, usage and plans |

No tenant role can delete, suspend or restore the tenant, change plans or limits, record usage,
move the tenant to another region, erase data, impersonate users or manage signing keys and OAuth
clients; those are platform decisions. Tenants can add their own roles on top of these
([tenant roles](auth.md#tenant-roles-and-groups)). Override the tables with
`auth.roles.platform` / `auth.roles.tenant` (role → action patterns). Authorizer plugins such as
`rbac` still apply on top, and any `deny` wins.

## Passwords and protection

- Passwords are hashed with **argon2id** (64 MiB, 3 iterations).
- Policy: at least `users.password_min_length` characters (default 12), not a very common
  password, not the email address. Use a `user.before_create` hook or a plugin for stricter
  rules.
- **Breached passwords**: with `users.breached_password_check: true`, every new password (set
  on creation, by reset, invitation or change) is looked up in the
  [Have I Been Pwned](https://haveibeenpwned.com/Passwords) "Pwned Passwords" range API and
  refused with 400 `validation_failed` if it appears in a known breach. Only the first five hex
  digits of the password's SHA-1 leave the server (k-anonymity), and responses are padded. The
  check **fails open**: if the service is unreachable or answers an error within 5 seconds, the
  password is accepted and a warning is logged, so an outage never blocks sign-ups. Tenarium
  needs outbound HTTPS to `api.pwnedpasswords.com`.
- **Lockout**: after `users.lockout.max_failures` (default 10) wrong passwords, the account is
  locked for `users.lockout.duration` (default 15 minutes) and a `user.locked` event is
  emitted.
- **Rate limit**: `/v1/auth/*` accepts at most `auth.rate_limit` requests per client IP per
  minute (default 30). Behind a proxy all clients share the proxy's IP, so raise the limit or
  rate-limit at the proxy.
- Unknown emails and wrong passwords get the same answer, and take the same time.
- Password reset (`POST /v1/auth/password-reset`) always answers 202, whether or not the email
  exists. Reset links expire after `users.reset_ttl` (default 1 hour), and every token is single
  use. Changing a password signs the user out everywhere.

## Two-factor authentication

Users signing in with a password can add a TOTP authenticator app:

```sh
curl -sX POST $API/v1/me/mfa/totp -H "Authorization: Bearer $TOKEN"
# → {"secret": "...", "otpauth_url": "otpauth://totp/..."}   show the URL as a QR code
curl -sX POST $API/v1/me/mfa/totp/confirm -H "Authorization: Bearer $TOKEN" -d '{"code":"123456"}'
# → {"recovery_codes": ["abcde-fghij", ...]}   10 single-use codes, shown once
```

From then on `POST /v1/auth/token` with the password grant also needs `"otp"`: a current code
from the app or a recovery code. Without it the answer is 401 `mfa_required`; with a wrong or
already used one, 401 `invalid_otp`. Codes cannot be replayed, and wrong codes count toward the
lockout. Refreshing a session does not ask again.

| Endpoint | Purpose |
|---|---|
| `GET /v1/me/mfa` | `enabled`, `pending`, `recovery_codes_left` |
| `POST /v1/me/mfa/recovery-codes` `{"code"}` | replace the recovery codes |
| `POST /v1/me/mfa/disable` `{"code"}` | turn it off |
| `DELETE /v1/users/{id}/mfa` | admins (`users:write`) reset it for a user who lost their device |

Events: `user.mfa_enabled`, `user.mfa_disabled`. TOTP secrets are stored in the database,
encrypted when a [`secrets` provider](secrets.md) is configured and in plain text otherwise.
Users signing in through a tenant's [SSO](auth.md#single-sign-on-per-tenant) use their
provider's MFA instead.

## Sign-in links

Passwordless sign-in by email ("magic links") is off by default. Turn it on by giving links a
lifetime:

```yaml
users:
  magic_link_ttl: 15m      # > 0 enables POST /v1/auth/magic-link; needs auth.tokens.enabled
```

```sh
curl -sX POST $API/v1/auth/magic-link -d '{"email":"ada@acme.io","tenant":"acme"}'   # tenant optional
# → 202 {"status": "sent if the account exists"}
```

The user gets a link to `<users.public_url>/ui/#/magic/<token>`. The page (or your own) exchanges
the token for a session:

```sh
curl -sX POST $API/v1/auth/token -d '{"grant_type":"magic_link","token":"..."}'
# with two-factor authentication: 401 mfa_required, then again with "otp"
curl -sX POST $API/v1/auth/token -d '{"grant_type":"magic_link","token":"...","otp":"123456"}'
```

- The request always answers 202, whether or not the address is known, active, or belongs to a
  domain whose tenant [enforces SSO](auth.md#single-sign-on-per-tenant); in those cases no email
  is sent. With links disabled the endpoint answers 404.
- Links are single use and expire after `magic_link_ttl`. A link names the user and, if given,
  the tenant the session is scoped to.
- **Two-factor authentication still applies.** For a user with TOTP the link alone is not
  enough: the exchange answers 401 `mfa_required` **without using up the link**, so the page can
  ask for the code and retry with `otp`. Wrong codes count toward the lockout, and a locked
  account cannot use links either.
- Following a link proves control of the address, so the user's email is marked verified.
- Invalid, expired or used links answer 400 `invalid_token`.

## Changing the email address

Users of the `internal` directory change their own address with their current password; the
change only takes effect once the new address is confirmed:

```sh
curl -sX POST $API/v1/me/email -H "Authorization: Bearer $TOKEN" \
  -d '{"email":"ada@new.example","password":"..."}'
# → 202 {"status": "confirmation sent to the new address"}
curl -sX POST $API/v1/auth/email-change/confirm -d '{"token":"..."}'   # from the link, no auth
# → the updated user
```

- The confirmation link (`<users.public_url>/ui/#/confirm-email/<token>`) goes to the **new**
  address and is valid for `users.email_change_ttl` (default 24h), once.
- A wrong password answers 401 `invalid_credentials`, so a stolen session alone cannot take over
  the account. The new address must be valid, different and not used by another user.
- On confirmation the address changes (and is marked verified), `user.updated` is emitted, and
  the **old** address gets an `email_changed` notice naming the new one, so the owner learns
  about a change they did not make. A failure to send the notice is only logged.
- With an external user directory, addresses are managed there and the request answers 409.
  Impersonated sessions cannot change the address. Users without a password (for example
  created through [social login](auth.md#social-login)) cannot use this endpoint.

## Sessions and devices

Each sign-in that issues a refresh token is a **session**: a refresh token family, which
survives rotation. Sessions record the user agent and client IP of the request that opened
them, so users can recognise their devices.

```sh
curl -s $API/v1/me/sessions -H "Authorization: Bearer $TOKEN"
# → {"items": [{"id", "tenant_id", "user_agent", "ip", "created_at", "last_used_at", "expires_at"}]}
curl -sX DELETE $API/v1/me/sessions/<id> -H "Authorization: Bearer $TOKEN"
```

| Endpoint | Who |
|---|---|
| `GET /v1/me/sessions`, `DELETE /v1/me/sessions/{session}` | the signed-in user (not while impersonated) |
| `GET /v1/users/{id}/sessions` | `users:read` |
| `DELETE /v1/users/{id}/sessions/{session}` | `users:write`: sign out one device |
| `DELETE /v1/users/{id}/sessions` | `users:write`: sign out everywhere |

- Sessions are listed most recently used first; expired and revoked ones are left out.
- Revoking a session stops it from being refreshed. Access tokens it already issued stay valid
  until they expire (`auth.tokens.access_ttl`, 15 minutes by default); disable the user to cut
  those off at once.
- Revoking one session emits `user.session_revoked` with the user and session IDs.
- The IP is the direct peer's address; behind a proxy it is the proxy's.

## Passkeys

Users can register passkeys (WebAuthn: platform authenticators, phones, security keys) and
sign in with them instead of a password. A passkey is a strong factor on its own, so no one-time
code is asked.

```yaml
auth:
  webauthn:
    enabled: true                 # default
    rp_id: example.com            # default: the host of users.public_url
    origins: [https://app.example.com, https://tenarium.example.com]   # default: users.public_url's origin
```

- **`rp_id` is the domain passkeys are bound to.** Browsers only use a passkey on that domain or
  its subdomains, so choose the registrable domain (`example.com`) if the sign-in page and
  Tenarium live on different subdomains, and do not change it later: passkeys registered under
  one `rp_id` stop working under another. It must be a domain name; when `users.public_url` is
  an IP address (such as `http://127.0.0.1:8080`) and `rp_id` is not set, passkeys are disabled
  with a warning at startup. `localhost` works for development.
- **`origins`** are the full origins (`scheme://host[:port]`) of the pages that run the
  ceremonies; responses from other origins are rejected. Browsers only allow an origin on
  `rp_id` or one of its subdomains. List your application's sign-in page if it calls the API
  itself.
- Passkeys need Tenarium tokens (`auth.tokens.enabled`).

Registration (the signed-in user) and sign-in (no authentication, rate limited like
`/v1/auth/token`) are two-step ceremonies. The server state travels as a signed `ceremony`
string valid for 5 minutes, so any replica can finish what another started:

```sh
# register
curl -sX POST $API/v1/me/passkeys/register/begin -H "Authorization: Bearer $TOKEN"
# → {"options": {...}, "ceremony": "..."}   pass options.publicKey to navigator.credentials.create()
curl -sX POST $API/v1/me/passkeys/register/finish -H "Authorization: Bearer $TOKEN" \
  -d '{"ceremony":"...","name":"MacBook","credential":<the PublicKeyCredential as JSON>}'

# sign in (email optional: without it the browser offers any passkey it has for the site)
curl -sX POST $API/v1/auth/passkey/begin -d '{"email":"ada@acme.io"}'
# → {"options": {...}, "ceremony": "..."}   pass options.publicKey to navigator.credentials.get()
curl -sX POST $API/v1/auth/passkey/finish -d '{"ceremony":"...","credential":{...},"tenant":"acme"}'
# → the same token pair as /v1/auth/token
```

- `GET /v1/me/passkeys` lists the user's passkeys, `DELETE /v1/me/passkeys/{passkey}` removes
  one. A user can have up to 20.
- Unknown emails get the same kind of answer as known ones, so `begin` does not reveal which
  accounts exist. A failed or replayed ceremony answers 401 `passkey_rejected`.
- Sign-in refuses disabled users, locked accounts and, as for passwords, addresses whose tenant
  [enforces SSO](auth.md#single-sign-on-per-tenant). The signature counter is stored and a
  cloned authenticator is rejected.
- Events: `user.passkey_added`, `user.passkey_removed`.

## Impersonation

Support staff can act as a user for a short time, for example to reproduce a problem the user
sees. It needs `users:impersonate`, which is platform-only.

```yaml
auth:
  impersonation:
    require_consent: true   # default: the user must issue a consent code first
    max_ttl: 1h             # default: upper bound for a session's ttl
```

```sh
# 1. the user creates a single-use consent code (ttl default 1h, at most 24h) and hands it to support
curl -sX POST $API/v1/me/impersonation-consent -H "Authorization: Bearer $USER_TOKEN" -d '{"ttl":"2h"}'
# → {"code": "...", "expires_at": "..."}
# 2. support opens a session as the user in one of the user's tenants
curl -sX POST $API/v1/users/ada@acme.io/impersonate -H "Authorization: Bearer $SUPPORT_TOKEN" \
  -d '{"tenant":"acme","reason":"ticket #4711: dashboard is empty","ttl":"15m","consent_code":"..."}'
# → {"access_token": "...", "token_type": "Bearer", "expires_in": 900, "tenant_id": "..."}
```

- The result is a single access token, without refresh token, valid for `ttl` (default 15
  minutes, at most `auth.impersonation.max_ttl`). The session is always **tenant-scoped**, with
  the user's roles in that tenant; `tenant` and a `reason` (up to 500 characters) are required.
- Only active users without platform roles can be impersonated, so support cannot gain admin
  rights this way. An impersonated session cannot impersonate again.
- With `require_consent` (the default), a missing, wrong, expired or already used code answers
  403 `consent_required`. Codes are bound to the user who issued them.
- While impersonating, the session cannot create API keys, change webhooks, SSO or roles, manage
  users, export or erase data, or manage the user's own password, two-factor authentication,
  passkeys and consent codes.
- **Audit.** The access token carries the impersonator in the RFC 8693 `act` claim. Every event
  caused during the session has the actor
  `core/token:<user-id>;impersonated-by=<authenticator>:<subject>`, for example
  `core/token:0192...;impersonated-by=core/token:0191...`. Granting consent emits
  `user.impersonation_consented`, starting a session `user.impersonated` (with the
  impersonator, reason, tenant, expiry and whether consent was used).

## Email

Invitations and password resets are sent through a **mailer** plugin, typically `smtp`:

```yaml
users:
  public_url: https://tenarium.example.com   # used for links in emails
  product_name: Acme Cloud
  mailer: smtp                               # optional if there is only one mailer
  templates:                                 # optional overrides (Go text/template)
    invitation:
      subject: "Welcome to {{.Product}}"
      text: "Hi {{.User.Name}}, finish your setup here: {{.Link}} (expires {{.Expires}})"
      html: "<p>Hi {{.User.Name}}, <a href=\"{{.Link}}\">finish your setup</a>.</p>"

plugins:
  - plugin: smtp
    config:
      host: smtp.example.com
      port: 587
      username: apikey
      password: ${SMTP_PASSWORD}
      from: "Acme Cloud <no-reply@acme.example>"
```

Template kinds: `invitation`, `password_reset`, `magic_link`, `email_change` (sent to the new
address) and `email_changed` (the notice to the old address, which also has `{{.NewEmail}}`).
Without any mailer, emails are written to the log (fine for development, so you can copy the
link) and Tenarium warns at startup.

## The first administrator

```yaml
bootstrap:
  users:
    - email: admin@example.com
      name: Admin
      roles: [admin]
      password: ${TENARIUM_ADMIN_PASSWORD}
```

Bootstrap users are created only if their email is unknown, so this is safe to keep in the
configuration.

## Hooks and events

- `user.before_create` and `user.before_update` hooks can change a user's name, roles and
  attributes, or reject the change (for example to allow only some email domains).
- Events: `user.created`, `user.updated`, `user.activated`, `user.disabled`, `user.enabled`,
  `user.deleted`, `user.password_changed`, `user.locked`, `user.mfa_enabled`, `user.mfa_disabled`,
  `user.passkey_added`, `user.passkey_removed`, `user.impersonation_consented`,
  `user.impersonated`, `user.erased`, `user.session_revoked`. They never contain credentials.

## Personal data

`GET /v1/me/export` and `GET /v1/users/{id}/export` return everything Tenarium stores about a
user; `POST /v1/users/{id}/erase` deletes the user and can redact them from the event log. See
[data protection](privacy.md).

## API summary

| Endpoint | Who |
|---|---|
| `POST /v1/auth/token`, `/logout`, `/password-reset`, `/password-reset/confirm`, `/invitations/accept`, `/passkey/begin`, `/passkey/finish`, `/magic-link`, `/email-change/confirm` | anyone (rate limited, like everything under `/v1/auth/`) |
| `GET /v1/me`, `GET /v1/me/memberships`, `POST /v1/me/password`, `/v1/me/mfa/...`, `/v1/me/passkeys/...`, `/v1/me/sessions[/{session}]`, `POST /v1/me/email`, `GET /v1/me/export`, `POST /v1/me/impersonation-consent` | the signed-in user |
| `GET /v1/auth/sso/start` · `/callback` · `/discover`, `/v1/auth/sso/saml/{tenant}/...` | anyone ([SSO](auth.md#single-sign-on-per-tenant)) |
| `GET/POST /v1/users`, `GET/PATCH/DELETE /v1/users/{id}` | `users:read` / `users:write` |
| `POST /v1/users/{id}/disable` · `/enable` · `/password` · `/invitation` | `users:write` |
| `DELETE /v1/users/{id}/sessions[/{session}]` · `/mfa`, `GET /v1/users/{id}/sessions`, `GET /v1/users/{id}/memberships` | `users:write` / `users:read` |
| `GET /v1/users/{id}/export`, `POST /v1/users/{id}/erase` | `users:read` / `data:erase` |
| `POST /v1/users/{id}/impersonate` | `users:impersonate` |

User administration is platform-level: tenant-scoped callers manage *members* of their tenants,
not users.
