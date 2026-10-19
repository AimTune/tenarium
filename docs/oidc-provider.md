# OpenID provider

Tenarium can be the sign-in service of your own applications: they redirect users to Tenarium,
users sign in with their Tenarium account (password, then one-time code if enabled), approve
the application, and the application receives an ID token, an access token for the Tenarium API
and, if requested, a refresh token. It is a standard OpenID Connect provider (authorization
code flow with PKCE), so any certified OIDC client library works.

This is different from [per-tenant SSO](auth.md#single-sign-on-per-tenant), where Tenarium is
the *client* of a customer's identity provider. The two combine: a user can reach Tenarium's
login through your application, and the tenants' own SSO still governs who may use a password.

```yaml
auth:
  tokens:
    enabled: true          # required
    issuer: ""             # default users.public_url; must be the URL Tenarium is served at
  provider:
    enabled: true          # default
    session_ttl: 12h       # how long the browser stays signed in at Tenarium
users:
  public_url: https://login.example.com
```

## Registering applications

Clients are managed by platform callers only (`oauthclients:read|write`):

```sh
curl -sX POST $API/v1/oauth-clients -H "$AUTH" -d '{
  "name": "Acme Dashboard",
  "redirect_uris": ["https://app.example.com/callback"],
  "post_logout_redirect_uris": ["https://app.example.com/"],
  "scopes": ["openid", "profile", "email", "offline_access"],
  "first_party": true}'
# → {"client": {"id": "tc_...", ...}, "client_secret": "..."}   the secret is shown only once
```

| Field | Meaning |
|---|---|
| `redirect_uris` | 1 to 20 exact redirect URIs: `https`, `http` on loopback only (`localhost`, `127.0.0.1`, `::1`; any host with `auth.sso.allow_private_issuers` for development), or a private-use scheme with a dot for native apps (`com.example.app:/cb`). No fragments. |
| `post_logout_redirect_uris` | where `/oauth/logout` may send the browser afterwards |
| `scopes` | what the client may ask for: `openid` (always required in requests), `profile`, `email`, `offline_access`. Default `openid profile email` |
| `first_party` | skip the consent screen (your own applications) |
| `public` | no secret (single-page and mobile apps); such clients must use PKCE |
| `tenant_id` | pin the client to one tenant: its sessions are always scoped to that tenant |

`GET/PUT/DELETE /v1/oauth-clients/{client}` read, replace and delete a client;
`POST /v1/oauth-clients/{client}/rotate-secret` issues a new secret (the old one stops working).
Changes emit `oauth_client.updated` and `oauth_client.deleted` (never with the secret hash).

## The flow

1. The application redirects to `/oauth/authorize`:

   ```
   GET /oauth/authorize?response_type=code&client_id=tc_...&redirect_uri=https://app.example.com/callback
       &scope=openid%20email%20offline_access&state=...&nonce=...
       &code_challenge=...&code_challenge_method=S256&tenant=acme
   ```

   - `code_challenge_method` must be `S256`. PKCE is mandatory for public clients and
     recommended for all.
   - `tenant` (ID or slug) asks for a session scoped to that tenant, with the user's role there;
     the user must be an active member. Without it, only users with platform roles can sign in.
     A client with `tenant_id` always uses its own tenant.
   - `prompt=login` forces the login form; `prompt=none` fails with `consent_required` instead
     of showing the consent page.
   - Unknown clients and unregistered redirect URIs get an error page, never a redirect. Other
     errors are sent to the redirect URI (`error`, `error_description`, `state`).

2. Tenarium shows its login page unless the browser already has a session (an HttpOnly
   `tenarium_session` cookie on `/oauth`, valid for `auth.provider.session_ttl`). The page
   accepts email and password, then asks for a one-time code if the user has
   [two-factor authentication](users.md#two-factor-authentication). Lockout applies, and users
   whose domain [enforces SSO](auth.md#single-sign-on-per-tenant) are told to use SSO; the page
   does not offer passkeys or SSO itself.

3. For clients that are not `first_party`, the user approves the requested scopes once per
   client; later requests for the same or fewer scopes skip the page. There is no API to list
   or revoke consents yet.

4. The browser returns to the redirect URI with `code`, `state` and `iss` (RFC 9207). The code is
   valid for one minute and can be redeemed once.

5. The application exchanges it at `/oauth/token`:

   ```sh
   curl -sX POST https://login.example.com/oauth/token -u "tc_...:$CLIENT_SECRET" \
     -d grant_type=authorization_code -d code=... -d redirect_uri=https://app.example.com/callback \
     -d code_verifier=...
   # public clients send client_id=tc_... in the form instead of -u
   ```

   ```json
   {"access_token": "...", "token_type": "Bearer", "expires_in": 900,
    "id_token": "...", "refresh_token": "...", "scope": "openid email offline_access"}
   ```

   - `client_secret_basic` and `client_secret_post` are accepted; public clients authenticate
     with their ID only.
   - The **ID token** is an ES256 JWT with `aud` = client ID and `sub`, `auth_time`, `azp`,
     `nonce` (if sent), `email` and `email_verified` (scope `email`), `name` (scope `profile`)
     and `tid` (tenant sessions).
   - The **access token** is a regular [Tenarium token](users.md#signing-in-with-tenarium-tokens)
     for the Tenarium API (`aud` = `auth.tokens.audience`); your services can verify it the same
     way.
   - A **refresh token** is issued only with `offline_access`. It is bound to the client it was
     issued to: `grant_type=refresh_token` succeeds only for that client (another client gets
     `invalid_grant`), and rotates the token as on `/v1/auth/token`.

6. `GET/POST /oauth/userinfo` with the access token returns `sub`, `email`, `email_verified`,
   `name` and `tid`.

7. `GET /oauth/logout?client_id=...&post_logout_redirect_uri=...&state=...` clears the browser
   session and redirects only to a registered post-logout URI. It does not revoke refresh tokens
   already issued; use `POST /v1/auth/logout` for that.

`/oauth/login` and `/oauth/token` share the `auth.rate_limit` limiter with `/v1/auth/`.

## Discovery

With the provider enabled, `/.well-known/openid-configuration` advertises
`authorization_endpoint`, `token_endpoint` (`/oauth/token`), `userinfo_endpoint`,
`end_session_endpoint`, `jwks_uri`, the `authorization_code` and `refresh_token` grants, the
`code` response type, scopes, `S256`, the client authentication methods and the claims above.
All URLs are built from the issuer, so `auth.tokens.issuer` (default `users.public_url`) must be
the public base URL Tenarium is reachable at. With `auth.provider.enabled: false`, discovery
describes only token verification, and the `/oauth` endpoints are not served.
