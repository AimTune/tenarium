# auth0-directory

Keeps Tenarium's platform users in an **Auth0 database connection**, through the Management
API v2.

| Interface | Implemented | Notes |
|---|---|---|
| `sdk.UserDirectory` | yes | create, update, block, delete, set password |
| `sdk.InvitationSender` | yes | `invitation: change_password_email` or `verification_email`; with `none` (default) it returns `ErrUnsupported` and Tenarium sends its own invitation |
| `sdk.PasswordVerifier` | optional | only when `password_login` is set (Resource Owner Password grant) |

## Configuration

```yaml
users:
  directory: auth0

plugins:
  - plugin: auth0-directory
    name: auth0
    config:
      domain: acme.eu.auth0.com           # or https://acme.eu.auth0.com
      client_id: ${AUTH0_M2M_CLIENT_ID}   # M2M app authorized for the Management API
      client_secret: ${AUTH0_M2M_CLIENT_SECRET}
      # audience: https://acme.eu.auth0.com/api/v2/   # set it with a custom domain
      connection: Username-Password-Authentication
      verify_email: false                 # Auth0 sends its verification email on create
      invitation: change_password_email   # none | change_password_email | verification_email
      # invitation_client_id: ...         # app named in Auth0 emails; default password_login.client_id or client_id
      password_login:                     # optional: enables POST /v1/auth/token for these users
        client_id: ${AUTH0_APP_CLIENT_ID}
        client_secret: ${AUTH0_APP_CLIENT_SECRET}
      timeout: 10s
```

The M2M application needs the `read:users`, `create:users`, `update:users` and `delete:users`
scopes. Its tokens are fetched with the client credentials grant (`audience` parameter) and
cached until they expire.

## Behaviour

- **Find or create by email.** `CreateUser` looks the email up with
  `GET /api/v2/users-by-email` and only considers users of the configured connection. A user
  carrying `app_metadata.tenarium.user_id` of another Tenarium user is refused; one without it
  (created outside Tenarium) is adopted. Otherwise the user is created with a random, unknown
  password (database connections require one); Tenarium then sets the real password or sends an
  invitation.
- **Mapping.** `name` (the email when empty), `email_verified`, `blocked` (= status
  `disabled`), and `app_metadata.tenarium = {user_id, attributes}`. Email changes are sent with
  the connection, as Auth0 requires.
- **Delete** is idempotent (a missing user is fine).
- **Errors** carry Auth0's message (e.g. `PasswordStrengthError`) and never the password.

### Invitations

- `change_password_email` calls `POST /dbconnections/change_password`: Auth0 emails a link to
  choose a password. The application in `invitation_client_id` must be enabled for the
  connection. Tenarium's user stays `invited` until it is activated in Tenarium (e.g. a
  password set through Tenarium or a sign-in linked through the `oidc` plugin).
- `verification_email` queues `POST /api/v2/jobs/verification-email`. It only verifies the
  address; combine it with a password set elsewhere.
- Password-change *tickets* are not used: they return a URL that must be emailed by the caller.

### Password verification caveats

`password_login` uses the `http://auth0.com/oauth/grant-type/password-realm` grant with
`realm` = the connection. Enable the **Password** grant type on that application. Be aware that:

- Auth0 discourages the Resource Owner Password flow; prefer signing in through Auth0 (the
  `oidc` plugin) where you can.
- All attempts come from Tenarium's IP address, so Auth0's brute-force and suspicious-IP
  protection may throttle or block it. Consider allow-listing that IP in Attack Protection.
- If MFA applies, the grant answers `mfa_required` and verification fails with
  `ErrMFARequired`, never with "invalid credentials".
- Blocked users and wrong passwords both yield `ErrInvalidCredentials`.
