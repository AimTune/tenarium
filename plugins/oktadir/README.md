# okta-directory

Keeps Tenarium's platform users in an **Okta** org, through the Users API.

| Interface | Implemented | Notes |
|---|---|---|
| `sdk.UserDirectory` | yes | create (staged), update profile, suspend/deactivate, delete, set password |
| `sdk.InvitationSender` | yes | Okta activation email when `send_invitation: true`; otherwise `ErrUnsupported` and Tenarium sends its own |
| `sdk.PasswordVerifier` | optional | when `verify_passwords: true`, through the Authentication API (`/api/v1/authn`) |

## Configuration

```yaml
users:
  directory: okta

plugins:
  - plugin: okta-directory
    name: okta
    config:
      org_url: https://acme.okta.com
      # Either an API token ...
      api_token: ${OKTA_API_TOKEN}
      # ... or (recommended) an API service app with private key JWT:
      # oauth:
      #   client_id: 0oa...
      #   private_key_file: /etc/tenarium/okta-key.pem   # or private_key: <PEM>
      #   key_id: my-key-id
      #   scopes: [okta.users.read, okta.users.manage]   # default
      user_id_attribute: tenariumUserId   # custom profile property (add it to the profile schema)
      attribute_map:                      # Tenarium attribute -> Okta profile property
        dept: department
      disable_action: suspend             # suspend | deactivate
      send_invitation: false
      verify_passwords: false
      timeout: 10s
```

**API token** (`SSWS`) acts with the permissions of the admin who created it; a *User
Administrator* or a custom role that can manage users is enough.

**OAuth service app.** Create an *API Services* app with *Public key / Private key* client
authentication, grant it `okta.users.read` and `okta.users.manage`, and give it an admin role
that can manage users. RSA (2048+ bits, RS256) and EC (P-256/384/521) keys in PEM (PKCS#1,
SEC 1 or PKCS#8) are supported. **Turn off "Require DPoP"** for the app: the plugin uses plain
Bearer tokens. Tokens are cached until shortly before they expire.

## Behaviour

- **Find or create by login.** The email is the login. `CreateUser` looks it up with
  `GET /api/v1/users/{login}`. With `user_id_attribute`, a user owned by another Tenarium user is
  refused; otherwise an existing user is adopted. New users are created with
  `activate=false` (status `STAGED`), with `login`, `email`, `firstName`, `lastName`, the owner
  property and mapped attributes. Okta requires both names: a missing first name falls back to
  the email's local part, a missing last name to `-`.
- **Update** applies the profile (absent mapped attributes are cleared, and the login follows
  the email if it was the email) and then the status:
  - `disabled`: `ACTIVE` users are suspended (`disable_action: suspend`, keeps app
    assignments). Other states are deactivated, and so is everyone with
    `disable_action: deactivate`. Note that deactivation removes app assignments in Okta.
  - enabled again: `SUSPENDED` users are unsuspended, `DEPROVISIONED` users are activated
    without email. They come back `PROVISIONED`, or `ACTIVE` if they have a password.
- **SetPassword** sets `credentials.password`. A `STAGED` user is then activated (no email),
  since setting the first password ends Tenarium's invitation. Policy violations return Okta's
  error causes, never the password.
- **Delete** deactivates (first `DELETE`) and deletes (second `DELETE`), with `sendEmail=false`.
  It is idempotent.
- **Invitations.** `SendInvitation` activates a `STAGED`/`DEPROVISIONED` user with
  `sendEmail=true`, or reactivates a `PROVISIONED` one. The user then chooses a password in
  Okta. Tenarium's user stays `invited` until it is activated in Tenarium.

### Password verification caveats

`verify_passwords` calls `POST /api/v1/authn` without an API token:

- `SUCCESS` passes. `401 E0000004` (wrong password, unknown, suspended or deprovisioned user)
  and `LOCKED_OUT` yield `ErrInvalidCredentials`. `MFA_REQUIRED`/`MFA_ENROLL` yield
  `ErrMFARequired`. Other states (e.g. `PASSWORD_EXPIRED`) are errors.
- On **Okta Identity Engine** orgs the Authn API is a legacy API that only works while your
  sign-on policies allow password-only authentication. Prefer signing in through Okta (the
  `oidc` plugin).
- All attempts come from Tenarium's IP, so Okta ThreatInsight and rate limits apply to that
  address.
