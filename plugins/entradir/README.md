# entra-directory

Keeps Tenarium's platform users in **Microsoft Entra ID** (Azure AD), through Microsoft Graph.

| Interface | Implemented | Notes |
|---|---|---|
| `sdk.UserDirectory` | yes | create, update, enable/disable, delete; `SetPassword` in member mode |
| `sdk.InvitationSender` | yes | guest mode: Microsoft B2B invitation email; member mode returns `ErrUnsupported` (Tenarium sends its own) |
| `sdk.PasswordVerifier` | **no** | Entra has no API to check a password. Users sign in through OIDC/SSO (the `oidc` plugin with Entra as identity provider), so `POST /v1/auth/token` is unavailable for them |

## Configuration

```yaml
users:
  directory: entra

plugins:
  - plugin: entra-directory
    name: entra
    config:
      tenant_id: 00000000-0000-0000-0000-000000000000
      client_id: ${ENTRA_CLIENT_ID}
      client_secret: ${ENTRA_CLIENT_SECRET}
      mode: member                          # member | guest
      upn_domain: contoso.onmicrosoft.com   # member mode: ada@example.com -> ada_example.com@contoso.onmicrosoft.com
      force_change_password: false          # make users change passwords set by Tenarium
      # invite_redirect_url: https://console.example.com/   # guest mode, default https://myapps.microsoft.com
      user_id_attribute: employeeId         # or extension_<appId>_tenariumUserId
      attribute_map:                        # Tenarium attribute -> Graph user property
        dept: department
      hard_delete: false                    # also purge from deleted items
      # authority_url: https://login.microsoftonline.com   # national clouds: change both URLs
      # graph_url: https://graph.microsoft.com/v1.0
      timeout: 15s
```

The app registration authenticates with the client credentials grant (scope
`https://graph.microsoft.com/.default`) and needs these **application** permissions, with
admin consent:

- `User.ReadWrite.All` (members and guests).
- `User.Invite.All` in guest mode.
- To set passwords: `User-PasswordProfile.ReadWrite.All`, or assign the app the
  *User Administrator* directory role. Without it `SetPassword` fails with 403.

## Modes

**member** (default). Users are member accounts. `CreateUser` creates them with
`accountEnabled`, `displayName`, `mail`, a generated `mailNickname` and `userPrincipalName`, and a
random password with `forceChangePasswordNextSignIn`. Tenarium then sets the real password
(`PATCH passwordProfile`) when the user is created with one or accepts Tenarium's invitation.
Without `upn_domain`, the email is used as the UPN, so its domain must be verified in the
tenant.

**guest**. Users are B2B guests who sign in with their home account. `CreateUser` uses
`POST /invitations` without a message and then sets the other properties. `SendInvitation`
re-invites with `sendInvitationMessage: true`, so Microsoft sends the email. `SetPassword`
returns `ErrUnsupported`.

## Behaviour

- **Find or create by email.** The directory searches `mail eq '<email>'` (and the generated UPN
  in member mode). With `user_id_attribute`, a user owned by another Tenarium user is refused;
  otherwise an existing user is adopted.
- **Mapping.** `displayName` (the email when the name is empty), `accountEnabled` (= status
  not `disabled`), `mail`, the owner property and `attribute_map` (absent attributes are
  cleared). An email change also renames the UPN, but only when the directory generated it.
  `email_verified` has no Entra equivalent and is ignored.
- **Replication.** Entra replicates new objects asynchronously, so requests by ID that get a
  404 are retried briefly (0.5 s, 1 s, 2 s). Throttled requests (429/503) are retried after
  `Retry-After` (at most 10 s).
- **Delete** moves the user to deleted items (restorable for 30 days), or purges it with
  `hard_delete`. It is idempotent.
