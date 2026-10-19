# ldap-directory

Keeps Tenarium's platform users in a **writable LDAP directory** (OpenLDAP, 389 Directory
Server, ...) or **Active Directory**.

| Interface | Implemented | Notes |
|---|---|---|
| `sdk.UserDirectory` | yes | add, modify (and rename), delete entries; set passwords |
| `sdk.PasswordVerifier` | yes (default) | binds as the user's entry; `verify_passwords: false` turns it off |
| `sdk.InvitationSender` | **no** | LDAP sends no email; Tenarium sends its own invitation and sets the chosen password |

## Configuration

```yaml
users:
  directory: ldap

plugins:
  - plugin: ldap-directory
    name: ldap
    config:
      url: ldaps://ldap.example.com:636      # or ldap:// with start_tls: true
      bind_dn: cn=tenarium,ou=services,dc=example,dc=org
      bind_password: ${LDAP_BIND_PASSWORD}
      user_base_dn: ou=people,dc=example,dc=org   # where entries are created
      # search_base_dn: dc=example,dc=org         # where users are looked up (default user_base_dn)
      # user_filter: (mail=%s)                    # %s = escaped email
      object_classes: [top, person, organizationalPerson, inetOrgPerson]
      rdn_attribute: uid
      rdn_source: email            # email (renamed when the email changes) | user_id (stable)
      id_attribute: entryUUID      # external ID: entryUUID, nsUniqueId, objectGUID, dn, ...
      email_attribute: mail
      name_attribute: cn           # "-" leaves an attribute out
      given_name_attribute: givenName
      surname_attribute: sn
      user_id_attribute: employeeNumber   # owner marker (optional)
      attribute_map:
        dept: departmentNumber
      extra_attributes:            # set on create; text/template over .ID .IDHex .Email .LocalPart .Domain .Name .GivenName .Surname
        description: "Managed by Tenarium"
      password_mode: password_modify      # password_modify | user_password | unicode_pwd
      disable:
        mode: attribute                   # none | attribute | ad_user_account_control
        attribute: pwdAccountLockedTime   # OpenLDAP ppolicy
        disabled_value: "000001010000Z"   # locks the account permanently
        enabled_value: ""                 # empty: attribute removed
      verify_passwords: true
      timeout: 5s
```

The service account needs write access to `user_base_dn` (add, modify, delete, rename) and the
right to set passwords.

### Active Directory

`active_directory: true` changes the defaults:

| Setting | Default with AD |
|---|---|
| `object_classes` | `top, person, organizationalPerson, user` |
| `rdn_attribute` | `cn` (value: the email) |
| `id_attribute` | `objectGUID` (canonical GUID string) |
| `name_attribute` | `displayName` |
| `password_mode` | `unicode_pwd`, which needs `ldaps://` or `start_tls` (enforced) |
| `disable.mode` | `ad_user_account_control` |
| `extra_attributes.userPrincipalName` | `{{.Email}}` |

AD generates a `sAMAccountName` if none is given. To set one, use for example
`sAMAccountName: "{{slice .IDHex 0 20}}"`. Entries are created with `userAccountControl: 514`
(disabled), because AD refuses enabled accounts without a password. `SetPassword` writes
`unicodePwd` (the password in quotes, UTF-16LE) and then clears the `ACCOUNTDISABLE` bit unless
the user is disabled. Invited users therefore stay disabled in AD until they have a password.

## Behaviour

- **Find or create by email.** `CreateUser` searches `user_filter` under `search_base_dn`.
  With `user_id_attribute`, an entry owned by another Tenarium user is refused; otherwise an
  existing entry is adopted. New entries are named `<rdn_attribute>=<email or user ID>` under
  `user_base_dn` and get the object classes, the mapped attributes and `extra_attributes`. The
  external ID is the `id_attribute` value read back after the add.
- **Mapping.** Email, name (the email when empty), given name and surname (`sn` is mandatory
  for `person`; it falls back to the full name or the email's local part), the owner marker and
  `attribute_map`. On update, absent values remove the attribute. The RDN attribute only
  changes through a rename (`ModifyDN`), when `rdn_source: email` and the email changes.
- **Disabled users.** With `mode: attribute` the attribute is set to `disabled_value` or
  `enabled_value` (removed when empty). For example, use `pwdAccountLockedTime` with the
  ppolicy overlay so that the server itself refuses binds. `VerifyPassword` also refuses entries
  carrying `disabled_value`. With `mode: none` the status is not written to the directory.
- **Passwords.**
  - `password_modify` uses the RFC 3062 Password Modify extended operation, so the server
    hashes the password according to its policy.
  - `user_password` replaces `userPassword` with the plain value. Use it only if the server
    hashes it (e.g. OpenLDAP `ppolicy_hash_cleartext`); otherwise it is stored as is.
  - `unicode_pwd` is for Active Directory.
  - Policy rejections (constraint violation, unwilling to perform) are reported without the
    password.
- **VerifyPassword** binds as the entry on a fresh connection. Wrong passwords, missing entries
  and disabled entries yield `ErrInvalidCredentials`. Empty passwords are refused, because they
  would be unauthenticated binds.
- **Delete** removes the entry and is idempotent.

## Tests

Unit tests cover the entry building, the configuration and an Active Directory flow against an
in-memory fake. The integration test runs against a real OpenLDAP when
`TENARIUM_TEST_LDAP_URL` is set (optional: `TENARIUM_TEST_LDAP_BIND_DN`,
`TENARIUM_TEST_LDAP_BIND_PASSWORD`, `TENARIUM_TEST_LDAP_BASE_DN`):

```sh
docker run --rm -d -p 3389:389 -e LDAP_DOMAIN=example.org -e LDAP_ADMIN_PASSWORD=admin osixia/openldap:1.5.0
TENARIUM_TEST_LDAP_URL=ldap://localhost:3389 go test ./plugins/ldapdir/ -run Integration
```
