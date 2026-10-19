# Data protection

Tools for data subject requests (GDPR articles 15, 17 and 20, and similar laws): exports of a
tenant's or a user's data, erasure of a user with redaction of the event log, and purging the
data of deleted tenants. They cover what **Tenarium** stores. Data your plugins put elsewhere
(provisioned databases, buckets, CRM records, Kafka topics, SIEM indexes, archives) is out of
their reach; handle it in those systems, for example from the `user.erased` and `tenant.purged`
events.

## Exports

```sh
curl -s $API/v1/tenants/acme/export -H "$AUTH" -o tenant-acme.json   # data:export
curl -s $API/v1/users/ada@acme.io/export -H "$AUTH" -o user.json      # users:read
curl -s $API/v1/me/export -H "Authorization: Bearer $TOKEN" -o me.json  # the signed-in user
```

Exports are JSON downloads (`Content-Disposition: attachment`, `Cache-Control: no-store`).

| Export | Contains |
|---|---|
| tenant | the tenant, its entitlements, members, usage counters (all periods), domains, API keys, webhooks, SSO connection, custom roles, groups, scheduled actions, and its events (newest 10,000; `events_truncated` is set when there are more) |
| user | the user, memberships, two-factor status, passkeys (name and dates), and the events the user caused while signed in with Tenarium tokens (newest 10,000) |

Secrets are never included: no password or API key hashes, webhook secrets, SSO client secrets,
SAML metadata, TOTP secrets or passkey key material.

`data:export` is held by tenant owners and admins (and platform admins), so customers can
serve their own portability requests. It is refused in [impersonated](users.md#impersonation)
sessions, as is `/v1/me/export`.

## Erasing a user

```sh
curl -sX POST $API/v1/users/ada@acme.io/erase -H "$AUTH" -d '{"redact_events": true}'
# → {"user_id": "0192...", "erased": true, "redacted_events": 42}
```

- The user is deleted like `DELETE /v1/users/{id}`: memberships, credentials, passkeys,
  sessions, and the identity in an external [user directory](users.md#where-identities-live-user-directories).
- With `redact_events`, every occurrence of the user's email and name (if at least 3
  characters long) inside event data is replaced with `[erased]`. Event actors keep the user ID,
  which is pseudonymous once the user record is gone.
- A `user.erased` event records the user ID and the number of redacted events.
- It needs `data:erase`, which is platform-only.

Limits to be aware of:

- Redaction is a text replacement in the `events` table of the database. Copies outside it are
  not touched: events already delivered to plugins (Kafka, webhooks, SIEM, archives), tenant
  webhook delivery logs (kept for `webhooks.delivery_retention`) and database backups.
- A name that also appears in unrelated text (another person with the same name, a tenant
  called the same) is replaced there too.

## Purging deleted tenants

A deleted tenant stays in the database as a record with status `deleted`, together with its
related rows, unless purging is configured:

```yaml
tenants:
  deletion_grace_period: 720h   # optional: restorable for 30 days
  purge_after: 2160h            # then remove the data 90 days after deletion
```

The [scheduler](operations.md#scaling-and-high-availability) checks at most once an hour (on
every replica with `scheduler.interval` > 0) for tenants deleted longer than `purge_after` ago.
For each it removes members, usage, API keys, domains, webhooks (and their delivery logs), the
SSO connection, custom roles, groups and scheduled actions, blanks the tenant's settings, labels,
features and limits, sets the status reason to `purged`, and emits `tenant.purged`. The tenant
record itself remains as a tombstone (ID, slug, name, plan, timestamps), so references in the
event log still resolve.

The event log is not purged by this: events of the tenant, including the tenant snapshots inside
`tenant.*` events, are removed by `events.retention` like any others. Set a retention, or archive
and prune events yourself, if deleted tenants' data must disappear from the log too.
