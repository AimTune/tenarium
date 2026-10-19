# spicedb

An authorizer that asks [SpiceDB](https://authzed.com/spicedb) through its HTTP gateway
(`POST /v1/permissions/check`, authenticated with the preshared key). It can also write
tenant hierarchy and membership relationships (`POST /v1/relationships/write`) from
Tenarium events.

The built-in tenant-scope rule runs before every authorizer, and this plugin cannot relax
it.

```yaml
- plugin: spicedb
  config:
    url: http://spicedb:8443          # spicedb serve --http-enabled
    token: ${SPICEDB_PRESHARED_KEY}
    subject: "{principal.kind}:{principal.subject}"     # "type:id" or "type:id#relation"
    permission: "can_{action.verb}"
    permissions: {members:write: manage_members, events:read: ""}   # "" = do not ask
    resource: "{resource.type}:{resource.id_or_tenant}"
    resources: {member: "tenant:{resource.tenant_id}"}
    global_resource: platform:default
    consistency: minimize_latency     # | fully_consistent | at_least_as_fresh
    on_not_allowed: abstain           # abstain | deny
    fail_mode: abstain                # abstain | deny
    timeout: 2s
    cache_ttl: 5s
    cache_size: 10000
    tenant_type: tenant
    parent_relation: parent
    sync:
      tenant_parents: true            # tenant:<child>#parent@tenant:<parent>
      members: true                   # tenant:<id>#<role>@user:<user_id>
      member_subject: "user:{member.user_id}"
      roles: {owner: owner, member: member}   # empty = same name
```

Placeholders and the empty-identifier rule are the same as in the
[openfga plugin](../openfga/README.md). `member_subject` uses the `{member.*}` placeholders.

`at_least_as_fresh` uses the ZedToken from this instance's latest relationship write. Until
the first write it falls back to `minimize_latency`.

## Decisions

| SpiceDB | decision |
|---|---|
| `PERMISSIONSHIP_HAS_PERMISSION` | allow |
| `NO_PERMISSION`, `CONDITIONAL_PERMISSION` (Tenarium sends no caveat context) | `on_not_allowed` |
| unmapped action, empty identifier | abstain |
| error, timeout, unknown permission, invalid ID | `fail_mode` |

SpiceDB object IDs only allow `[a-zA-Z0-9/_|\-=+]`. Subjects such as e-mail addresses are
rejected by SpiceDB, which leads to `fail_mode`. Use templates that produce valid IDs, such
as user IDs instead of e-mail addresses.

## Example schema

```
definition user {}

definition tenant {
    relation parent: tenant
    relation owner: user
    relation member: user

    permission admin = owner + parent->admin
    permission can_update = admin
    permission can_read = admin + member
}
```

Writes use `OPERATION_TOUCH` and `OPERATION_DELETE`, which are idempotent. Every write
clears the decision cache. Health calls `POST /v1/schema/read`: a missing schema still
counts as healthy, and a wrong key does not.
