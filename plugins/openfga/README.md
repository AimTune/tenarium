# openfga

An authorizer that asks [OpenFGA](https://openfga.dev) for each API request
(`POST /stores/{store_id}/check`). It can also keep tenant hierarchy and membership
tuples in sync with Tenarium events.

The built-in tenant-scope rule runs before every authorizer, and this plugin cannot relax
it. Decisions are combined as usual: any `deny` wins, and at least one `allow` is required.

```yaml
- plugin: openfga
  config:
    url: http://openfga:8080
    store_id: 01HXYZ...
    authorization_model_id: ""        # optional; latest model when empty
    api_token: ${OPENFGA_TOKEN}       # optional preshared key
    user: "{principal.kind}:{principal.subject}"        # default
    relation: "can_{action.verb}"                         # default for unmapped actions
    relations:                                            # per action; "" = do not ask (abstain)
      members:write: can_manage_members
      events:read: ""
    object: "{resource.type}:{resource.id_or_tenant}"    # default
    objects:                                              # per resource type
      member: "tenant:{resource.tenant_id}"
      usage: "tenant:{resource.tenant_id}"
    global_object: platform:default   # used when the object would be empty (e.g. listing plans)
    consistency: ""                   # minimize_latency | higher_consistency
    on_not_allowed: abstain           # abstain | deny  (allowed=false)
    fail_mode: abstain                # abstain | deny  (unreachable, timeout, bad response)
    timeout: 2s
    cache_ttl: 5s                     # "0s" disables the decision cache
    cache_size: 10000
    tenant_type: tenant
    parent_relation: parent
    contextual_parents: false         # send the resource tenant's ancestry as contextual tuples
    principal_tenant_relation: ""     # e.g. member: (user, member, tenant:<principal tenant>)
    sync:                             # optional subscription writing tuples
      tenant_parents: true            # tenant:<child>#parent@tenant:<parent>
      members: true                   # tenant:<id>#<role>@user:<user_id> for active members
      member_user: "user:{member.user_id}"
      roles: {owner: admin, admin: admin, member: member, viewer: viewer}   # empty = same name
```

## Placeholders

`user`, `relation`, `object` and `objects` can use:

| placeholder | value |
|---|---|
| `{principal.kind}` `{principal.subject}` `{principal.authenticator}` `{principal.tenant_id}` | the caller |
| `{action}` `{action.resource}` `{action.verb}` | e.g. `tenants:update`, `tenants`, `update` |
| `{resource.type}` `{resource.id}` `{resource.tenant_id}` | the target |
| `{resource.id_or_tenant}` | the resource ID, or its tenant ID when it has none |

`member_user` can use `{member.user_id}`, `{member.email}`, `{member.id}` and
`{member.tenant_id}`.

If a placeholder is empty, the request is not sent and the plugin abstains, so an
identifier like `tenant:` is never checked. The object template is the exception: it falls
back to `global_object` when one is set. For example, creating a child tenant is
authorized against `tenant:<parent>`, while creating a root tenant uses `global_object` or
abstains.

## Decisions

| OpenFGA | decision |
|---|---|
| `allowed: true` | allow |
| `allowed: false` | `on_not_allowed` (abstain by default) |
| action mapped to `""`, empty identifier | abstain |
| error, timeout, unknown relation | `fail_mode` (abstain by default) |

The plugin never returns an error to the core. Denials are logged at info level with the
reason (for example `openfga: no relationship user:ann can_delete tenant:…`).
`(*Plugin).Check` returns the decision together with its reason.

Definite answers are cached for `cache_ttl`. Errors are never cached, and the cache is
cleared after every tuple write.

## Example model

```
model
  schema 1.1
type user
type tenant
  relations
    define parent: [tenant]
    define admin: [user] or admin from parent
    define member: [user]
    define can_read: admin or member
    define can_update: admin
    define can_create: admin
```

## Tuple sync

Delivery is at least once. Writing a tuple that already exists, or deleting one that is
already gone, counts as success. Only `active` members get a tuple. When a role changes
or a member is suspended, the old tuple is removed. Deleting a tenant removes only its
`parent` tuple, because Tenarium does not emit `member_removed` for members of a deleted
tenant. Their tuples stay on the deleted tenant object.

`/readyz` includes `GET /stores/{store_id}`.
