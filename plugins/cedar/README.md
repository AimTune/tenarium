# cedar

An in-process authorizer that evaluates [Cedar](https://www.cedarpolicy.com) policies with
`github.com/cedar-policy/cedar-go`. It needs no external service.

The built-in tenant-scope rule runs before every authorizer, and a policy cannot relax it.

```yaml
- plugin: cedar
  config:
    policies: |                       # inline, and/or policy_files
      @id("admins") permit (principal in Role::"admin", action, resource);
    policy_files: [/etc/tenarium/policies.cedar]
    entities_file: /etc/tenarium/entities.json   # optional static entities (e.g. role hierarchy)
    reload_interval: 10s              # poll files for changes; empty/0s disables
    on_no_match: abstain              # abstain | deny
    fail_mode: abstain                # abstain | deny (tenant lookups failed)
    principal_types: {user: User, service: Service}
    role_type: Role
    tenant_type: Tenant
    action_type: Action
    resource_types: {member: Member}  # default: CamelCase of the type (signing_key → SigningKey)
    tenant_cache_ttl: 10s
```

## Entities

| | entity | parents | attributes |
|---|---|---|---|
| principal | `User::"<subject>"` / `Service::"<subject>"` | `Role::"<role>"` for each role, `Tenant::"<tenant_id>"` if tenant-scoped | `subject`, `kind`, `authenticator`, `roles` (set), `tenant_id`?, `claims`? |
| action | `Action::"tenants:update"` | `Action::"tenants:*"`, `Action::"*:update"` | |
| tenant | `Tenant::"<id>"` | its parent tenant | `id`, `slug`, `name`, `status`, `plan`, `labels` (record), `parent_id`? |
| other resource | `<Type>::"<id>"` | `Tenant::"<tenant_id>"` | `type`, `id`, `tenant_id`? |

Tenants are loaded through the host, together with their ancestors. This means
`resource in Tenant::"<org>"` matches the whole subtree, and `principal in Tenant::"<org>"`
matches callers scoped to that tenant. A tenant about to be created is `Tenant::""` inside
its parent. Claims are converted to Cedar values. Nulls and fractional numbers are dropped.

The context is `{resource_type: String, tenant_scoped: Bool}`.

## Decisions

| Cedar | decision |
|---|---|
| a `forbid` matched | deny (reason: the policy IDs) |
| a `permit` matched, no `forbid` | allow |
| nothing matched | `on_no_match` (abstain by default) |
| tenant lookup failed | `fail_mode` |

Policy IDs come from `@id("...")` annotations. Without one, the ID is `<file>#<index>` or
`inline#<index>`. Duplicate IDs are rejected at startup.

Cedar skips a policy whose evaluation fails, for example when it reads a missing
attribute. Such errors are logged as warnings. Guard optional attributes with `has`,
especially in `forbid` policies.

## Reloading

With `reload_interval`, the policy files and the entities file are checked for changes
(modification time and size). A file that fails to parse keeps the previous policies in
force, logs an error and makes `/readyz` (Health) fail until a good version is loaded.

```cedar
@id("viewers-read")
permit (principal in Role::"viewer", action in Action::"*:read", resource);

@id("tenant-admins-subtree")
permit (principal in Role::"tenant-admin", action in Action::"tenants:*", resource)
when { principal has tenant_id && resource in Tenant::"org-id" };

@id("no-delete-prod")
forbid (principal, action == Action::"tenants:delete", resource is Tenant)
when { resource.labels has env && resource.labels.env == "prod" };
```
