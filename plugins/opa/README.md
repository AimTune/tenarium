# opa

An authorizer that queries an [Open Policy Agent](https://www.openpolicyagent.org) server:
`POST /v1/data/<path>` with the request as `input`. Policies run only on the server.
Tenarium does not embed an OPA engine or load bundles.

The built-in tenant-scope rule runs before every authorizer, and a policy cannot relax it.

```yaml
- plugin: opa
  config:
    url: http://opa:8181
    path: tenarium/authz              # or tenarium.authz, or tenarium/authz/allow
    token: ${OPA_TOKEN}               # optional, for --authentication=token
    include_tenant: true              # add the resource's tenant and its ancestors
    on_not_allowed: abstain           # abstain | deny
    fail_mode: abstain                # abstain | deny
    timeout: 2s
    cache_ttl: 5s                     # "0s" disables
    cache_size: 10000
```

## Input

```json
{
  "principal": {"subject": "...", "kind": "user", "authenticator": "oidc", "tenant_id": "...", "roles": [], "claims": {}},
  "action": "tenants:update", "action_resource": "tenants", "action_verb": "update",
  "resource": {"type": "tenant", "id": "...", "tenant_id": "..."},
  "tenant": {"id": "...", "slug": "...", "status": "active", "plan": "pro", "labels": {}, "...": "..."},
  "tenant_ancestors": ["parent-id", "grandparent-id"]
}
```

`tenant` and `tenant_ancestors` are only present with `include_tenant` and when the
resource belongs to a tenant. Results are cached on everything except the tenant data, so
tenant changes can take up to `cache_ttl` to show up.

## Result

| result | decision |
|---|---|
| undefined (no document at the path) | abstain |
| `true` | allow |
| `false` | `on_not_allowed` |
| `{"deny": true \| "msg" \| ["msg", ...]}` (non-empty) | deny, with the messages as reason |
| `{"allow": true}` | allow |
| `{"allow": false}` or `{}` | `on_not_allowed` |
| anything else, HTTP error, timeout | `fail_mode` |

`reason` (a string or a list) is included in the logged reason.

```rego
package tenarium.authz

import rego.v1

default allow := false
allow if "admin" in input.principal.roles
allow if { input.action_verb == "read"; "viewer" in input.principal.roles }

deny contains "tenant is frozen" if input.tenant.labels.frozen == "true"
reason := "no matching role" if not allow
```

Denials are logged at info level with their reason. `(*Plugin).Check` returns the decision
with its reason. `/readyz` includes OPA's `GET /health`.
