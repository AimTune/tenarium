# opensearch-tenant

Gives every tenant its own index prefix on OpenSearch or Elasticsearch: an index template, an
optional initial index and write alias, and optionally a role and a user limited to the prefix.
The plugin uses the REST API directly over `net/http` (package `plugins/opensearchtenant`).

```yaml
- plugin: opensearch-tenant
  config:
    url: https://search.internal:9200        # or urls: [https://n1:9200, https://n2:9200] (required)
    username: tenarium                       # basic auth (optional)
    password: ${OPENSEARCH_PASSWORD}
    # api_key: ${ES_API_KEY}                 # "Authorization: ApiKey ..." instead of basic auth
    tls:
      ca_file: /etc/tenarium/opensearch-ca.pem
      insecure_skip_verify: false
    timeout: 30s                             # per request (default 30s)
    flavor: opensearch                       # opensearch (default) | elasticsearch
    name_template: "tenant_{{.Slug}}"        # default; renders the index prefix
    index_template:
      enabled: true                          # default true
      priority: 100                          # default 100
      shards: 1                              # index.number_of_shards
      replicas: 1                            # index.number_of_replicas
      settings: {"index.refresh_interval": "5s"}
      mappings: {"properties": {"title": {"type": "text"}}}
    create_initial_index: "000001"           # creates <prefix>-000001 (optional)
    initial_alias: write                     # write alias <prefix>-write on it (optional)
    security:
      enabled: true
      create_user: true
      password_secret: ${OPENSEARCH_TENANT_SECRET}
      index_permissions: [crud, create_index, "indices:admin/mapping/put"]   # default (OpenSearch)
      cluster_permissions: [cluster_composite_ops]                          # default (OpenSearch)
      backend_roles: []                      # OpenSearch only
    quota_from_limit: search_indices         # recorded in the template _meta
    on_deprovision: delete                   # delete (default) | keep | retain
```

## Behavior

- **Names.** `name_template` is a `text/template` over the tenant. The output is lowercased.
  Every character other than `a-z` and `0-9` (hyphens included) becomes `_`, runs of `_`
  collapse into one, and leading or trailing `_` are trimmed. The prefix therefore never
  starts with `-`, `_`, `+` or `.` and never contains `\ / * ? " < > | , # :` or spaces.
  Prefixes longer than 64 bytes are shortened and get a hash of the tenant ID appended. A
  template that renders the same prefix for two sample tenants is rejected at startup. Use only
  `ID` and `Slug`, because the prefix is computed again on deprovision.
  Each tenant owns the index pattern `<prefix>-*`. Since a prefix never contains a hyphen,
  one tenant's pattern can never match another tenant's indices: `tenant_acme-*` does not
  match `tenant_acme_corp-logs`. With the default template, slug `acme-corp` becomes
  `tenant_acme_corp`.
- **Objects.** For prefix `P`, the plugin manages:

  | Object | Name | Notes |
  |---|---|---|
  | Index template | `tenarium-P` | `index_patterns: ["P-*"]`, configured settings and mappings, `_meta` |
  | Initial index | `P-<create_initial_index>` | optional, with the write alias `P-<initial_alias>` |
  | Role | `P` | `index_permissions` on `P-*` (security only) |
  | User | `P` | password `TenantPassword(password_secret, tenant ID)` (`create_user` only) |
  | Role mapping | `P` | OpenSearch only; maps the user and `backend_roles` to the role |

  `TenantPassword` is the first 32 hex characters of HMAC-SHA256(secret, tenant ID).
  Applications that know the secret derive the same password, so the password is never
  stored and never returned by the API.
- **Ownership.** The template `_meta.tenarium_tenant_id`, the role (description
  `tenarium-tenant-id=<id>` on OpenSearch, `metadata.tenarium_tenant_id` on Elasticsearch)
  and the user (OpenSearch `attributes`, Elasticsearch `metadata`) record the owning tenant.
  Provision never adopts or overwrites an object that belongs to another tenant. It also never
  overwrites an unmarked object. Each object is written in one request together with its
  marker, so an interrupted run cannot leave an unmarked object behind, and an unmarked object
  was created by someone else. If no object carries the tenant's marker yet, the prefix is
  claimed only when no index matches `P-*`. Marker objects are written before any index is
  created, so a retry after an interruption always finds its own marker. Deprovision touches
  only objects marked for the tenant. It does not delete indices if any object of the prefix
  belongs to another tenant.
  At least one marker-carrying object is required: `index_template.enabled` or
  `security.enabled`. With the template disabled, the role is the marker.
- **Index template.** Composable templates (`_index_template`) are used on both flavors. When
  several templates match an index, only the one with the highest priority applies. Templates
  with overlapping patterns must not share a priority, or the cluster rejects the template. The
  default priority of 100 sits above typical catch-all templates. Set
  `index_template.enabled: false` if your own templates must keep applying to tenant indices.
  Templates only affect indices created after them. The plugin does not create data streams,
  because the template has no `data_stream` section.
- **Quota.** Neither OpenSearch nor Elasticsearch has per-prefix storage or index-count
  quotas. With `quota_from_limit`, the tenant's limit of that name is written to the template as
  `_meta.tenarium_quota` (and the limit name to `_meta.tenarium_quota_limit`), where your own
  tooling can read and enforce it. Unlimited tenants get no quota. The value is written at
  provisioning, so retry provisioning after a plan change to update it. This option requires the
  index template.
- **Deprovision.**
  - `delete` (the default, as with the other provisioners): the plugin first removes the user
    and the role mapping, which revokes access. It then lists every index matching `P-*`,
    including closed and hidden ones, and deletes each one by its concrete name. This works on
    clusters with `action.destructive_requires_name: true`, the default since Elasticsearch 8.
    Aliases go away with their indices. The role and then the template are removed last, so an
    interrupted run can be retried. Choose `retain` or `keep` if the indices hold primary data
    and not data derived from another store.
  - `keep`: nothing is touched. The markers stay, so a new tenant with the same slug cannot take
    over the data.
  - `retain`: indices are kept, and the user, role mapping and role are deleted. The template's
    `_meta` is replaced by `tenarium_deleted_tenant_id` and `tenarium_deleted_at`. Provisioning a
    tenant whose prefix collides then fails until an operator removes the indices and the
    template. With the template disabled, nothing marks retained indices, and a colliding tenant
    is refused because unmarked indices match its pattern.
- **Route.** `GET /v1/plugins/{instance}/tenants/{tenant}` returns `flavor`, `urls`, `prefix`,
  `index_pattern`, `index_template`, `initial_index`, `alias`, `role` and `user`. A tenant that
  does not exist, or that the caller may not read (`tenants:read`), gets 404.
- **Health.** `/readyz` calls `GET /_cluster/health` and fails when the status is `red`.
- **Failover.** With several `urls`, a request that fails at the transport level is retried on
  the next node, and that node is preferred from then on.

## OpenSearch and Elasticsearch differences

| | OpenSearch (`flavor: opensearch`) | Elasticsearch (`flavor: elasticsearch`) |
|---|---|---|
| Role | `PUT _plugins/_security/api/roles/P` with `index_permissions[].allowed_actions` and `cluster_permissions`; marker in `description` | `PUT _security/role/P` with `indices[].privileges` and `cluster`; marker in `metadata` |
| User | `PUT _plugins/_security/api/internalusers/P`; marker in `attributes` and `description` | `PUT _security/user/P` with `roles: [P]`; marker in `metadata` |
| Role mapping | `PUT _plugins/_security/api/rolesmapping/P` (user and `backend_roles`) | not used; the user carries the role. `backend_roles` is rejected; use ES role mappings yourself |
| Default index permissions | `crud`, `create_index`, `indices:admin/mapping/put` | `read`, `write`, `create_index`, `view_index_metadata` |
| Default cluster permissions | `cluster_composite_ops` (bulk, mget, msearch) | none |
| Password rules | the Security plugin may enforce strength rules; the derived 32-hex password passes the default rules | minimum 6 characters |

Index templates, `_cat/indices`, index creation and deletion, and `_cluster/health` are the
same on both flavors.

## Required permissions

The configured user needs:

- cluster: `cluster:monitor/health`, index template management (OpenSearch `cluster_manage_index_templates`;
  Elasticsearch `manage_index_templates`).
- indices on `<prefix>-*` (with the default template: `tenant_*`): create, delete, list
  (`indices:monitor/*` for `_cat/indices`) and alias management (OpenSearch `indices_all` or
  `create_index`, `delete`, `indices:admin/aliases`, `indices_monitor`; Elasticsearch `manage`,
  `delete_index`, `monitor`).
- with `security.enabled`: OpenSearch REST API access to the Security plugin (a role listed in
  `plugins.security.restapi.roles_enabled`, such as `all_access` or
  `security_rest_api_access`). On Elasticsearch, `manage_security`.

## Tests

Unit tests use an in-memory fake of both REST flavors. Integration tests run against a real
cluster when `TENARIUM_TEST_OPENSEARCH_URL` is set:

```sh
docker run -d -p 9200:9200 -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true \
  -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m" opensearchproject/opensearch:2
TENARIUM_TEST_OPENSEARCH_URL=http://localhost:9200 go test ./plugins/opensearchtenant/

# with the Security plugin (roles and users):
docker run -d -p 9200:9200 -e discovery.type=single-node \
  -e OPENSEARCH_INITIAL_ADMIN_PASSWORD='<strong password>' opensearchproject/opensearch:2
TENARIUM_TEST_OPENSEARCH_URL=https://localhost:9200 TENARIUM_TEST_OPENSEARCH_INSECURE=1 \
TENARIUM_TEST_OPENSEARCH_USER=admin TENARIUM_TEST_OPENSEARCH_PASSWORD='<strong password>' \
TENARIUM_TEST_OPENSEARCH_SECURITY=1 go test ./plugins/opensearchtenant/
```

`TENARIUM_TEST_OPENSEARCH_FLAVOR=elasticsearch` runs the same tests against Elasticsearch.
