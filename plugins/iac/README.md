# iac-tenant

Provisions per-tenant infrastructure with an infrastructure-as-code engine
(package `plugins/iac`, plugin ID `iac-tenant`):

| Engine | What it does per tenant |
|---|---|
| `terraform` / `opentofu` | Runs the CLI on a module in a working directory `<state_dir>/<tenant-id>`: `init`, `apply -auto-approve -input=false`, `output -json`. Deprovision runs `destroy -auto-approve`. |
| `pulumi` | Runs the CLI on a project with one stack per tenant: `stack select --create`, `config set`, `up --yes --skip-preview`, `stack output --json`. Deprovision runs `destroy --yes` and `stack rm`. |
| `crossplane` | Creates a Claim (namespaced) or Composite resource (cluster-scoped) from a YAML template and waits for its `Ready` condition. Deprovision deletes it and waits until it is gone. |

## Configuration

Common settings:

```yaml
- plugin: iac-tenant
  config:
    engine: terraform                 # terraform | opentofu | pulumi | crossplane (required)
    state_dir: /var/lib/tenarium/iac  # working directories (terraform, opentofu, pulumi; required for them)
    timeout: 30m                      # per provisioning/deprovisioning run (default 30m)
    on_deprovision: destroy           # destroy (default) | keep
    reapply_on: [tenant.updated, tenant.plan_changed]   # default; [] disables re-applying
    max_parallel: 4                   # concurrent runs across tenants (default 4)
    log_limit: 8192                   # trailing bytes of CLI output kept in errors (default 8 KiB)
    env_passthrough: [AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "ARM_*"]
    env: {AWS_REGION: eu-central-1}
    vars:                             # static variables; strings are templates
      region: '{{index .Labels "region"}}'
      instance_count: 2
```

### terraform / opentofu

```yaml
    engine: terraform                 # or opentofu (default binary "tofu")
    terraform:
      binary: /usr/local/bin/terraform
      module_dir: /srv/infra/tenant   # a local module, or:
      # module_source: "git::https://github.com/acme/infra.git//tenant?ref=v1.4.0"
      backend_config:                 # -backend-config=key=value; templates
        bucket: acme-tf-state
        key: "tenants/{{.ID}}.tfstate"
      plugin_cache_dir: /var/cache/terraform-plugins
```

- Exactly one of `module_dir` (copied into the working directory before each
  run) or `module_source` (any module source address, fetched with
  `init -from-module` into a temporary directory and copied) is required.
  Each run replaces the module files in the working directory, so files
  removed from the module disappear; `.terraform`, the lock file and local
  state are kept.
- Without `backend_config`, the module's backend applies, normally local
  state in `<state_dir>/<tenant-id>/terraform.tfstate`. That is fine for
  development; in production use a remote backend. The module must declare
  the backend (e.g. `terraform { backend "s3" {} }`). A `backend_config` that
  renders the same for every tenant is rejected at startup, since tenants
  would share one state.
- Variables are written to `<state_dir>/<tenant-id>/.tenarium/vars.tfvars.json`
  and passed with `-var-file`. Terraform only warns about variables the
  module does not declare, so declare the ones you use.
- Deprovision with local state and no state file does nothing. With a
  remote backend it always runs `init` and `destroy` (the state may exist
  even if the working directory does not). The working directory is removed
  after a successful destroy.

### pulumi

```yaml
    engine: pulumi
    pulumi:
      binary: pulumi
      project_dir: /srv/infra/tenant-program   # contains Pulumi.yaml (required)
      backend_url: file:///var/lib/pulumi       # PULUMI_BACKEND_URL; s3://..., https://api.pulumi.com
      stack_template: "tenant-{{.ID}}"          # default
      secrets_provider: passphrase              # used when a stack is created
      keep_stack: false                         # keep the empty stack after destroy
    env: {PULUMI_CONFIG_PASSPHRASE: "${PULUMI_PASSPHRASE}"}
```

Every command names the stack (`--stack`) and the stack's configuration file
lives in the tenant's directory (`--config-file <state_dir>/<tenant-id>/Pulumi.<stack>.yaml`),
so runs for different tenants do not share the workspace's current stack and
the project directory is not modified. Non-string variables are set as JSON
strings. Variables removed from the configuration are removed from the stack
on the next run. Deprovision first lists the stacks (`stack ls --json`) and
does nothing if the tenant's stack does not exist.

### crossplane

```yaml
    engine: crossplane
    crossplane:
      kubeconfig: ""                  # empty: in-cluster, else $KUBECONFIG / ~/.kube/config
      context: ""
      resource: postgresinstances     # plural; empty: discovered from the API server
      wait: true                      # wait for Ready / for deletion (default true)
      poll_interval: 5s
      manifest: |                     # or manifest_file: /etc/tenarium/claim.yaml
        apiVersion: platform.acme.io/v1alpha1
        kind: PostgresInstance
        metadata:
          name: tenant-{{.Slug}}
          namespace: tenants          # omit for a cluster-scoped Composite
        spec:
          storageGB: {{index .Entitlements.Limits "storage_gb"}}
          writeConnectionSecretToRef:
            name: tenant-{{.Slug}}-db
```

- The resource is labeled `app.kubernetes.io/managed-by: tenarium`,
  `tenarium.io/tenant-id` and `tenarium.io/tenant-slug`. An existing object
  without the tenant's ID label is never adopted (provisioning fails) and
  never deleted.
- Re-applying replaces the spec from the template and merges labels and
  annotations; the status and other controllers' labels are kept.
- A manifest whose name and namespace do not depend on the tenant is rejected
  at startup. Use immutable fields (`ID`, `Slug`) for names.
- RBAC: `get, create, update, delete` on the claim/composite resource, `get`
  on `secrets` in the connection secret's namespace (key names only are read
  out), and discovery access when `resource` is empty.

## Inputs

Templates (`vars`, `backend_config`, `stack_template`, the Crossplane manifest)
run against the tenant with its fields promoted (`{{.ID}}`, `{{.Slug}}`,
`{{.Name}}`, `{{.Plan}}`, `{{index .Labels "x"}}`, `{{.Settings}}`) and
`{{.Entitlements.Features}}` / `{{.Entitlements.Limits}}`. Functions: `json`,
`dns1123`, `lower`, `upper`. A missing field is an error.

Every engine receives these variables (names starting with `tenant_` are
reserved):

| Variable | Value |
|---|---|
| `tenant_id`, `tenant_slug`, `tenant_name`, `tenant_plan`, `tenant_parent_id` | strings |
| `tenant_labels` | map of strings (a JSON string for Pulumi) |
| `tenant_settings_json` | settings as a JSON string |
| `tenant_entitlements_json` | effective features and limits as a JSON string |

## Outputs

`GET /v1/plugins/{instance}/tenants/{tenant}/outputs` (requires
`tenants:read` on the tenant; other callers get 404):

```json
{
  "tenant_id": "0192...",
  "engine": "terraform",
  "outputs": {
    "endpoint": {"value": "db.acme.internal"},
    "password": {"sensitive": true, "redacted": true}
  },
  "updated_at": "2026-01-02T03:04:05Z"
}
```

Terraform and Pulumi outputs are cached in the tenant's directory after each
successful apply; sensitive outputs (Terraform `sensitive = true`, Pulumi
secrets) are redacted before they are stored. Crossplane outputs are read
live: the fields of `.status` except `conditions`, `ready`, and the
`connection_secret` name with its key names (never values). A tenant that has
not been provisioned returns 404.

## Behavior

- **Serialization.** Runs for one tenant are serialized; at most
  `max_parallel` run at once. Each run is bounded by `timeout`; on timeout
  the CLI is interrupted (killed on Windows), then killed after 30 seconds.
- **Errors.** A failed command fails provisioning with the last `log_limit`
  bytes of its output, so the tenant's status reason shows the actual error.
- **Re-apply.** `reapply_on` events re-apply active and suspended tenants
  (others belong to the provisioner). Handlers act on the tenant's current
  state and skip versions already applied, so replays are cheap. A new
  subscription starts at the end of the event log. Plan changes to a plan
  (`plan.updated`) do not trigger a re-apply; retry provisioning instead.
- `/readyz` checks that the binary can be found (CLI engines) or that the API
  server is reachable (crossplane).

## Security

- **The configuration is trusted code.** Terraform modules, providers and
  Pulumi programs run with the permissions of the Tenarium process and can
  read its files. Only point the plugin at modules and programs you control,
  pin versions (`?ref=` for git sources, provider lock files), and run
  Tenarium with a dedicated, least-privileged account.
- **Environment.** Commands get only a minimal environment (`PATH`, `HOME`,
  temporary directories, proxies, certificate paths and the Windows system
  variables), the variables named in `env_passthrough`, and `env`. Pass cloud
  credentials through `env_passthrough`, not through `vars`.
- **Arguments are visible.** `backend_config` values and Pulumi config
  values appear on the command line (visible in the process list). Keep
  secrets out of them; backends read credentials from the environment.
- **State.** Local state and Pulumi file backends contain secrets in plain
  text or encrypted with the passphrase: protect `state_dir` (created `0700`)
  and the backend.
- Tenant data (slug, labels, settings) flows into variables; validate it in
  the module if it is used in names or commands.
