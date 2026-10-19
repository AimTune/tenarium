# Terraform provider for Tenarium

`terraform-provider-tenarium` manages a [Tenarium](../README.md) control plane with
Terraform: plans, tenants and their members, roles, groups, custom domains,
webhooks, SSO connections and API keys, plus feature rollouts and tenant
templates.

It is a separate Go module (`github.com/AimTune/tenarium/terraform-provider`)
built on the [Terraform Plugin Framework](https://developer.hashicorp.com/terraform/plugin/framework).
It talks to the REST API through the official Go client (`pkg/client`), so the
`replace github.com/AimTune/tenarium => ../` directive in `go.mod` keeps
the two in lockstep.

```hcl
terraform {
  required_providers {
    tenarium = { source = "aimtune/tenarium" }
  }
}

provider "tenarium" {} # TENARIUM_URL and TENARIUM_API_KEY

resource "tenarium_plan" "pro" {
  id       = "pro"
  name     = "Pro"
  features = { sso = true }
  limits   = { members = 50 }
}

resource "tenarium_tenant" "acme" {
  slug     = "acme"
  name     = "Acme Inc."
  plan     = tenarium_plan.pro.id
  settings = jsonencode({ theme = { color = "#0050ff" } })

  deletion_protection = true
}

resource "tenarium_member" "alice" {
  tenant_id = tenarium_tenant.acme.id
  email     = "alice@acme.example"
  role      = "admin"
}
```

## Provider configuration

| Argument   | Environment variable | Description |
|------------|----------------------|-------------|
| `endpoint` | `TENARIUM_URL`       | Base URL of the API |
| `api_key`  | `TENARIUM_API_KEY`   | Bearer API key (sensitive) |

The key needs the permissions of what it manages. For example, `force_delete`
needs `tenants:purge`, and plan, feature and limit changes need `plans:write`.
A static platform key from `server.api_keys` can do everything.

## Resources and data sources

| Type | Import ID |
|------|-----------|
| `tenarium_plan` | `<plan_id>` |
| `tenarium_tenant` | `<tenant_id>` or `<slug>` |
| `tenarium_member` | `<tenant>/<member_id>` |
| `tenarium_tenant_domain` | `<tenant>/<hostname>` |
| `tenarium_tenant_webhook` | `<tenant>/<webhook_id>` |
| `tenarium_tenant_role` | `<tenant>/<role_name>` |
| `tenarium_tenant_group` | `<tenant>/<group_id>` |
| `tenarium_tenant_sso` | `<tenant>` |
| `tenarium_api_key` | `<tenant>/<key_id>`, or `<key_id>` for platform keys |
| `tenarium_rollout` | `<feature>` |
| `tenarium_tenant_template` | `<template_id>` |
| data `tenarium_tenant` | by `id` or `slug` |
| data `tenarium_plan` | by `id` |
| data `tenarium_entitlements` | effective features and limits of a tenant |
| data `tenarium_plan_revisions` | recorded revisions of a plan, newest first |
| data `tenarium_tenant_health` | health score, grade and factors of a tenant |

Full reference: [`docs/`](docs/index.md). Examples: [`examples/`](examples/).

### Behaviour notes

- **Optimistic locking.** Updates to tenants and plans send the stored
  `version` as `If-Match`. If something else changed the object after
  Terraform last read it, the update fails with HTTP 412 and Terraform asks
  you to refresh, so it never silently overwrites the other change. A normal
  `plan`/`apply` refreshes first, so this only happens with concurrent writers.
- **Tenant settings** are a JSON string (`jsonencode(...)`). Whitespace and
  key order differences are ignored, both on read and in plans. Updates send
  an RFC 7386 merge patch computed from the previous settings, so keys that
  you remove are deleted on the server.
- **Maps** (`labels`, `features`, `limits`) replace the whole map on update.
- **Regions.** `region` is set at creation. Changing it later moves the
  tenant (`POST /v1/tenants/{id}/move`, needs `tenants:move`) instead of
  replacing it; with `move_reprovision = true` the provisioners run again in
  the new region (the tenant is `provisioning` until they finish). When
  `region` is omitted, Terraform keeps whatever region the tenant has.
- **Plan revisions and grandfathering.** `tenarium_plan.grandfather_on_update =
  true` pins the tenants on a plan to its previous revision whenever the
  plan is updated (changing only that flag calls no API). The tenant's
  `plan_revision` reports the pin; set it to pin explicitly, or to `0` to
  follow the current plan again. Changing `plan` resets the pin on the server.
- **Add-ons, branding, billing anchor.** `add_ons` and `branding` replace the
  whole value; removing `branding` (or setting `add_ons = []`) clears it.
  `billing_anchor` is an RFC 3339 timestamp; spellings of the same instant
  are equal. Set it to `""` to remove the anchor; omitting it keeps the
  current one (for example one set by a billing plugin).
- **Templates.** `template` is only used when the tenant is created; changing
  or removing it later does nothing (no replacement, and it is empty after an
  import). Attributes you configure win over the template. Of `add_ons`,
  `labels`, `settings`, `features`, `limits` and `branding`, the ones you
  leave unset at creation keep the template's values: the provider remembers
  them in private state and leaves them alone until you configure them. `plan`
  and `region` from a template are kept like any server-chosen value.
- **Replacement.** Changing `slug` or `parent_id` of a tenant, the
  `tenant_id` of any tenant-scoped resource, a role `name`, a domain
  `hostname`, a rollout `feature`, a template `id`, or any argument of an
  API key creates a new object.
- **Deletion.** `deletion_protection = true` makes destroy and replace fail.
  `force_delete = true` skips the server's deletion grace period
  (`DELETE ...?force=true`). Without it, a server with
  `tenants.deletion_grace_period` only schedules the deletion.
- **Secrets.** `tenarium_tenant_webhook.secret` and `tenarium_api_key.key`
  come back from the API only once, when the object is created. They are
  stored in state as sensitive values and are empty after an import. SSO
  `client_secret` and `saml_metadata` are never returned, so the provider
  cannot detect changes made to them outside Terraform.
- **Domain verification.** `tenarium_tenant_domain` exposes
  `txt_record_name` and `txt_record_value` to publish, for example with a
  DNS provider. With `verify = true`, apply asks the server to check the
  record. If the record is not visible yet, apply succeeds with a warning,
  `verified` stays `false`, and the next plan retries.
- **Groups.** `members` is optional. When it is unset, the provider leaves
  group membership alone (for example when SCIM manages it).
- **Roles, SSO, rollouts and templates** use `PUT`. To avoid silently taking
  over an existing object, `create` refuses when it already exists.
  Import it instead.

## Development

```sh
go build ./...                 # build
go test ./...                  # unit tests (schemas, conversions, merge patches)
TF_ACC=1 go test ./... -v      # acceptance tests
```

The acceptance tests need no external services. `TestMain` starts a real
Tenarium server in-process (`pkg/server`, memory store) on a random port,
with a fake DNS resolver for domain verification. The tests then run
Terraform against it with `resource.Test`. They need a Terraform CLI. They
use `terraform` from `PATH` or the binary at `TF_ACC_TERRAFORM_PATH`. If
neither exists, `terraform-plugin-testing` downloads one (pin it with
`TF_ACC_TERRAFORM_VERSION=1.9.8`).

### Using a local build

```sh
go install .
cat >> ~/.terraformrc <<'EOF'
provider_installation {
  dev_overrides { "aimtune/tenarium" = "/path/to/go/bin" }
  direct {}
}
EOF
```

### Documentation

`docs/` is in the [tfplugindocs](https://github.com/hashicorp/terraform-plugin-docs)
format and was generated from the schemas and `examples/`. Regenerate it
after changing a schema or an example:

```sh
go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.22.0 generate --provider-name tenarium
```

tfplugindocs needs a Terraform CLI. It uses `terraform` from `PATH` and
otherwise downloads one, which fails with tfplugindocs v0.22.0 because the
signing key it checks has expired. Put a Terraform binary (for example 1.9.8)
on `PATH` first.
