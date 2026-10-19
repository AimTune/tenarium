# Tenarium Kubernetes operator

The operator manages Tenarium tenants, plans, feature rollouts and tenant
templates declaratively from Kubernetes. You write `Tenant`, `Plan`,
`Rollout` and `TenantTemplate` resources, and the operator creates, updates
and deletes the matching objects through the Tenarium REST API. It uses the
official Go client (`pkg/client`).

It is a separate Go module (`github.com/AimTune/tenarium/operator`). It
builds against the Tenarium module in the parent directory through a
`replace` directive.

## Resources

All resources are namespaced and belong to the API group `tenarium.io/v1alpha1`.

| Kind | Short name | Purpose |
|---|---|---|
| `TenariumConnection` | `tconn` | URL of a Tenarium server and a Secret that holds its API key |
| `Plan` | | A plan: ID, name, description, features, limits |
| `Tenant` | `tnt` | A tenant: slug, name, plan, add-ons, plan revision, region, billing anchor, branding, template, parent, labels, settings, feature and limit overrides, scheduled actions |
| `Rollout` | | A feature rollout: feature, percentage, cohort filters (plans, regions, labels), include/exclude lists, enabled |
| `TenantTemplate` | `ttpl` | A tenant template: presets (plan, add-ons, region, labels, settings, features, limits, branding, custom roles) for new tenants |

`kubectl get tenarium` lists all five kinds.

### Tenant

```yaml
apiVersion: tenarium.io/v1alpha1
kind: Tenant
metadata:
  name: acme
spec:
  slug: acme                 # required, immutable
  name: Acme Inc.            # defaults to the slug
  plan: pro                  # plan ID; omitted = not managed
  addOns: [extra-seats]      # plan IDs stacked on the plan; [] removes them; omitted = not managed
  planRevision: 3            # pin to a plan revision; 0 unpins; omitted = not managed
  region: eu                 # set on create; a later change moves the tenant; omitted = not managed
  moveReprovision: false     # true: a move re-runs the provisioners in the new region
  billingAnchor: "2026-01-01T00:00:00Z"   # start of monthly billing cycles; omitted = not managed
  branding:                  # see "Branding" below
    displayName: Acme
    logoUrl: https://acme.example.com/logo.png    # https URLs: logoUrl, iconUrl, supportUrl
    primaryColor: "#1a2b3c"  # hex colors: primaryColor, accentColor
    supportEmail: support@acme.example.com
  template: startup          # create-only: presets from a tenant template
  parent:                    # immutable; exactly one of:
    name: some-tenant        #   a Tenant resource in this namespace (waits until Ready)
    # slug: some-org         #   or an existing Tenarium tenant
  labels: {region: eu}       # omitted = not managed
  settings:                  # any JSON object; omitted = not managed
    theme: dark
  features: {sso: true}      # overrides the plan; omitted = not managed
  limits: {seats: 75}        # overrides the plan; omitted = not managed
  schedule:                  # optional, see "Scheduled actions"
    - action: suspend        # suspend | resume | set_plan | delete
      after: 14d             # or  at: "2027-01-01T00:00:00Z"
      reason: trial ended
  deletionPolicy: Delete     # Delete (default) | Orphan
  connectionRef:             # optional; default: the operator's flags
    name: tenarium
```

The status reports the following:

| Field | Meaning |
|---|---|
| `id`, `parentID` | Tenarium IDs |
| `phase`, `statusReason` | The tenant's Tenarium status (`provisioning`, `active`, `suspended`, `failed`, `deleting`, `deleted`) |
| `version` | Last remote version seen (used for `If-Match`) |
| `adopted` | The tenant existed before and was adopted |
| `entitlements` | Effective plan, enabled features and limits (including add-ons and rollouts) |
| `planRevision` | Plan revision the tenant is pinned to (0 = current) |
| `region` | The tenant's region in Tenarium |
| `maintenance` | The maintenance window, if any: `active`, `message`, `until`, `moveTo` |
| `health` | Health `score` (0-100) and `grade`, refreshed on every sync |
| `brandingManaged` | The operator applied `spec.branding` (removing it clears the branding) |
| `scheduledActions` | Actions scheduled from `spec.schedule`, with their state |
| `observedGeneration`, `lastSyncTime` | Reconcile bookkeeping |
| `conditions` | `Ready` and `Synced` (see below) |

```
$ kubectl get tenants
NAME            SLUG            PLAN   PHASE    READY   SYNCED   AGE
acme            acme            pro    active   True    True     2m
acme-research   acme-research          active   True    True     2m
```

`kubectl get tenants -o wide` adds the ID, region and health grade.

Field notes:

- **Region.** `region` is sent when the tenant is created. If you change it
  later, the operator calls `POST /v1/tenants/{id}/move` (it never recreates
  the tenant) and emits a `Moved` event. The move needs the platform-only
  `tenants:move` permission. With `moveReprovision: true` the provisioners
  run again in the new region inside a maintenance window. Tenarium then
  reports the tenant as `provisioning`, and such a move waits until the
  tenant is `active`. Tenarium only records the placement: moving the data
  is up to you or your plugins (see `docs/plans.md`).
- **Add-ons, billing anchor and plan revision** need `plans:write`.
- **Branding.** With `branding` set, the tenant's branding matches it; an
  empty `branding: {}` clears it. If `branding` is later removed from a spec
  that set it, the operator clears the branding in Tenarium (it sends an
  empty branding). If a spec never set `branding` (for example on an adopted
  tenant), the tenant's branding is left alone.
- **Template.** `template` names a tenant template (see `TenantTemplate`)
  and is used only when the operator creates the tenant: the spec's own
  values win over the template's. Changing or removing `template` after the
  tenant exists has no effect. Tenants keep no link to their template.
- **Health and maintenance** are read on every sync, so they are as fresh as
  `--resync-period`. An error reading the health score keeps the previous
  value and does not fail the sync.

### Plan

```yaml
apiVersion: tenarium.io/v1alpha1
kind: Plan
metadata:
  name: pro
spec:
  id: pro               # defaults to metadata.name; immutable
  name: Pro             # defaults to the ID
  description: For growing teams
  features: {sso: true}
  limits: {seats: 50}
  deletionPolicy: Delete
```

### Rollout

A rollout turns a feature on gradually, independently of plans. A tenant
gets the feature when the rollout is enabled, the tenant is not in
`exclude`, and it is either in `include` or matches every cohort filter that
is set and falls within `percentage`.

```yaml
apiVersion: tenarium.io/v1alpha1
kind: Rollout
metadata:
  name: new-editor
spec:
  feature: new-editor   # defaults to metadata.name; immutable
  enabled: true         # false is the kill switch
  percentage: 10        # 0-100, stable per tenant
  plans: [pro]          # cohort filters, all optional
  regions: [eu]
  labels: {beta: "yes"}
  include: []           # tenant IDs
  exclude: []
  deletionPolicy: Delete
```

Set `feature` for feature names Kubernetes does not allow as object names,
such as `audit_export`. The whole rollout is replaced (`PUT`) when it differs
from the spec. Rollouts are platform-only: the API key needs `plans:write`.

### TenantTemplate

```yaml
apiVersion: tenarium.io/v1alpha1
kind: TenantTemplate
metadata:
  name: startup
spec:
  id: startup           # defaults to metadata.name; immutable
  name: Startup         # defaults to the ID
  description: Pro plan in the EU
  plan: pro
  addOns: [extra-seats]
  region: eu
  labels: {segment: startup}
  settings: {theme: light}
  features: {beta: true}
  limits: {seats: 20}
  branding: {primaryColor: "#1a2b3c"}
  roles:
    - name: billing-admin
      description: Reads usage
      actions: ["usage:read", "tenants:read"]
  deletionPolicy: Delete
```

A `Tenant` with `spec.template: startup` starts from these values. The whole
template is replaced (`PUT`) when it differs from the spec. Changing a
template does not change tenants created from it. Templates are
platform-only: the API key needs `plans:write`.

### TenariumConnection

```yaml
apiVersion: v1
kind: Secret
metadata: {name: tenarium-credentials}
stringData: {api-key: "..."}
---
apiVersion: tenarium.io/v1alpha1
kind: TenariumConnection
metadata: {name: tenarium}
spec:
  url: https://tenarium.example.com
  apiKeySecretRef: {name: tenarium-credentials, key: api-key}
```

The operator calls `GET /v1/me` with these credentials. It sets `Ready` and
records the principal in `status.principal`. Tenants, Plans, Rollouts and
TenantTemplates reference a
connection in the same namespace with `spec.connectionRef`. Resources
without a reference use the default connection from the operator's flags.
If there is no default connection, they fail with `Synced=False`, reason
`ConnectionError`.

The API key needs the `tenants:*` and `plans:*` permissions. Changing a
tenant's plan, add-ons, plan revision, billing anchor, features or limits,
and managing rollouts and templates, requires `plans:write`. Moving a tenant
to another region requires `tenants:move`.

## Reconcile behavior

- **Create.** If the tenant does not exist (looked up by slug), the operator
  creates it with an `Idempotency-Key` derived from the resource's UID and
  generation. A retried create, for example after a timeout or a restart,
  is replayed by the server instead of creating a duplicate. The operator
  marks each tenant it creates with the label
  `tenarium.io/k8s-owner=<resource UID>`. If the status write is lost after
  a create, the next reconcile finds the tenant by this label and claims it
  again.
- **Adopt.** An existing tenant or plan is never touched unless the resource
  has the annotation `tenarium.io/adopt: "true"`. Without the annotation the
  resource reports `Synced=False`, reason `AlreadyExists`, and emits a
  warning event. A tenant that another `Tenant` resource owns (a different
  owner label) is never adopted (reason `OwnedByOtherResource`). For plans,
  the operator repeats the original create with the same Idempotency-Key. If
  the server replays that create, the plan was created by this resource and
  the operator claims it. Rollouts and templates are written with `PUT`,
  which has no idempotency keys: if the status write is lost after the
  operator created one, the next reconcile reports `AlreadyExists`, and the
  adopt annotation resolves it.
- **Update.** The operator compares the spec with the remote object and
  sends only the fields that differ, as one `PATCH` with
  `If-Match: <version>`. If the server answers 412 (someone else changed the
  object in the meantime), the operator re-reads the object and retries.
  `settings` is sent as a JSON merge patch, so keys missing from the spec are
  removed. Optional fields that are not set in the spec (plan, add-ons,
  plan revision, region, billing anchor, labels, settings, features, limits)
  are left alone. The plan revision and the region are set with their own
  calls (`PUT /plan-revision`, `POST /move`) after the `PATCH`.
- **Drift.** Every object is compared with Tenarium again after
  `--resync-period` (default 5m). Changes made outside Kubernetes are
  reverted, and the operator emits a `DriftRepaired` event. If a tenant or
  plan was deleted outside Kubernetes, the operator recreates it with a new
  idempotency key and emits a `RemoteMissing` event.
- **Parents.** A child Tenant that references its parent by `name` waits
  (`Ready=False`, reason `WaitingForParent`) until the parent is Ready. When
  the parent becomes Ready, the operator reconciles the child right away. A
  parent cannot be deleted while it has live children, because Tenarium
  answers 409. The operator then reports `DeleteBlocked` and retries, so
  deleting a whole tree in one step works: children go first.
- **Scheduled actions.** Each `spec.schedule` entry is posted once to
  `/v1/tenants/{id}/schedule` and tracked in `status.scheduledActions`,
  keyed by a hash of the entry. If you remove an entry that is still
  pending, the operator cancels the action. If you change an entry, the old
  action is canceled and a new one is scheduled. `after` is relative to the
  moment the action is scheduled.
- **Deletion.** A finalizer (`tenarium.io/finalizer`) keeps the resource
  until the remote side is handled. With `deletionPolicy: Delete`, the
  operator deletes the tenant or plan. A plan that tenants still use is
  blocked with 409, and the operator retries until the plan is free. With
  `Orphan`, the remote object stays in Tenarium, and the operator removes
  the tenant's owner label so another resource can adopt it later. If the
  server has a deletion grace period, a deleted tenant is suspended pending
  deletion, and the finalizer is released once the API accepts the delete.
- **Errors.** API and connection errors set `Synced=False` with reason
  `APIError` or `ConnectionError`, emit a `SyncFailed` warning event, and
  are retried with per-object exponential backoff from 1s up to
  `--max-backoff` (default 5m). A transient error does not flip `Ready` to
  `False` on an object that already exists. Requests that are safe to
  repeat are also retried inside one reconcile (`--api-retries`).

### Conditions

| Type | True when | Typical False reasons |
|---|---|---|
| `Ready` | Tenant: the remote tenant is `active`. Plan, Rollout, TenantTemplate: the object exists. Connection: the credentials work | `WaitingForParent`, `Provisioning`, `ProvisioningFailed`, `Suspended`, `Deleting`, `AlreadyExists`, `ConnectionError` |
| `Synced` | The last reconcile brought the remote object in line with the spec | `APIError`, `ConnectionError`, `InvalidSpec`, `AlreadyExists`, `OwnedByOtherResource`, `ParentMismatch`, `VersionConflict`, `DeleteBlocked`, `WaitingForParent` |

### Events

`Created`, `Adopted`, `Updated`, `DriftRepaired`, `Moved`, `RemoteMissing`,
`Scheduled`, `Unscheduled`, `Deleted`, `Orphaned`, plus the warnings
`SyncFailed`, `AlreadyExists`, `DeleteBlocked`, `ParentMismatch` and
`ConnectionFailed`. Events use the `events.k8s.io/v1` API.

## Install

The image is built from the repository root, because the operator module
uses the parent module:

```sh
docker build -f operator/Dockerfile -t ghcr.io/you/tenarium-operator:v0.1.0 .
docker push ghcr.io/you/tenarium-operator:v0.1.0
```

Install the CRDs, the RBAC rules and the manager (namespace
`tenarium-system`):

```sh
cd operator
# Point the image at your registry.
(cd config/manager && kustomize edit set image tenarium-operator=ghcr.io/you/tenarium-operator:v0.1.0)

# Default connection used by resources without spec.connectionRef
# (see the --tenarium-* args in config/manager/manager.yaml).
kubectl create namespace tenarium-system
kubectl -n tenarium-system create secret generic tenarium-operator --from-literal=api-key="$TENARIUM_API_KEY"

kubectl apply -k config/default
```

To install only the CRDs, run `kubectl apply -k config/crd`.
`config/rbac/editor_role.yaml` aggregates edit and view rights for the new
kinds into the built-in `admin`, `edit` and `view` roles.

Then apply the examples:

```sh
kubectl apply -k config/samples     # Secret + TenariumConnection, two Plans, a Rollout, a TenantTemplate, four Tenants
kubectl get tenarium
kubectl describe tenant acme        # conditions and events
```

### Manager flags

| Flag | Default | |
|---|---|---|
| `--tenarium-url` | `$TENARIUM_URL` | Default server for resources without `connectionRef` |
| `--tenarium-api-key-secret` | `$TENARIUM_API_KEY_SECRET` | `namespace/name` of the Secret that holds the default API key. Without it, `$TENARIUM_API_KEY` is used |
| `--tenarium-api-key-secret-key` | `api-key` | Key in that Secret |
| `--resync-period` | `5m` | Drift detection interval |
| `--max-backoff` | `5m` | Maximum retry delay after errors |
| `--max-concurrent-reconciles` | `2` | Per controller |
| `--api-retries` | `2` | Retries of safe API requests within one reconcile |
| `--watch-namespaces` | all | Comma-separated namespaces to watch |
| `--leader-elect` | `false` | Enable for more than one replica |
| `--metrics-bind-address`, `--health-probe-bind-address` | `:8080`, `:8081` | |

The operator reads Secrets with direct GETs instead of watching them, so its
ClusterRole needs only `get` on Secrets. A rotated API key takes effect at
the next reconcile.

### Run locally

```sh
cd operator
kubectl apply -k config/crd
TENARIUM_URL=http://localhost:8080 TENARIUM_API_KEY=dev-key go run ./cmd
```

## Development

```sh
cd operator
make generate manifests   # deepcopy, CRDs (config/crd/bases), ClusterRole (config/rbac/role.yaml)
make test                 # unit tests
make test-envtest         # + envtest suite (Linux/macOS)
make test-envtest-docker  # envtest suite in a Linux container, e.g. on Windows
```

`make generate` and `make manifests` install `controller-gen` v0.22.0 into
`operator/bin`.

The tests run against a real, in-process Tenarium server
(`pkg/server` with the memory store):

- `go test ./...` reconciles with controller-runtime's fake client. The
  tests cover create, update, drift repair, recreation after remote
  deletion, adoption, ownership conflicts, crash recovery through the owner
  label and idempotency keys, both deletion policies, parent/child ordering
  and blocked deletes, scheduled actions, connection errors, API errors,
  TenariumConnection checks, region moves, add-ons, plan revision pins,
  billing anchors, branding (set, clear, unmanaged), maintenance and health
  status, tenants created from templates, and the Rollout and
  TenantTemplate controllers.
- `go test -tags envtest ./...` (with `KUBEBUILDER_ASSETS` set) also starts a
  real kube-apiserver and etcd. It runs the full manager, with its watches,
  predicates and field indexes, against the generated CRDs. It checks the
  CEL validation rules and that every object in `config/samples` is
  accepted. The envtest package of controller-runtime v0.25 does not compile
  on Windows, which is why this suite sits behind a build tag. On Windows,
  use `make test-envtest-docker` or WSL.

## Limitations

- `slug`, `parent`, the plan `id`, the rollout `feature` and the template
  `id` are immutable (enforced by CEL rules), as in Tenarium.
- Members, API keys, domains, webhooks and maintenance windows are not
  managed yet (maintenance is reported in the status only).
- Removing `billingAnchor` from a spec that set it removes the anchor in
  Tenarium (`status.billingAnchorManaged`); an anchor set elsewhere, e.g. by a
  billing plugin, is never touched.
- A resource cannot be finalized while its connection is unusable, for
  example when the TenariumConnection or its Secret was deleted first.
  Delete Tenants and Plans before their connection, or remove the finalizer
  by hand.
- There is no Helm chart yet. Kustomize manifests are in `config/`.
