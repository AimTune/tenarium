# gcs-tenant

Gives every tenant its own Google Cloud Storage bucket, or its own object prefix in a shared
bucket. The plugin calls the GCS JSON API directly over `net/http`, with
`golang.org/x/oauth2/google` credentials (package `plugins/gcstenant`).

```yaml
- plugin: gcs-tenant
  config:
    project: my-gcp-project                    # required in bucket mode
    # endpoint: https://storage.googleapis.com # default; e.g. http://localhost:4443 for an emulator
    # credentials_file: /secrets/sa.json       # or credentials_json: ${GCS_CREDENTIALS}
    # anonymous: false                         # true = no auth (emulators only)
    mode: bucket                               # bucket (default) | prefix
    # bucket: shared-tenant-data               # the existing shared bucket; prefix mode only
    name_template: "acme-prod-{{.Slug}}"       # default "tenant-{{.Slug}}"
    ownership: labels                          # labels (default) | object; bucket mode only
    location: EU                               # used at creation
    storage_class: STANDARD                    # STANDARD | NEARLINE | COLDLINE | ARCHIVE
    versioning: true
    lifecycle_expire_days: 0                   # 0 = no managed rule
    uniform_bucket_level_access: true          # default true; false = leave as is
    public_access_prevention: enforced         # enforced | inherited | "" (unmanaged)
    labels:                                    # extra bucket labels, templates over the tenant
      tenant-slug: "{{.Slug}}"
    quota_from_limit: storage_gb               # limit recorded as tenarium-quota-gb
    on_deprovision: delete                     # delete (default) | keep | retain
```

All bucket options (`ownership`, `location`, `storage_class`, `versioning`,
`lifecycle_expire_days`, `uniform_bucket_level_access`, `public_access_prevention`, `labels`) are
rejected in prefix mode, because they would apply to every tenant in the shared bucket.

## Behavior

- **Authentication.** `credentials_file` or `credentials_json` (service account key, external
  account / workload identity federation, authorized user, impersonated service account). If
  neither is set, Application Default Credentials are used. The scope is
  `devstorage.full_control`. `anonymous: true` sends unauthenticated requests, for emulators.
- **Names.** Rendered names are sanitized to bucket names: lowercase letters, digits and
  hyphens, 3 to 63 characters. `google` becomes `ggl` and a leading `goog` gets a `t-` prefix
  (GCS rejects both). Names that are too short or too long get a hash of the tenant ID. A
  template that renders the same name for two tenants is rejected at startup. Use only `ID` and
  `Slug`, because the name is computed again on deprovision. **Bucket names are global across
  all of GCS**, so use an organization-specific prefix. If a name is already taken by another
  project, provisioning fails with a clear error (HTTP 403 on the bucket). In prefix mode the
  tenant's prefix is `<name>/`.
- **Ownership.** With `ownership: labels`, a bucket has the label
  `tenarium-tenant-id=<id>`. UUIDs are used as they are; other IDs are encoded as `sha256-<hex>`
  so they fit label rules. With `ownership: object`, and always in prefix mode, the marker is an
  object `.tenarium-owner` (at the bucket root, or `<name>/.tenarium-owner`). Its content and its
  `tenarium-tenant-id` metadata hold the tenant ID. The marker is created with
  `ifGenerationMatch=0` and updated with the generation it was read at, and bucket updates use
  `ifMetagenerationMatch`. If two tenants race for one name, only one of them can claim it.
  Resources marked for another tenant are never adopted or deleted. An unmarked bucket or prefix
  is adopted only when it is empty (including noncurrent generations), which is what an
  interrupted provisioning run leaves behind.
- **Bucket settings.** `location` applies only at creation, because it cannot be changed. A
  mismatch on an existing bucket is logged. Labels, storage class, versioning (only enabled,
  never disabled), uniform bucket-level access, public access prevention and lifecycle are
  reconciled on every Provision with one PATCH. Nothing is sent if the bucket already matches.
  `lifecycle_expire_days: N` maintains a `Delete` rule `{age: N}` and, with `versioning`, a
  `Delete` rule `{daysSinceNoncurrentTime: N}`. GCS lifecycle rules have no IDs, so any
  `Delete` rule whose only condition is `age` or `daysSinceNoncurrentTime` counts as managed.
  Every other rule is kept.
- **Quota.** GCS has no storage quotas. With `quota_from_limit`, the tenant's limit of that
  name (read as gigabytes) is written as the bucket label `tenarium-quota-gb`. With
  `ownership: object` and in prefix mode, it is written as `tenarium-quota-gb` metadata on the
  owner marker instead. Your own tooling enforces it. Unlimited tenants get no value, and the
  label is removed when a limit is dropped. The value is written on each Provision.
- **Deprovision.** `delete` (default) permanently deletes every object generation, live and
  noncurrent, and then the bucket. Owner markers go last, so an interrupted run can be retried.
  Objects under a retention policy, a hold or Bucket Lock cannot be deleted, so the run fails
  until the retention ends. Soft-deleted objects (the bucket's soft delete policy) do not block
  bucket deletion. `keep` changes nothing, and the ownership marker stays. `retain` keeps the
  data but releases ownership:
  - With labels: `tenarium-tenant-id` is replaced by `tenarium-deleted-at`
    (`2006-01-02t15-04-05z` format, since label values cannot hold `:`) and
    `tenarium-deleted-tenant-id`.
  - With marker objects: the owner marker is replaced by `.tenarium-retained` (JSON with
    `tenant_id` and `deleted_at`).

  Provisioning a new tenant whose name collides with retained data then fails until an operator
  moves or removes the data.
- **Route.** `GET /v1/plugins/{instance}/tenants/{tenant}` returns
  `{"mode", "bucket", "prefix", "project", "url": "gs://bucket/prefix"}`. It answers 404 for
  unknown tenants and for callers who may not read the tenant (`tenants:read`).
- **Health.** `/readyz` lists one bucket of `project` (bucket mode) or reads the shared bucket
  (prefix mode).

## Required permissions

Bucket mode (for example the `roles/storage.admin` role on the project, or a custom role):

```
storage.buckets.list                         (readiness check)
storage.buckets.create  storage.buckets.get  storage.buckets.update  storage.buckets.delete
storage.objects.list  storage.objects.get  storage.objects.create  storage.objects.delete
```

`storage.buckets.update` covers labels, lifecycle, versioning, storage class and IAM
configuration. With `ownership: labels` and the default `on_deprovision`, the object permissions
are only needed to check whether a bucket is empty and to delete its objects.

Prefix mode, on the shared bucket: `storage.buckets.get`, `storage.objects.list`,
`storage.objects.get`, `storage.objects.create` and `storage.objects.delete`
(`roles/storage.objectAdmin` plus `storage.buckets.get`, or `roles/storage.admin` on the bucket).

## Emulators (fake-gcs-server)

```sh
docker run -d -p 4443:4443 fsouza/fake-gcs-server -scheme http -public-host localhost:4443
```

```yaml
config:
  endpoint: http://localhost:4443
  anonymous: true
  project: test-project
  ownership: object
```

fake-gcs-server only partly implements the bucket API:

- It does not store bucket labels. With `ownership: labels`, Provision checks the PATCH response
  and fails with "does not support bucket labels, use ownership: object" instead of running
  without an ownership marker. Use `ownership: object` there. Custom `labels` and the quota
  label are not persisted either.
- It ignores lifecycle rules, storage class, location, uniform bucket-level access and public
  access prevention, so Provision sends a (harmless) PATCH every time those are configured.
- It resets versioning on any bucket PATCH that omits `versioning`. The plugin always restates
  `versioning` in its PATCH requests when the bucket is versioned. On GCS this is a no-op.
- Object generations, `versions=true` listings, generation-specific deletes and
  `ifGenerationMatch` work, so prefix mode and `ownership: object` behave as on GCS.

## Tests

Unit tests run against an in-memory fake of the JSON API (`fake_test.go`).

Integration tests (`integration_test.go`) need one of:

- `TENARIUM_TEST_GCS_ENDPOINT=http://localhost:4443`: an emulator with anonymous access.
  `TENARIUM_TEST_GCS_PROJECT` is optional (default `test-project`). The labels test skips itself
  after checking the "labels not supported" error.
- `TENARIUM_TEST_GCS_PROJECT=<project>` without an endpoint: real GCS with Application Default
  Credentials. The tests create and delete buckets named `tnt-it-*`.
