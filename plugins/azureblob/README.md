# azure-blob-tenant

Gives every tenant its own Azure Blob Storage container (package `plugins/azureblob`). The
plugin calls the Blob service REST API directly, using Shared Key authorization
(HMAC-SHA256, `x-ms-version: 2023-11-03`). It works with Azure Storage accounts and with the
Azurite emulator.

```yaml
- plugin: azure-blob-tenant
  config:
    # Either a connection string ...
    connection_string: ${AZURE_STORAGE_CONNECTION_STRING}
    #   "DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=...;EndpointSuffix=core.windows.net"
    #   "UseDevelopmentStorage=true"   (Azurite at http://127.0.0.1:10000/devstoreaccount1)
    # ... or the account directly:
    # account_name: acme
    # account_key: ${AZURE_STORAGE_KEY}
    # endpoint: https://acme.blob.core.windows.net   # default; http://127.0.0.1:10000 for Azurite
    name_template: "tenant-{{.Slug}}"   # default
    public_access: none                 # none (default) | blob | container
    quota_from_limit: storage_gb        # limit recorded as metadata tenarium_quota_gb
    on_deprovision: delete              # delete (default) | keep | retain
```

Set exactly one of `connection_string` or `account_name` + `account_key` (+ optional
`endpoint`). Connection strings may contain `DefaultEndpointsProtocol`, `AccountName`,
`AccountKey`, `EndpointSuffix` and `BlobEndpoint`, or `UseDevelopmentStorage=true` (with an
optional `DevelopmentStorageProxyUri`). `SharedAccessSignature` is rejected because
provisioning needs account-level rights. An endpoint whose host is an IP address or
`localhost` and that has no path gets the account appended as the first path segment, which is
the path-style URL form used by Azurite. A custom `BlobEndpoint` is used exactly as given.

## Behavior

- **Names.** The rendered name is sanitized to a valid container name: lowercase letters,
  digits and single hyphens, 3 to 63 characters, starting and ending with a letter or digit.
  Names that are too short or too long are cut and get a `-<hash>` suffix computed from the
  tenant ID, so tenants never collide because of truncation. A template that renders the same
  name for two sample tenants is rejected at startup. Use only immutable fields (`ID`, `Slug`),
  because the name is recomputed on deprovision.
- **Ownership.** Containers carry the metadata `tenarium_tenant_id=<id>`. Metadata names must
  be C# identifiers, so they use underscores. New containers are created with the marker in
  the same request, so no unmarked window exists. A container marked for another tenant is
  never adopted or deleted. An unmarked container is adopted only if it holds no blob (checked
  with List Blobs `maxresults=1`). Existing metadata such as your own labels is preserved.
- **Public access.** `public_access` is applied at creation and corrected on every Provision.
  The stored access policies (signed identifiers) of the container are kept, because Set
  Container ACL replaces both at once. Storage accounts with *Allow Blob anonymous access*
  disabled reject `blob` and `container`.
- **Quota.** Azure has no container quotas. With `quota_from_limit`, the tenant's limit of that
  name (read as gigabytes) is written as metadata `tenarium_quota_gb` for your own tooling to
  enforce. Unlimited tenants get no value. The value is updated when provisioning is retried.
- **Deprovision.**
  - `delete` (default) deletes the container and every blob in it. Enable container soft delete
    on the account if you want a recovery window. Azure deletes containers asynchronously.
    While a deletion runs, creating a container with the same name fails with
    `409 ContainerBeingDeleted`. Provision retries for up to 60 seconds and then fails with a
    clear error, after which a provisioning retry succeeds. Deprovision treats
    `ContainerBeingDeleted` and `ContainerNotFound` as done.
  - `keep` changes nothing. The marker stays, so a new tenant with the same slug cannot take
    over the data.
  - `retain` keeps the data but releases ownership: `tenarium_tenant_id` (and
    `tenarium_quota_gb`) are replaced by `tenarium_deleted_at=<RFC3339>` and
    `tenarium_deleted_tenant_id=<id>`, and public access is switched off. Provisioning a tenant
    whose name collides with retained data then fails until an operator removes or renames the
    container.
- **Concurrency.** Set Container Metadata does not support `If-Match`, so the plugin cannot use
  ETags there. Ownership is checked right before each change instead. Delete Container is sent
  with `If-Unmodified-Since` set to the `Last-Modified` time seen during the ownership check.
  If the container's properties or metadata changed in the meantime, the delete is refused
  (`ConditionNotMet`), and the deprovision fails so it can be retried. Blob writes do not change
  a container's `Last-Modified`. Containers under a lease or an immutability policy cannot be
  deleted, and the error is reported.
- **Route.** `GET /v1/plugins/{instance}/tenants/{tenant}` returns
  `{"container", "account", "url"}`. Callers without `tenants:read` on the tenant get `404`.
- **Health.** `/readyz` runs List Containers with `maxresults=1`, which checks both
  reachability and the account key.

## Required permissions

Shared Key authorization uses an account key, which grants full access to the storage
account. Give the plugin a dedicated storage account for tenant data. Key-based access must be
allowed on the account (`allowSharedKeyAccess` must not be `false`). The operations used are:
List Containers, Create Container, Get Container Properties, Set Container Metadata,
Get/Set Container ACL, List Blobs and Delete Container.

## Tests

Unit tests use an in-memory fake Blob service that verifies every request's signature with a
separate implementation, plus a fixed Shared Key test vector computed with `openssl`.
Integration tests run when `TENARIUM_TEST_AZURE_CONNECTION_STRING` is set:

```sh
docker run -d --name azurite -p 10000:10000 mcr.microsoft.com/azure-storage/azurite \
  azurite-blob --blobHost 0.0.0.0 --skipApiVersionCheck --loose
TENARIUM_TEST_AZURE_CONNECTION_STRING='UseDevelopmentStorage=true' go test ./plugins/azureblob/
```
