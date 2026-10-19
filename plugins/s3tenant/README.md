# s3-tenant

Gives every tenant its own bucket, or its own key prefix in a shared bucket, on Amazon S3 or an
S3-compatible store. The full reference for names, ownership, bucket options, quota and
deprovisioning is in [docs/plugins/README.md](../../docs/plugins/README.md#s3-tenant). This file
covers the optional **per-tenant IAM users**.

## IAM users

```yaml
- plugin: s3-tenant
  config:
    endpoint: s3.eu-central-1.amazonaws.com
    region: eu-central-1
    access_key: ${S3_ACCESS_KEY}
    secret_key: ${S3_SECRET_KEY}
    iam:
      enabled: true
      path: /tenarium/                 # default; IAM path of tenant users
      user_template: "{{.Name}}"       # default; over {Tenant, Name} (Name = bucket or prefix name)
      # policy_template: |             # default: access to the tenant's bucket or prefix only
      #   {"Version": "2012-10-17", "Statement": [...{{.Bucket}}...{{.Prefix}}...]}
      # permissions_boundary: arn:aws:iam::123456789012:policy/tenant-boundary
      # partition: aws                 # ARN partition of the default policy (aws-cn, aws-us-gov)
      # endpoint: http://localstack:4566   # IAM endpoint override; empty = AWS
      # region: us-east-1              # signing region for IAM (global service)
      # access_key / secret_key        # default: the top-level credentials
```

- **Provision** (after the bucket or prefix) creates the IAM user `user_template` under `path`,
  tagged `tenarium-tenant-id=<id>` and `tenarium-tenant-slug=<slug>` in the same call, and
  (re)writes its inline policy `tenarium-s3`. Re-provisioning rewrites the policy, so policy
  changes reach existing tenants on the next provisioning run. User names are sanitized to IAM's
  character set (`[A-Za-z0-9+=,.@_-]`) and shortened to 64 characters with a hash of the tenant ID.
- **Default policy.** Bucket mode: `s3:ListBucket`, `ListBucketVersions`,
  `ListBucketMultipartUploads` and `GetBucketLocation` on the bucket, and object read, write,
  delete, versions, tagging and multipart actions on `bucket/*`. Prefix mode: listing of the shared
  bucket only with `s3:prefix` matching `<name>/*`, object actions on `bucket/<name>/*`, and an
  explicit `Deny` on writing or deleting the ownership markers (`.tenarium-owner`,
  `.tenarium-retained`). No bucket-level management (tags, policy, lifecycle, versioning) is
  granted. `policy_template` replaces it. It is a text/template over
  `{Tenant, Bucket, Prefix, Partition, User}` and must render valid JSON.
- **Ownership.** A user tagged for another tenant is never adopted or deleted (provisioning fails
  with a clear error). An untagged user with the same name is adopted only if it has no access keys
  and no inline or attached policies. Otherwise provisioning fails.
- **Access keys are never created or stored by provisioning.** Admins create them on demand:

  | Route (under `/v1/plugins/{instance}`) | Authorization | Result |
  |---|---|---|
  | `POST /tenants/{tenant}/access-keys` | `tenants:update` | `201` with `access_key_id` and `secret_access_key` (**returned once**, `Cache-Control: no-store`), plus `user`, `bucket`, `prefix`, `endpoint`, `region` |
  | `GET /tenants/{tenant}/access-keys` | `tenants:update` | key IDs, status and creation time (no secrets) |
  | `DELETE /tenants/{tenant}/access-keys/{key}` | `tenants:update` | `204` |

  Callers that cannot read the tenant get `404`. Callers that can read but not update it get `403`.
  `409` means the tenant has no IAM user yet (provision first) or already has IAM's maximum of two
  keys. To rotate a key, create the new one, switch the application over, then delete the old one.
  New keys can take a few seconds to work, because IAM is eventually consistent.
- **Deprovision** with `delete` or `retain` deletes the user first (revoking access even when the
  data is retained), together with everything that blocks deletion: access keys, inline policies,
  attached managed policies, group memberships, the login profile, signing certificates, SSH keys,
  service-specific credentials and MFA devices. Credential types the server does not implement
  (HTTP 501, e.g. LocalStack) are skipped. `keep` leaves the user in place.
- `GET /tenants/{tenant}` also returns `iam_user`. `/readyz` additionally lists IAM users under
  `path`.

The IAM API is AWS's. S3-compatible stores without it (MinIO, SeaweedFS, R2) cannot use this
feature. LocalStack and Ceph RGW implement the parts the plugin uses.

### Required IAM permissions

On `arn:aws:iam::<account>:user/tenarium/*` (adjust to `path`):

```
iam:GetUser  iam:CreateUser  iam:TagUser  iam:DeleteUser
iam:PutUserPolicy  iam:ListUserPolicies  iam:DeleteUserPolicy
iam:ListAttachedUserPolicies  iam:DetachUserPolicy  iam:ListGroupsForUser  iam:RemoveUserFromGroup
iam:CreateAccessKey  iam:ListAccessKeys  iam:DeleteAccessKey
iam:DeleteLoginProfile  iam:ListSigningCertificates  iam:DeleteSigningCertificate
iam:ListSSHPublicKeys  iam:DeleteSSHPublicKey
iam:ListServiceSpecificCredentials  iam:DeleteServiceSpecificCredential
iam:ListMFADevices  iam:DeactivateMFADevice
iam:ListUsers                                  (readiness check, resource "*")
```

Granting `iam:PutUserPolicy` lets the plugin's credentials give any permission to users under the
path. Constrain that with `permissions_boundary` and a condition
`iam:PermissionsBoundary = <arn>` on `iam:CreateUser` and `iam:PutUserPolicy`.

## Tests

Unit tests use an in-memory IAM fake. Integration tests need `TENARIUM_TEST_S3_ENDPOINT`
(host:port of an S3-compatible server). IAM tests also need `TENARIUM_TEST_S3_IAM_ENDPOINT` (e.g.
LocalStack `http://localhost:4566`), with credentials `TENARIUM_TEST_S3_IAM_ACCESS_KEY` and
`TENARIUM_TEST_S3_IAM_SECRET_KEY` (default `test`/`test`).
