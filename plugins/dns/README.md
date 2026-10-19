# dns-tenant

Creates DNS records for each tenant in an **Amazon Route 53** hosted zone or a **Cloudflare**
zone, for example `acme.example.com CNAME ingress.example.com` when tenant `acme` is created, and
removes them when the tenant is deleted. Every managed name gets a sibling TXT ownership marker
so the plugin never takes over or deletes records it did not create.

## Configuration

```yaml
- plugin: dns-tenant
  config:
    provider: route53                 # route53 | cloudflare (the block of that name is required)
    zone: example.com                 # the DNS zone; record names must lie inside it
    records:
      - name_template: "{{.Slug}}"    # relative to zone -> acme.example.com
        type: CNAME
        values: [ingress.example.com]
      - name_template: "api.{{.Slug}}.example.com"   # absolute (ends with the zone)
        type: A
        values: [192.0.2.10, 192.0.2.11]
        ttl: 120
      - name_template: "_verify.{{.Slug}}"
        type: TXT
        values: ["tenant={{.ID}}"]
    ownership_txt_prefix: "_tenarium."   # marker TXT lives at _tenarium.<record name>
    on_deprovision: delete               # delete | keep
    route53:
      region: us-east-1
      hosted_zone_id: Z0123456789ABCDEFGHIJ   # optional, looked up by zone name
      # access_key_id / secret_access_key / session_token: optional static credentials;
      # otherwise the default AWS chain (env, shared config, IAM role / IRSA) is used
      # endpoint: http://localhost:4566         # e.g. LocalStack
      wait: true                               # wait until the change is INSYNC
      wait_timeout: 2m
```

Cloudflare:

```yaml
- plugin: dns-tenant
  config:
    provider: cloudflare
    zone: example.com
    cloudflare:
      api_token: ${CLOUDFLARE_API_TOKEN}
      zone_id: 023e105f4ecef8ad9ca31a8372d0c353   # optional, looked up by zone name
      # base_url: https://api.cloudflare.com/client/v4
    records:
      - name_template: "{{.Slug}}"
        type: A
        values: [192.0.2.10]
        proxied: true
```

### Field reference

| Field | Default | Description |
|---|---|---|
| `provider` | (required) | `route53` or `cloudflare`. Exactly the matching block must be set. |
| `zone` | (required) | Zone (domain) name, e.g. `example.com`. All record names must be inside it. |
| `records[].name_template` | (required) | text/template over the tenant (`.ID`, `.Slug`, ...). See *Names*. |
| `records[].type` | (required) | `A`, `AAAA`, `CNAME` or `TXT`. |
| `records[].values` | (required) | Values, each a template (static strings are fine). A/AAAA must be IP addresses of the right family, a CNAME has exactly one host name value, TXT values are printable ASCII (long values are split into 255-byte strings automatically). |
| `records[].ttl` | `300` | Seconds. Cloudflare: `1` (automatic) or 30-86400. |
| `records[].proxied` | `false` | Cloudflare only; A, AAAA and CNAME. Proxied records always use the automatic TTL. |
| `ownership_txt_prefix` | `_tenarium.` | Prefix of the marker TXT name; must end with `.` (it forms separate labels). |
| `on_deprovision` | `delete` | `delete` or `keep`, see below. |
| `route53.region` | `us-east-1` | Route 53 is global; the region only selects the signing region/endpoint. |
| `route53.access_key_id`, `secret_access_key`, `session_token` | | Static credentials (key ID and secret together). Without them the default AWS credential chain is used. |
| `route53.endpoint` | | API URL override (LocalStack, VPC endpoint). |
| `route53.hosted_zone_id` | | Looked up with `ListHostedZonesByName` when empty; if a public and a private zone share the name, you must set it. |
| `route53.wait` | `false` | Block Provision/Deprovision until Route 53 reports the change `INSYNC`. |
| `route53.wait_timeout` | `5m` | Go duration bounding `wait`. |
| `cloudflare.api_token` | (required) | API token (not a global API key). |
| `cloudflare.base_url` | `https://api.cloudflare.com/client/v4` | API URL override. |
| `cloudflare.zone_id` | | Looked up with `GET /zones?name=<zone>` when empty. |

The configuration is validated at startup: templates are rendered for two sample tenants, every
name template must depend on the tenant, values must parse for their type, a CNAME cannot share
its name with another record, the same name and type cannot appear twice, and no record may sit
at a marker name. Startup does not contact the provider; `/readyz` does.

## Behavior

### Names

The rendered name is lowercased and interpreted like this:

- ends with `.` - absolute; it must be inside `zone`, otherwise provisioning fails;
- equals the zone or ends with `.<zone>` - taken as is;
- anything else - relative to the zone (`{{.Slug}}.apps` -> `acme.apps.example.com`).

Each label is sanitized to letters, digits and hyphens (other characters become `-`, runs
collapse, leading/trailing hyphens are removed). A single leading underscore is kept
(`_acme-challenge`), and `*` is allowed as the first label for wildcard records. Labels longer
than 63 characters are shortened and suffixed with `-` + the first 8 hex characters of
`sha256(tenant ID)`, so shortening never maps two tenants to one name; names longer than 253
characters are rejected. The zone apex can never be a tenant record.

Use only immutable tenant fields (`ID`, `Slug`) in templates: names are recomputed at
deprovision time, and a name derived from a mutable field would leave the old records behind.

### Ownership

Following the external-dns TXT registry, every managed name `N` has a marker
`TXT <ownership_txt_prefix>N = "tenarium-owner=<tenant ID>"` (for a wildcard `*.x.example.com`
the marker is `_tenarium._wildcard.x.example.com`). The marker cannot live at `N` itself because
a CNAME cannot coexist with any other record type. The marker is the source of truth on both
providers (on Cloudflare the records additionally carry the comment
`managed by tenarium for tenant <id>`, which is informational only).

- If the marker names another tenant, Provision fails and Deprovision leaves the name alone.
- If the marker name holds TXT values that are not a tenarium marker, the name is refused.
- Without a marker, Provision only creates records that do not exist yet: an existing record of
  the same name and type, a CNAME at the name, or any record where a CNAME should go makes
  Provision fail with an error instead of taking it over. Unmarked records are never adopted.
- Once the marker names the tenant, Provision converges: values, TTL and proxying are updated
  to match the configuration.

### Provisioning

- **Route 53**: markers and records are written in **one atomic change batch**. Sets that do not
  exist yet use `CREATE`, so if someone creates a conflicting record between the ownership check
  and the write, the whole batch fails rather than overwriting it; owned sets use `UPSERT`.
  Nothing is sent when everything is already up to date. With `wait`, the plugin waits for
  `INSYNC`.
- **Cloudflare** has no transactions: markers are created first, then the records of each
  name/type are converged (matching records kept or patched, missing ones created, surplus ones
  deleted). An interrupted run leaves the names marked for the tenant, so a retry finishes it.

Removing a record from the configuration does not delete it from existing tenants; changing a
record's type at an owned name may fail at the provider (e.g. a new CNAME over an old A record).
Deprovision with the old configuration, or clean up manually, in those cases.

### Deprovisioning

- `delete` (default): for each name whose marker names the tenant, the configured record types
  are deleted with their exact current values, then the marker. On Route 53 this is one batch;
  on Cloudflare the marker is deleted last. Names not marked for the tenant (never provisioned,
  already deleted, owned by someone else) are skipped, so Deprovision is idempotent.
- `keep`: nothing is touched. The records keep resolving and the marker keeps blocking other
  tenants (e.g. a new tenant reusing the slug) from taking the names.

There is no `retain` mode: DNS records carry no data worth keeping without an owner, and
releasing the marker while leaving the records live would produce unowned records that no tenant
could reclaim. Quota mapping from entitlements does not apply to DNS and is not offered.

## Routes

`GET /v1/plugins/{instance}/tenants/{tenant}` (tenant ID or slug) returns the records rendered for
the tenant (from the configuration, not read back from the provider). It requires
`tenants:read` on the tenant and answers 404 when denied, so callers cannot probe other tenants:

```json
{
  "provider": "route53",
  "zone": "example.com",
  "records": [
    {"name": "acme.example.com", "type": "CNAME", "values": ["ingress.example.com"], "ttl": 300},
    {"name": "api.acme.example.com", "type": "A", "values": ["192.0.2.10", "192.0.2.11"], "ttl": 120}
  ]
}
```

## Health

`/readyz` calls `GetHostedZone` (Route 53) or `GET /zones/{id}` (Cloudflare), after looking up the
zone ID if needed, and checks that the zone name matches `zone`.

## Required permissions

Route 53 IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets", "route53:GetHostedZone"],
     "Resource": "arn:aws:route53:::hostedzone/Z0123456789ABCDEFGHIJ"},
    {"Effect": "Allow", "Action": ["route53:GetChange"], "Resource": "arn:aws:route53:::change/*"},
    {"Effect": "Allow", "Action": ["route53:ListHostedZonesByName"], "Resource": "*"}
  ]
}
```

(`GetChange` is needed only with `wait`, `ListHostedZonesByName` only without `hosted_zone_id`.)

Cloudflare API token: `Zone - DNS - Edit` and `Zone - Zone - Read`, scoped to the zone.

## Security notes

- Credentials (AWS keys, Cloudflare token) are never returned by the route or logged. Prefer the
  AWS default credential chain (IAM role / IRSA) and `${ENV}` substitution for the token.
- Marker TXT records are public DNS data: they reveal tenant IDs (UUIDs) to anyone who queries
  the zone. Tenant IDs are not secrets in Tenarium, but use a dedicated prefix if you prefer.
- Scope the credentials to the one zone; the plugin never touches names outside `zone`.
- Record values may come from templates; they are validated per type (IPs, host names,
  printable ASCII TXT) so a tenant field cannot inject other record data.

## Testing

```sh
go test ./plugins/dns/...
```

Unit tests use an in-memory Route 53 client (behind a small interface; atomic batches, CREATE
conflicts, exact-match DELETE) and an `httptest` fake of the Cloudflare API.

Integration tests are skipped unless configured:

| Variable | Purpose |
|---|---|
| `TENARIUM_TEST_ROUTE53_ENDPOINT` | Route 53 compatible endpoint, e.g. LocalStack `http://localhost:4566`. A hosted zone is created and deleted per test. |
| `TENARIUM_TEST_ROUTE53_ACCESS_KEY_ID`, `TENARIUM_TEST_ROUTE53_SECRET_ACCESS_KEY` | Credentials (default `test`/`test`). |
| `TENARIUM_TEST_CLOUDFLARE_API_TOKEN`, `TENARIUM_TEST_CLOUDFLARE_ZONE_ID` | A real Cloudflare zone; records are created under a random label and removed. |
| `TENARIUM_TEST_CLOUDFLARE_BASE_URL` | Optional API URL override. |

```sh
docker run -d --name tenarium-test-localstack -p 44566:4566 -e SERVICES=route53 localstack/localstack:3.8
TENARIUM_TEST_ROUTE53_ENDPOINT=http://localhost:44566 go test -run Integration ./plugins/dns/
docker rm -f tenarium-test-localstack
```

Recent `localstack/localstack:latest` images require a LocalStack auth token; the 3.x community
images (e.g. `3.8`) run Route 53 without one.
