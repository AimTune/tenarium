# tenarium-client (Python)

Typed client for the Tenarium REST API. The types and the per-operation
methods are generated from [`internal/api/openapi.yaml`](../../internal/api/openapi.yaml)
into `tenarium_client/_generated.py`; the runtime around them (credentials,
retries, pagination, errors) is hand-written. It needs Python 3.9+ and uses
only the standard library (`urllib`).

```python
from tenarium_client import Client, TenariumError, etag_of, is_version_conflict

c = Client("https://tenarium.example.com", api_key=API_KEY, max_retries=3)

t = c.create_tenant({"slug": "acme", "name": "Acme", "plan": "free"})

try:
    c.update_tenant("acme", {"plan": "pro"}, if_match=t["version"])  # or if_match=etag_of(t)
except TenariumError as e:
    if is_version_conflict(e):
        ...  # 412: someone else changed it; reload and retry

for tenant in c.iter_tenants(status="active"):
    print(tenant["slug"])
```

## Methods

`Client` has one method per operation, named after its `operationId` in
snake_case (`list_tenants`, `get_tenant`, `record_usage`, `scim_create_user`,
`list_tenant_api_keys`, ...):

- path parameters are positional (`c.get_webhook(tenant_id, webhook_id)`),
- the request body follows them, as a dict,
- query parameters are keyword arguments in snake_case (`start_index=`);
  `None` leaves one out and lists repeat the key (`label=["a=1", "b=2"]`),
- `if_match=` (updates that support it), `idempotency_key=` (POST) and
  `headers=` are keyword arguments too.

Request and response bodies are `TypedDict` classes (`Tenant`,
`TenantCreate`, `ListMembersResponse`, ...) exported from the package; at
runtime they are plain dicts. Decoded objects are `ResultDict`, a `dict`
with the response's `status`, `headers`, `etag` and `request_id` attached.
Non-JSON responses are returned as `str`, empty ones as `None`.

Operations without an `operationId` (`/healthz`, `/readyz`, `/metrics`,
`/.well-known/*`) and anything else can be called with
`c.call("GET", "/readyz")`.

## Credentials

`api_key=` or `token=` send static bearer credentials; `token_source=`
takes any object with `token()` and optionally `reauth(rejected)`.
Operations that are public in the spec (`token`, `logout`, password reset,
SSO discovery, ...) never send credentials.

### User sessions with automatic refresh

```python
pub = Client(BASE_URL)
pair = pub.token({"grant_type": "password", "email": email, "password": password, "tenant": "acme"})

ts = pub.token_source(pair, on_refresh=save)  # refresh tokens rotate: persist the whole pair
c = pub.with_options(token_source=ts)
```

`TokenSource` refreshes the access token with the `refresh_token` grant 30
seconds (at most half the lifetime) before it expires, and once more when
the server answers 401, after which the request is repeated. It is
thread-safe and serializes refreshes, so a rotated refresh token is never
reused (which would make the server revoke the session). A saved pair (it
has `expires_at`) can be passed back to restore the session.

## Retries and idempotency

`max_retries=` (default 0) enables retries of network errors, timeouts,
502/503/504 and 429 responses that carry `Retry-After`. The delay is the
server's `Retry-After`, or exponential backoff from `retry_backoff`
(default 0.2 s, capped at `max_retry_delay`) with jitter.

Only requests that are safe to repeat are retried: GET, HEAD, PUT, DELETE,
OPTIONS, and POSTs that carry an `Idempotency-Key`. With retries on, create
calls (POSTs answering 201, and `record_usage`) get a random key
automatically, and the server replays the first response instead of
creating a duplicate. Pass `idempotency_key=` to make other POSTs retryable.
PATCH is never retried. `timeout=` (default 30 s) applies to each attempt.

## Errors

Non-2xx responses raise `TenariumError` with `status`, `code`, `message`,
`field`, `request_id`, `retry_after` and the decoded `body`. SCIM errors map
`scimType`/`detail` to `code`/`message`. Network errors are raised as the
underlying `OSError` (`urllib.error.URLError`, `TimeoutError`, ...).

```python
try:
    c.record_usage("acme", "api_calls", {"delta": 1})
except TenariumError as e:
    if is_quota_exceeded(e):
        print("limit reached for", e.field)
    else:
        print(e.code, e.request_id)
```

Helpers: `is_not_found`, `is_conflict`, `is_version_conflict`,
`is_quota_exceeded`, `is_forbidden`, `is_unauthorized`, `is_validation`.

## Pagination

Paginated lists have an `iter_*` generator that follows the `next` cursor:
`iter_tenants`, `iter_children`, `iter_users`, `iter_events` (cursor sent as
`after`), and `iter_audit`, `iter_tenant_audit`, `iter_webhook_deliveries`
(newest first; cursor sent as `before`). Pages are fetched lazily.

## Development

```sh
go run ./tools/clientgen        # regenerate _generated.py after a spec change (repo root)
python -m unittest              # tests, from sdks/python-client
docker run --rm -v "$PWD:/w" -w /w/sdks/python-client python:3.13-slim python -m unittest
```

Do not edit `_generated.py` by hand: `go test ./tools/clientgen/` fails when
the committed file differs from what the generator produces.
