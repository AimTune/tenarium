# @tenarium/client (TypeScript)

Typed client for the Tenarium REST API. The types and the per-operation
methods are generated from [`internal/api/openapi.yaml`](../../internal/api/openapi.yaml);
the runtime around them (credentials, retries, pagination, errors) is
hand-written. It has no runtime dependencies, is ESM-only, uses the global
`fetch`, and works in Node.js 18+ and browsers.

```ts
import { Client, isVersionConflict, etagOf } from "@tenarium/client";

const c = new Client({
  baseUrl: "https://tenarium.example.com",
  apiKey: process.env.TENARIUM_API_KEY,
  maxRetries: 3,
});

const t = await c.createTenant({ slug: "acme", name: "Acme", plan: "free" });

try {
  await c.updateTenant("acme", { plan: "pro" }, { ifMatch: t.version }); // or ifMatch: etagOf(t)
} catch (err) {
  if (isVersionConflict(err)) { /* 412: someone else changed it; reload and retry */ }
}

for await (const tenant of c.listTenantsAll({ status: "active" })) {
  console.log(tenant.slug);
}
```

## Methods

`Client` has one method per operation, named after its `operationId`
(`listTenants`, `getTenant`, `recordUsage`, `scimCreateUser`, ...). The
arguments are, in order:

1. path parameters, positionally (`getWebhook(tenantId, webhookId)`),
2. the request body, if the operation has one,
3. the query parameters as one object (`listTenants({ status, label: ["tier=gold"], limit })`),
4. `RequestOptions`: `{ ifMatch, idempotencyKey, headers, signal, timeoutMs }`.

Every request and response body has a named type (`Tenant`, `TenantCreate`,
`ListMembersResponse`, ...), exported from the package. See
[`src/generated/operations.ts`](src/generated/operations.ts) for the full list.
Operations without an `operationId` (`/healthz`, `/readyz`, `/metrics`,
`/.well-known/*`) and anything else can be called with
`c.call("GET", "/readyz")`.

Arrays in query parameters repeat the key (`label=a&label=b`); `undefined`
values are left out. int64 values are plain numbers (exact up to 2^53);
int64 query parameters also accept strings.

## Credentials

| Option | Purpose |
|---|---|
| `apiKey` / `token` | Static bearer credentials (API key or an external access token) |
| `tokenSource` | Any `TokenProvider` (`token()`, optionally `reauth(rejected)`) |

Operations marked public in the spec (`token`, `logout`, password reset,
SSO discovery, ...) never send credentials.

### User sessions with automatic refresh

```ts
const pub = new Client({ baseUrl });
const pair = await pub.token({ grant_type: "password", email, password, tenant: "acme" });

const ts = pub.tokenSource(pair, {
  onRefresh: (p) => save(p), // refresh tokens rotate: persist the whole pair
});
const c = pub.with({ tokenSource: ts });
```

`TokenSource` refreshes the access token with the `refresh_token` grant 30
seconds (at most half the lifetime) before it expires. If the server
rejects a token with 401 the client refreshes once and repeats the request.
Refreshes are serialized: concurrent requests share one refresh, so a
rotated refresh token is never reused (which would make the server revoke
the session). A saved pair (it has `expires_at`) can be passed back to
`tokenSource()` to restore the session.

## Retries and idempotency

`maxRetries` (default 0) enables retries of network errors, timeouts,
502/503/504 and 429 responses that carry `Retry-After`. The delay is the
server's `Retry-After`, or exponential backoff from `retryBackoffMs`
(default 200 ms, capped at `maxRetryDelayMs`) with jitter.

Only requests that are safe to repeat are retried: GET, HEAD, PUT, DELETE,
OPTIONS, and POSTs that carry an `Idempotency-Key`. With retries on, create
calls (POSTs answering 201, and `recordUsage`) get a random key
automatically, and the server replays the first response instead of
creating a duplicate. Pass `{ idempotencyKey }` to make other POSTs
retryable or to reuse a key across process restarts. PATCH is never retried.

`timeoutMs` (client or per call) bounds each attempt; `signal` aborts the
whole call including backoff waits.

## Concurrency control (ETag / If-Match)

Mutable resources carry a `version` and the response has an `ETag`. Pass
either as `ifMatch`; a stale value fails with 412 (`isVersionConflict`).
`etagOf(result)` and `responseOf(result)` (status, headers, `requestId`)
read the response metadata, which is attached to every decoded object as a
non-enumerable property.

## Errors

Non-2xx responses throw `TenariumError` with `status`, `code`, `message`,
`field`, `requestId`, `retryAfterMs` and the decoded `body`. SCIM errors map
`scimType`/`detail` to `code`/`message`.

```ts
try {
  await c.recordUsage("acme", "api_calls", { delta: 1 });
} catch (err) {
  if (isQuotaExceeded(err)) console.log("limit reached for", err.field);
  else if (err instanceof TenariumError) console.log(err.code, err.requestId);
  else throw err; // network error, timeout, abort
}
```

Helpers: `isNotFound`, `isConflict`, `isVersionConflict`, `isQuotaExceeded`,
`isForbidden`, `isUnauthorized`, `isValidation`.

## Pagination

Paginated lists have an `<operationId>All` async iterator that follows the
`next` cursor: `listTenantsAll`, `listChildrenAll`, `listUsersAll`,
`listEventsAll` (cursor sent as `after`), and `listAuditAll`,
`listTenantAuditAll`, `listWebhookDeliveriesAll` (newest first; cursor sent
as `before`). Pages are fetched as the loop advances; `collect(iter, max)`
gathers items into an array.

## Development

```sh
go run ./tools/clientgen                 # regenerate src/generated after a spec change (repo root)
node --test "test/*.test.ts"             # tests (Node 22.6+ runs the .ts sources directly)
npx -p typescript@5.8 tsc -p tsconfig.json --noEmit   # type-check
npm run build                            # emit dist/ (JavaScript + .d.ts) for publishing
```

Do not edit `src/generated/` by hand: `go test ./tools/clientgen/` fails
when the committed files differ from what the generator produces.
