# Tenant middleware

Tenarium manages tenants, but your application still has to work out which tenant each of its
own requests belongs to and whether that tenant may be served. The tenant middleware packages
handle this for your application's services:

| Language | Package | Frameworks |
|---|---|---|
| Go | `github.com/AimTune/tenarium/pkg/tenantmw` | `net/http` and anything that accepts `func(http.Handler) http.Handler` |
| TypeScript | `@tenarium/middleware` (`sdks/typescript-middleware`) | Express/Connect, `node:http`, or the framework-agnostic core |
| Python | `tenarium-middleware` (`sdks/python-middleware`) | WSGI (Flask, Django, ...) and ASGI (Starlette, FastAPI, ...) |

All three implement the same model, response codes and caching behavior. To call the
Tenarium API itself (create tenants, manage members), use the [Go client](client.md) instead.

## How it works

For each request the middleware:

1. **Resolves** a tenant reference (ID or slug) with a *resolver*: an ordered list of
   *sources*. The first one that matches wins.
2. **Loads** the tenant's state (status, plan, labels and effective features and limits) from
   a *source*: the Redis cache kept by the `redis` plugin or the REST API, usually behind an
   in-memory cache.
3. **Enforces** the tenant's status and the token mismatch rule, and rejects the request if
   either check fails.
4. **Stores** the tenant, and the verified token claims if a Tenarium token was used, where
   handlers can read them.

### Resolution sources

| Source | Go / TypeScript / Python | Matches |
|---|---|---|
| Token | `FromToken(v)` / `fromToken(v)` / `from_token(v)` | `tid` claim of a Tenarium access token in `Authorization: Bearer` |
| Subdomain | `FromSubdomain("app.example.com")` / `fromSubdomain` / `from_subdomain` | `acme.app.example.com` → `acme` (a single label only; the port is ignored) |
| Header | `FromHeader("X-Tenant-ID")` / `fromHeader` / `from_header` | header value, ID or slug |
| Path | `FromPathPrefix()` / `fromPathPrefix()` / `from_path_prefix()` | `/t/{id-or-slug}/...` (Go: `FromPath(prefix)` for another prefix; TS/Python take the prefix as an argument) |
| Custom domain | `FromCustomDomain(d)` / `fromCustomDomain(d)` / `from_custom_domain(d)` | request host looked up with `GET /v1/domains/resolve?host=` |

Custom extractors can be added: `tenantmw.With(extractor)` in Go, any object with `name` and
`extract(req)` in TypeScript, and `Extractor(name, fn)` in Python.

**Tokens.** Tenarium access tokens are ES256 JWTs. The token source verifies the signature
against Tenarium's JWKS (`/.well-known/jwks.json`) and checks `iss`, `aud` (default
`tenarium`), `exp` and `nbf`, with 30s leeway. Key sets are cached for 1h. A token with an
unknown `kid` triggers an earlier refresh, at most once per 30s, so forged key IDs cannot
flood the JWKS endpoint. Bearer values that are not JWTs (such as API keys) or that come from
another issuer do not match and are passed on to the next source. A Tenarium token that fails
verification is rejected with 401. Platform tokens, which have no `tid`, do not resolve a
tenant.

**Mismatch rule.** When a token is present, resolution continues until the *addressed* tenant,
the first match from a non-token source, is also known. If the token's tenant and the
addressed tenant differ, the request is refused with 403 `tenant_mismatch`. A token for tenant
A therefore cannot act on tenant B's subdomain, header or path.

### Sources and caching

- **Redis.** `RedisSource` / `redisSource` / `redis_source` read the keys that the
  [redis plugin](plugins/README.md#redis)'s `cache` feature maintains:
  `<prefix>tenant:<id>` (tenant JSON with effective features and limits) and
  `<prefix>tenant-slug:<slug>` (the ID). The prefix defaults to `tenarium:`, matching the
  plugin's `key_prefix`. A tenant missing from the cache counts as unknown (404), so enable the
  cache and resync it (`POST /v1/plugins/redis/resync`) before you rely on this source. One
  `GET` (two for a slug) per load.
- **API.** `APISource` / `apiSource` / `api_source` (or the `Client` / `ApiClient` itself) call
  `GET /v1/tenants/{id}` and `GET /v1/tenants/{id}/entitlements` with an API key. That is two
  calls per load, so put a cache in front of it.
- **Caching.** `CachingSource` / `cachingSource` / `CachingSource` is an in-memory TTL cache.
  It caches unknown tenants too, for a negative TTL that defaults to the TTL; set it to 0 to
  turn negative caching off. It merges concurrent misses for the same key into one load and
  never caches other errors. Entries are keyed by the reference as given (ID or slug). It holds
  10,000 entries by default. `Invalidate`/`invalidate` drops one entry, for example when a
  `tenant.*` event arrives, and `Purge`/`clear` drops all of them. `CachingDomains` /
  `cachingDomains` cache custom-domain lookups, including unknown hosts, so that a lookup does
  not run on every request.

A cached tenant can be up to one TTL stale, and that includes its status. Choose the TTL with
that in mind, or invalidate entries from an event consumer.

### Status handling

| Situation | Status | Error code |
|---|---|---|
| No source matched (unless optional) | 404 | `tenant_required` |
| Unknown or deleted tenant | 404 | `tenant_not_found` |
| Status not in the allowed statuses (default: `active`) | 403 | `tenant_inactive` |
| Token tenant differs from the addressed tenant | 403 | `tenant_mismatch` |
| Invalid Tenarium token | 401 | `unauthorized` |
| Feature missing (`RequireFeature` and equivalents) | 403 | `feature_disabled` |
| Source or API failure | 503 | `tenant_unavailable` (no details exposed) |

The body is a Tenarium-style error: `{"error": {"code": "...", "message": "..."}}`. To let
suspended tenants in (for example to show a billing page), add `suspended` to the allowed
statuses and check `tenant.Status` in the handler. With the optional setting, requests without
any tenant reference pass through with no tenant. This suits public pages that are served on
the same host.

### Feature gating and limits

The loaded tenant carries its effective entitlements: the plan's features and limits plus the
tenant's overrides. Each language has a feature check that answers 403 `feature_disabled`, and a
limit accessor where an absent limit means unlimited.

### Usage recording

`UsageRecorder` posts to `POST /v1/tenants/{id}/usage/{metric}` with an API key. The server
adds the delta atomically and refuses an increment that would exceed the tenant's limit (429
`quota_exceeded`). The recorders surface that as `ErrQuotaExceeded` / `QuotaExceededError` /
`QuotaExceeded`, so you can answer 429 yourself.

## Go

```go
import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/AimTune/tenarium/pkg/tenantmw"
	"github.com/redis/go-redis/v9"
)

verifier, err := tenantmw.DiscoverVerifier(ctx, "https://tenarium.example.com", nil)
if err != nil {
	return err
}
api := tenantmw.NewClient("https://tenarium.example.com", apiKey)

resolver := tenantmw.NewResolver( // tried in order, first match wins
	tenantmw.FromToken(verifier),
	tenantmw.FromSubdomain("app.example.com"),
	tenantmw.FromHeader("X-Tenant-ID"),
	tenantmw.FromPathPrefix(),
	tenantmw.FromCustomDomain(tenantmw.CachingDomains(api, 5*time.Minute)),
)

// The redis plugin's cache; or tenantmw.APISource(baseURL, apiKey).
rdb := redis.NewClient(&redis.Options{Addr: "redis:6379"})
source := tenantmw.CachingSource(tenantmw.RedisSource(rdb, "tenarium:"), 30*time.Second).
	SetNegativeTTL(5 * time.Second)

usage := tenantmw.NewUsageRecorder(api)

mux := http.NewServeMux()
mux.Handle("GET /reports", tenantmw.RequireFeature("reports")(reportsHandler))
mux.HandleFunc("POST /api/convert", func(w http.ResponseWriter, r *http.Request) {
	t := tenantmw.FromContext(r.Context()) // ID, Slug, Status, Plan, Labels, Features, Limits
	if seats, ok := t.Limit("seats"); ok { // !ok means unlimited
		_ = seats
	}
	if claims := tenantmw.ClaimsFromContext(r.Context()); claims != nil {
		_ = claims.Subject // set when a Tenarium token was used
	}
	if _, err := usage.RecordFor(r.Context(), "api_calls", 1); errors.Is(err, tenantmw.ErrQuotaExceeded) {
		http.Error(w, "quota exceeded", http.StatusTooManyRequests)
		return
	} else if err != nil {
		http.Error(w, "usage unavailable", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintf(w, "hello %s\n", t.Slug)
})

handler := tenantmw.Middleware(resolver, source, tenantmw.Options{
	AllowedStatuses: []tenantmw.Status{tenantmw.StatusActive}, // default
})(mux)
http.ListenAndServe(":8080", handler)
```

- `RedisSource` accepts any `redis.Cmdable`, including cluster clients.
- `DiscoverVerifier` reads `/.well-known/openid-configuration` for the issuer and `jwks_uri`.
  Use `NewVerifier(tenantmw.VerifierConfig{JWKSURL, Issuer, Audience, KeysTTL,
  MinRefreshInterval, Leeway, HTTPClient})` to configure it directly. `Issuer` must match the
  server's `users.public_url` or `auth.tokens.issuer`.
- `Options.Optional` lets requests without a tenant reference through.
  `Options.ErrorHandler` replaces the default JSON writer (`tenantmw.WriteError`), and
  `tenantmw.StatusCode(err)` maps the package's errors (`ErrNoTenant`, `ErrNotFound`,
  `ErrInactive`, `ErrTenantMismatch`, `ErrInvalidToken`, `ErrFeatureDisabled`,
  `ErrQuotaExceeded`) to HTTP status codes.
- `RequireFeatureWith(feature, onErr)` is `RequireFeature` with a custom error writer.
- Tenants returned by sources may be shared between requests. Treat them as read-only.
- Tests: `go test ./pkg/tenantmw/`. Set `TENARIUM_TEST_REDIS_ADDR=localhost:6379` to include the
  Redis integration test.

## TypeScript (Node.js)

`@tenarium/middleware` has no dependencies and needs Node 22.6 or later, which runs the
TypeScript sources directly. Tokens are verified with `node:crypto`.

```ts
import http from "node:http";
import express from "express";
import { Redis } from "ioredis";
import {
  Client, Resolver, Verifier, UsageRecorder, QuotaExceededError,
  cachingDomains, cachingSource, redisSource,
  fromToken, fromSubdomain, fromHeader, fromPathPrefix, fromCustomDomain,
  tenantMiddleware, requireFeature, withTenant, limitOf,
} from "@tenarium/middleware";

const api = new Client("https://tenarium.example.com", process.env.TENARIUM_API_KEY!);
const verifier = await Verifier.discover("https://tenarium.example.com");

const opts = {
  resolver: new Resolver(                       // tried in order, first match wins
    fromToken(verifier),
    fromSubdomain("app.example.com"),
    fromHeader("X-Tenant-ID"),
    fromPathPrefix(),                           // "/t/" by default
    fromCustomDomain(cachingDomains(api, 300_000)),
  ),
  // Any client with get(key) works (ioredis, node-redis); or apiSource(baseUrl, apiKey) / api.
  source: cachingSource(redisSource(new Redis("redis://redis:6379"), "tenarium:"), 30_000,
    { negativeTtlMs: 5_000 }),
  allowedStatuses: ["active"],                  // default
};
```

**Express / Connect.** `tenantMiddleware` sets `req.tenant` and `req.tenantClaims` and answers
rejections itself. Pass `onError: (err, req, res, next) => next(err)` to forward them to your
error handler instead.

```ts
const app = express();
const usage = new UsageRecorder(api);
app.use(tenantMiddleware(opts));
app.get("/reports", requireFeature("reports"), (req, res) => {
  res.json({ tenant: req.tenant.slug, seats: limitOf(req.tenant, "seats") }); // undefined = unlimited
});
app.post("/api/convert", async (req, res) => {
  try {
    await usage.record(req.tenant.id, "api_calls", 1);
  } catch (err) {
    if (err instanceof QuotaExceededError) return res.status(429).end();
    throw err;
  }
  res.end("ok");
});
```

**node:http.**

```ts
http.createServer(withTenant(opts, (req, res, { tenant, claims }) => {
  res.end(`hello ${tenant?.slug}`);
})).listen(8080);
```

`withTenant` writes rejections as JSON. If the handler itself throws, the response is a 500.

**Other frameworks.** `resolveTenant(req, opts)` is the framework-agnostic core. It takes
anything with `headers` (a `Headers` object or a plain object) and `url`, returns
`{ tenant, claims }` and throws `TenantError`. `writeError(res, err)` writes such an error to a
`ServerResponse`. `tenantOf(req)` and `claimsOf(req)` return what an adapter stored for a
request, and `hasFeature(tenant, name)` / `limitOf(tenant, metric)` read entitlements.

- `new Verifier({ jwksUrl, issuer, audience, keysTtlMs, minRefreshIntervalMs, leewaySec, fetch })`
  configures token verification without discovery.
- `cachingSource(src, ttlMs, { negativeTtlMs, maxEntries })` returns a source with
  `invalidate(ref)` and `clear()`.
- `new Client(baseUrl, apiKey, { fetch, timeoutMs })` uses a 10s timeout by default.

Tests:

```sh
node --test "sdks/typescript-middleware/test/*.test.ts"
```

## Python (WSGI and ASGI)

`tenarium_middleware` needs Python 3.9 or later and uses only the standard library. Sources are
synchronous. The ASGI middleware calls them in a worker thread.

```python
import redis
from tenarium_middleware import (
    ApiClient, CachingDomains, CachingSource, Resolver, TenantASGIMiddleware, TenantMiddleware,
    TokenVerifier, UsageRecorder, QuotaExceeded, current_tenant, require_feature, redis_source,
    from_token, from_subdomain, from_header, from_path_prefix, from_custom_domain,
)

api = ApiClient("https://tenarium.example.com", API_KEY)   # timeout=10.0 by default

resolver = Resolver(                      # tried in order, first match wins
    from_token(verifier),                 # see "Verifying tokens" below
    from_subdomain("app.example.com"),
    from_header("X-Tenant-ID"),
    from_path_prefix(),                   # "/t/" by default
    from_custom_domain(CachingDomains(api, ttl=300)),
)
# Any client with .get(key) (e.g. redis.Redis), or the ApiClient / api_source(base_url, api_key).
source = CachingSource(redis_source(redis.Redis(host="redis"), "tenarium:"), ttl=30, negative_ttl=5)

# WSGI (Flask shown)
flask_app.wsgi_app = TenantMiddleware(flask_app.wsgi_app, resolver, source)

# ASGI (Starlette, FastAPI)
asgi_app = TenantASGIMiddleware(starlette_app, resolver, source, allowed_statuses=("active",))
```

Both middlewares take `allowed_statuses` (default `("active",)`) and `optional=False`.

- **WSGI** stores the tenant in `environ["tenarium.tenant"]` and the claims in
  `environ["tenarium.claims"]`.
- **ASGI** stores them in `scope["tenarium.tenant"]` and `scope["tenarium.claims"]`, and also
  in `scope["state"]["tenant"]`, which Starlette exposes as `request.state.tenant`.
- Both also set a context variable that `current_tenant()` and `current_claims()` read.

```python
@require_feature("reports")              # 403 feature_disabled unless enabled; sync or async
def reports():
    t = current_tenant()
    return {"tenant": t.slug, "seats": t.limit("seats")}   # None = unlimited

def convert():
    try:
        UsageRecorder(api).record(current_tenant().id, "api_calls", 1)
    except QuotaExceeded:
        ...  # answer 429
```

`require_feature` raises `TenantError`. Either middleware turns that into a response, provided
the app has not started its response yet. The framework-agnostic core is
`resolve_tenant(Request(...), resolver, source)`, which raises `TenantError` (with `.status`,
`.code` and `.body()`). `Request.from_wsgi(environ)` and `Request.from_asgi(scope)` build its
input.

### Verifying tokens

The standard library cannot verify ECDSA signatures, so `TokenVerifier` takes a
`decode(token) -> claims` callback that checks the ES256 signature against Tenarium's JWKS.
`TokenVerifier` then checks `iss`, `aud`, `exp` and `nbf` itself. With PyJWT
(`pip install "pyjwt[crypto]"`):

```python
import jwt

jwks = jwt.PyJWKClient("https://tenarium.example.com/.well-known/jwks.json")

def decode(token):
    key = jwks.get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=["ES256"], audience="tenarium")

verifier = TokenVerifier("https://tenarium.example.com", decode)   # audience="tenarium", leeway=30
```

The first argument is the expected issuer. Bearer values that are not JWTs, or whose
unverified `iss` belongs to another issuer, are ignored without calling `decode`. If `decode`
raises, the request gets 401.

Tests:

```sh
python -m unittest discover -s sdks/python-middleware/tests -v
```
