# tenantmw

`github.com/AimTune/tenarium/pkg/tenantmw` is net/http middleware for SaaS
applications whose tenants are managed by Tenarium. It works out which tenant
each request belongs to, loads that tenant's state, rejects unknown or inactive
tenants, and puts a `*tenantmw.Tenant` in the request context.

## Usage

```go
verifier, _ := tenantmw.DiscoverVerifier(ctx, "https://tenarium.example.com", nil)

resolver := tenantmw.NewResolver( // tried in this order, first match wins
	tenantmw.FromToken(verifier),                 // tid claim of a Tenarium access token
	tenantmw.FromSubdomain("app.example.com"),    // acme.app.example.com -> "acme"
	tenantmw.FromHeader("X-Tenant-ID"),           // ID or slug
	tenantmw.FromPathPrefix(),                    // /t/acme/...
	tenantmw.FromCustomDomain(tenantmw.CachingDomains(api, 5*time.Minute)),
)

// State from the redis plugin's cache (or tenantmw.APISource(baseURL, apiKey)).
source := tenantmw.CachingSource(tenantmw.RedisSource(rdb, "tenarium:"), 30*time.Second)

mux := http.NewServeMux()
mux.Handle("/reports", tenantmw.RequireFeature("reports")(reportsHandler))
http.ListenAndServe(":8080", tenantmw.Middleware(resolver, source, tenantmw.Options{})(mux))
```

In handlers:

```go
t := tenantmw.FromContext(r.Context())      // ID, Slug, Status, Plan, Features, Limits
if t.HasFeature("sso") { ... }
if seats, ok := t.Limit("seats"); ok { ... } // !ok means unlimited
claims := tenantmw.ClaimsFromContext(r.Context()) // set when a Tenarium token was used
```

Metered usage:

```go
api := tenantmw.NewClient("https://tenarium.example.com", apiKey)
usage := tenantmw.NewUsageRecorder(api)
if _, err := usage.RecordFor(r.Context(), "api_calls", 1); errors.Is(err, tenantmw.ErrQuotaExceeded) {
	http.Error(w, "quota exceeded", http.StatusTooManyRequests)
}
```

## Behaviour

| Situation | Response |
|---|---|
| No source matched (unless `Options.Optional`) | 404 `tenant_required` |
| Unknown or deleted tenant | 404 `tenant_not_found` |
| Status not in `Options.AllowedStatuses` (default: `active`) | 403 `tenant_inactive` |
| Token tenant differs from the subdomain/header/path tenant | 403 `tenant_mismatch` |
| Invalid Tenarium token (bad signature, expired, wrong audience) | 401 |
| Feature missing (`RequireFeature`) | 403 `feature_disabled` |
| Source failure | 503 (details not exposed) |

Override the response format with `Options.ErrorHandler`; `tenantmw.StatusCode(err)`
maps errors to status codes.

- **Tokens.** `FromToken` verifies ES256 tokens against Tenarium's JWKS (iss, aud
  `tenarium`, exp/nbf). Keys are cached for `KeysTTL` (1h) and fetched again when a
  token has an unknown `kid`, at most once per `MinRefreshInterval` (30s). Bearer
  values that are not JWTs (API keys) or come from another issuer are ignored.
  Platform tokens without `tid` do not resolve a tenant.
- **Mismatch rule.** When a token is present, resolution continues until it also
  knows the addressed tenant (first non-token match). If the two differ the request
  is refused, so a token for tenant A cannot act on tenant B's subdomain.
- **Sources.** `RedisSource` reads `<prefix>tenant:<id>` and
  `<prefix>tenant-slug:<slug>` written by the redis plugin's `cache` feature (it
  accepts any `redis.Cmdable`, including cluster clients). `APISource` calls
  `GET /v1/tenants/{id}` and `GET /v1/tenants/{id}/entitlements`.
  `CachingSource` adds a TTL cache with negative caching (`SetNegativeTTL`), merges
  concurrent misses into one load, and has `Invalidate`/`Purge`. Entries are keyed
  by the reference as given (ID or slug).
- **Custom domains.** `FromCustomDomain` calls `GET /v1/domains/resolve?host=` via
  `Client`. Wrap the client in `CachingDomains` so a lookup does not run on every
  request.

## Tests

```sh
go test ./pkg/tenantmw/
TENARIUM_TEST_REDIS_ADDR=localhost:6379 go test ./pkg/tenantmw/   # with the Redis integration test
```
