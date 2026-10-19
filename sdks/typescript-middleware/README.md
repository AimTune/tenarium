# @tenarium/middleware

Resolve and enforce the current Tenarium tenant in Node.js applications. The
package has no dependencies and runs on Node 22.6+ (the TypeScript sources run
directly). The core is framework-agnostic, and adapters are included for
Express/Connect and plain `node:http`.

## Usage

```ts
import {
  Client, Resolver, Verifier, UsageRecorder, QuotaExceededError,
  cachingDomains, cachingSource, redisSource, apiSource,
  fromToken, fromSubdomain, fromHeader, fromPathPrefix, fromCustomDomain,
  tenantMiddleware, requireFeature, withTenant, resolveTenant, hasFeature, limitOf,
} from "@tenarium/middleware";

const api = new Client("https://tenarium.example.com", process.env.TENARIUM_API_KEY!);
const verifier = await Verifier.discover("https://tenarium.example.com");

const opts = {
  // Tried in order, first match wins.
  resolver: new Resolver(
    fromToken(verifier),                        // tid claim of a Tenarium access token
    fromSubdomain("app.example.com"),           // acme.app.example.com -> "acme"
    fromHeader("X-Tenant-ID"),                  // ID or slug
    fromPathPrefix(),                           // /t/acme/...
    fromCustomDomain(cachingDomains(api, 300_000)),
  ),
  // The redis plugin's cache through any client with get(key) (ioredis, node-redis),
  // or apiSource(baseUrl, apiKey) / the Client itself.
  source: cachingSource(redisSource(redis, "tenarium:"), 30_000),
};

// Express / Connect
app.use(tenantMiddleware(opts));
app.get("/reports", requireFeature("reports"), (req, res) => {
  res.json({ tenant: req.tenant.slug, seats: limitOf(req.tenant, "seats") }); // undefined = unlimited
});

// node:http
http.createServer(withTenant(opts, (req, res, { tenant, claims }) => {
  res.end(`hello ${tenant?.slug}`);
}));

// Anything else (fetch Request, custom frameworks): the core throws TenantError.
const { tenant } = await resolveTenant(request, opts);

// Metered usage
try {
  await new UsageRecorder(api).record(tenant.id, "api_calls", 1);
} catch (err) {
  if (err instanceof QuotaExceededError) { /* 429 */ }
}
```

## Behaviour

| Situation | Status / code |
|---|---|
| No tenant reference (unless `optional: true`) | 404 `tenant_required` |
| Unknown or deleted tenant | 404 `tenant_not_found` |
| Status not in `allowedStatuses` (default `["active"]`) | 403 `tenant_inactive` |
| Token tenant differs from the subdomain, header or path tenant | 403 `tenant_mismatch` |
| Invalid Tenarium token | 401 `unauthorized` |
| `requireFeature` and the feature is off | 403 `feature_disabled` |
| Source or API failure | 503 `tenant_unavailable` (no details exposed) |

- **Tokens.** ES256 tokens are verified with `node:crypto` against the JWKS (iss,
  aud `tenarium`, exp, nbf, 30 s leeway). Keys are cached for 1 h and fetched again
  when a token has an unknown `kid` (at most once every `minRefreshIntervalMs`).
  Bearer values that are not JWTs, or that come from another issuer, are ignored.
- **Mismatch rule.** When a token is present, resolution keeps going until the
  addressed tenant (the first non-token match) is also known. If the two differ,
  the request is refused.
- **Caching.** `cachingSource` / `cachingDomains` are in-memory TTL caches. They
  cache unknown tenants as well (`negativeTtlMs`, set it to 0 to turn that off),
  merge concurrent misses into one load, and never cache errors.
  `invalidate(ref)` and `clear()` drop entries.

## Tests

```sh
node --test "sdks/typescript-middleware/test/*.test.ts"
```
