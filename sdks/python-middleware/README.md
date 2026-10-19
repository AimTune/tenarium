# tenarium-middleware (Python)

`tenarium_middleware` resolves and enforces the current Tenarium tenant in WSGI
apps (Flask, Django, ...) and ASGI apps (Starlette, FastAPI, ...). It needs
Python 3.9+ and uses only the standard library.

## Usage

```python
from tenarium_middleware import (
    ApiClient, CachingDomains, CachingSource, Resolver, TenantASGIMiddleware, TenantMiddleware,
    TokenVerifier, UsageRecorder, QuotaExceeded, current_tenant, require_feature, redis_source,
    from_token, from_subdomain, from_header, from_path_prefix, from_custom_domain,
)

api = ApiClient("https://tenarium.example.com", API_KEY)

resolver = Resolver(                      # tried in order, first match wins
    from_token(verifier),                 # tid claim of a Tenarium access token (see below)
    from_subdomain("app.example.com"),    # acme.app.example.com -> "acme"
    from_header("X-Tenant-ID"),           # ID or slug
    from_path_prefix(),                   # /t/acme/...
    from_custom_domain(CachingDomains(api, ttl=300)),
)
# The redis plugin's cache through any client with .get() (e.g. redis.Redis),
# or the ApiClient itself / api_source(base_url, api_key).
source = CachingSource(redis_source(redis.Redis(), "tenarium:"), ttl=30)

wsgi_app = TenantMiddleware(flask_app.wsgi_app, resolver, source)  # WSGI
asgi_app = TenantASGIMiddleware(starlette_app, resolver, source)   # ASGI

@require_feature("reports")            # 403 feature_disabled unless enabled
def reports():
    t = current_tenant()                # also environ["tenarium.tenant"] / request.state.tenant
    return {"tenant": t.slug, "seats": t.limit("seats")}  # None = unlimited

try:
    UsageRecorder(api).record(current_tenant().id, "api_calls", 1)
except QuotaExceeded:
    ...  # 429
```

### Verifying tokens

Tenarium signs access tokens with ES256, and the standard library cannot verify
ECDSA. `TokenVerifier` therefore takes a `decode(token) -> claims` callback that
checks the signature against Tenarium's JWKS. It then checks `iss`, `aud`
(`tenarium`), `exp` and `nbf` itself. With PyJWT (`pip install "pyjwt[crypto]"`):

```python
import jwt

jwks = jwt.PyJWKClient("https://tenarium.example.com/.well-known/jwks.json")

def decode(token):
    key = jwks.get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=["ES256"], audience="tenarium")

verifier = TokenVerifier("https://tenarium.example.com", decode)
```

jwcrypto works too: `json.loads(JWT(jwt=token, key=jwkset, algs=["ES256"]).claims)`.
Bearer values that are not JWTs, or whose unverified `iss` belongs to another
issuer, are ignored without calling `decode`. If `decode` raises, the request
gets 401. `check_claims(claims, issuer)` is also available on its own.

## Behaviour

| Situation | Status / code |
|---|---|
| No tenant reference (unless `optional=True`) | 404 `tenant_required` |
| Unknown or deleted tenant | 404 `tenant_not_found` |
| Status not in `allowed_statuses` (default `("active",)`) | 403 `tenant_inactive` |
| Token tenant differs from the subdomain, header or path tenant | 403 `tenant_mismatch` |
| Invalid Tenarium token | 401 `unauthorized` |
| `require_feature` and the feature is off | 403 `feature_disabled` |
| Source or API failure | 503 `tenant_unavailable` (no details exposed) |

- `resolve_tenant(Request(...), resolver, source)` is the framework-agnostic core.
  It raises `TenantError` (`.status`, `.code`, `.body()`). `Request.from_wsgi(environ)`
  and `Request.from_asgi(scope)` build its input.
- `CachingSource` / `CachingDomains` are thread-safe TTL caches. They cache unknown
  tenants as well (`negative_ttl`, set it to 0 to turn that off), merge concurrent
  misses into one load, never cache exceptions, and offer `invalidate()` / `clear()`.
- Sources are synchronous. The ASGI middleware calls them in a worker thread.
- `require_feature` raises `TenantError`. Both middlewares turn it into a response
  as long as the app has not started responding yet.

## Tests

```sh
python -m unittest discover -s sdks/python-middleware/tests -v
```
