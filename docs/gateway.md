# Gateway integration

`tenarium-gateway` is a small forward-auth service for API gateways. Envoy, NGINX and Traefik
call it before they proxy a request. It works out which tenant the request belongs to, checks
that tenant's status, required features and rate limit, and tells the proxy two things: whether
the request may proceed, and which **cell** (deployment) serves the tenant. The proxy then
routes on that answer.

```
client ──► proxy ──(check)──► tenarium-gateway ──► Redis cache / Tenarium API
             │  ◄── 200 + X-Tenant-* / 403 / 404 / 429
             └──► cell chosen by X-Tenant-Cell (eu-1, dedicated, shared, ...)
```

The service is built on [`pkg/tenantmw`](middleware.md), so resolution, sources, caching,
status handling and the token mismatch rule work exactly as they do in the middleware. The
reusable parts are in `pkg/gateway`, and `cmd/tenarium-gateway` is the standalone binary.
Example proxy configurations are in [`deploy/gateway/`](https://github.com/AimTune/tenarium/tree/main/deploy/gateway).

## Endpoints

| Path | Used by | Original request taken from | Denial status |
|---|---|---|---|
| `/envoy/...` | Envoy `ext_authz` (HTTP service) | method, `Host`, path after `/envoy` (+ query) | real (401/403/404/429/503) |
| `/nginx` | NGINX `auth_request` | `X-Original-Method`, `X-Original-Host` (or `X-Forwarded-Host`), `X-Original-URI` | 401 or 403, real status in `X-Tenarium-Status` |
| `/traefik` | Traefik `ForwardAuth` | `X-Forwarded-Method`, `X-Forwarded-Host`, `X-Forwarded-Uri`, `X-Forwarded-Proto` | real |
| `/check/...` | any of the above | `X-Forwarded-*`, then `X-Original-*`, then the Envoy shape | real |
| `/healthz` | liveness | | |
| `/readyz` | readiness (pings Redis when it is used) | | |
| `/metrics` | Prometheus | | |

The check request's own headers, such as `Authorization` and `X-Tenant-ID`, count as the
original request's headers. Each protocol endpoint reads only the forwarding headers its proxy
sets. The Envoy endpoint, for example, ignores `X-Forwarded-Host`, so a client cannot address
another tenant by sending one. Use `/check` only where the proxy overwrites the headers it
reads. The gateway endpoints skip `http.ServeMux` path cleaning, so a path like
`/envoy//a/../b` reaches the check unchanged.

### How each proxy describes the original request

- **Envoy `ext_authz`, HTTP service mode.** The check request keeps the original method and
  `Host`. Its path is `path_prefix` followed by the original path and query, so
  `path_prefix: /envoy` turns `GET /api/items?x=1` into `GET /envoy/api/items?x=1`.
  `allowed_headers` chooses which request headers are sent, and it must include
  `authorization` when tokens are used. On 200, Envoy copies the response headers matched by
  `authorization_response.allowed_upstream_headers` onto the upstream request, replacing any
  existing values. Any other status is returned to the client together with the body and the
  headers matched by `allowed_client_headers`.
- **NGINX `auth_request`.** A subrequest goes to an `internal` location that `proxy_pass`es to
  `/nginx`. NGINX does not tell the auth server what the original request was, so the
  configuration sets `X-Original-URI $request_uri`, `X-Original-Method $request_method`,
  `X-Original-Host $host` and, optionally, `X-Original-Proto $scheme`. The other request
  headers are passed by default. `auth_request` accepts only 2xx, 401 and 403 and turns
  anything else into a 500. In NGINX mode the gateway therefore sends 404, 429 and 503 as
  403 and puts the real code in `X-Tenarium-Status`, which a named location turns back into
  the right status (see below). The configuration reads response headers with
  `auth_request_set $var $upstream_http_<name>`.
- **Traefik `ForwardAuth`.** Traefik sends a `GET` to `address` with the client's headers plus
  `X-Forwarded-Method`, `X-Forwarded-Proto`, `X-Forwarded-Host` and `X-Forwarded-Uri`. Keep
  `trustForwardHeader: false` so that Traefik sets these headers itself instead of passing on
  values from the client. On 2xx, the headers listed in `authResponseHeaders` are copied onto
  the forwarded request, and Traefik first removes any client-supplied value. Any other
  status is returned to the client as it is, including the body, `Retry-After` and
  `RateLimit-*`.

## Responses

**Allowed (200, empty body).** The response carries these headers for the upstream request:

| Header | Value |
|---|---|
| `X-Tenant-Id` | tenant ID |
| `X-Tenant-Slug` | tenant slug |
| `X-Tenant-Plan` | plan ID (may be empty) |
| `X-Tenant-Cell` | the tenant's cell (see [Cells](#cells)) |
| `X-Tenant-Features` | enabled features, sorted and comma separated, when `expose_features` is on |
| `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `RateLimit-Policy` | rate limit state, when a limit applies |

All five `X-Tenant-*` headers are always sent, even when a value is empty, so a proxy that
overwrites request headers also clears any values the client sent. Configure the proxy to
copy them; the examples do. Applications behind the proxy can trust these headers only if
the proxy is the sole way in.

**Denied.** The body is a Tenarium-style JSON error,
`{"error":{"code":"...","message":"..."}}`, sent with `X-Tenarium-Error: <code>` and
`X-Tenarium-Status: <real status>`:

| Situation | Status | Code |
|---|---|---|
| No tenant in the request (and `optional` off) | 404 | `tenant_required` |
| Unknown or deleted tenant | 404 | `tenant_not_found` |
| Status not allowed (default: only `active`) | 403 | `tenant_inactive` |
| Token tenant differs from the addressed tenant | 403 | `tenant_mismatch` |
| Invalid Tenarium token | 401 | `unauthorized` |
| A matching feature rule's feature is off | 403 | `feature_disabled` |
| Rate limit exceeded or zero | 429 | `rate_limited` (with `Retry-After` and `RateLimit-*`) |
| Malformed original URI | 400 | `bad_request` |
| Source failure (Redis, API) | 503 | `tenant_unavailable` (no details exposed) |
| Limiter failure with `fail_open: false` | 503 | `rate_limit_unavailable` |

In NGINX mode, every status except 401 and 403 is sent as 403.

## Cells

`X-Tenant-Cell` tells the proxy where the tenant lives. The first non-empty answer from this
list wins:

1. the tenant label named by `cell.label` (default `cell`), for example
   `tenariumctl tenants update acme --label cell=eu-1`;
2. `cell.plans[<plan>]`, for example `enterprise: dedicated`;
3. `cell.default` (default `default`).

Cell names must match `[A-Za-z0-9._-]{1,63}` because proxies use them in routing decisions. A
label with any other value is ignored and logged, and the default cell is used. In Go,
`CellOptions.Func` can compute the cell from anything on the tenant. Labels come with the
tenant from both sources: the redis plugin caches them, and the API returns them.

Routing on the cell:

- **Envoy:** add one route per cell with a header matcher, plus a catch-all route for the
  default cell. Set `clear_route_cache: true` on `ext_authz`. Envoy picks a route before
  filters run, and this setting makes it pick again once `X-Tenant-Cell` has been set.

  ```yaml
  routes:
    - match: { prefix: "/", headers: [{ name: x-tenant-cell, string_match: { exact: eu-1 } }] }
      route: { cluster: cell_eu_1 }
    - match: { prefix: "/" }
      route: { cluster: cell_shared }
  ```

  For many cells, `cluster_header: x-tenant-cell` routes to a cluster with the same name as
  the cell and needs no per-cell routes.
- **NGINX:** capture the header with `auth_request_set $tenant_cell
  $upstream_http_x_tenant_cell`, map it to an upstream name, and `proxy_pass` to the result:

  ```nginx
  map $tenant_cell $cell_upstream { default cell_shared; eu-1 cell_eu_1; dedicated cell_dedicated; }
  location / { auth_request /_tenarium_auth; ...; proxy_pass http://$cell_upstream; }
  ```

  If `proxy_pass` names an upstream through a variable, the upstream has to be defined as an
  `upstream` block. Otherwise NGINX needs a `resolver`.
- **Traefik:** Traefik matches routers before it runs middlewares, so a router on the public
  entrypoint never sees `X-Tenant-Cell`. The example uses two hops inside one Traefik. The
  `edge` router on the public `web` entrypoint runs the ForwardAuth middleware and forwards
  to a loopback-only `cells` entrypoint. There, routers match
  ``Header(`X-Tenant-Cell`, `eu-1`)``, and a low-priority ``PathPrefix(`/`)`` catches the
  default cell. Clients cannot reach the second hop directly, and ForwardAuth has already
  replaced any `X-Tenant-*` headers they sent.

### NGINX: restoring the real status

```nginx
auth_request_set $tenarium_status $upstream_http_x_tenarium_status;
auth_request_set $tenarium_error  $upstream_http_x_tenarium_error;
auth_request_set $retry_after     $upstream_http_retry_after;
error_page 401 403 = @tenarium_denied;

location @tenarium_denied {
    default_type application/json;
    add_header Retry-After $retry_after always;
    if ($tenarium_status = 404) { return 404 '{"error":{"code":"$tenarium_error"}}\n'; }
    if ($tenarium_status = 429) { return 429 '{"error":{"code":"rate_limited"}}\n'; }
    if ($tenarium_status = 503) { return 503 '{"error":{"code":"$tenarium_error"}}\n'; }
    if ($tenarium_status = 401) { return 401 '{"error":{"code":"unauthorized"}}\n'; }
    return 403 '{"error":{"code":"$tenarium_error"}}\n';
}
```

## Rate limiting

Each tenant gets its own token bucket, keyed by tenant ID:

- **Rate:** the tenant's entitlement limit named `rate_limit.metric` (for example `rps`), in
  requests per `rate_limit.period` (default `1s`; use `1m` with an `rpm` limit). A value of
  `-1` (or any negative value) means unlimited, and `0` refuses every request. Tenants that
  do not have the limit get `default_rate`; a `default_rate` of 0 leaves them unlimited.
- **Burst:** the bucket size. It is the `burst_metric` limit if set, else `default_burst`,
  else one period's worth of requests.
- **Responses:** an allowed request carries `RateLimit-Limit` (burst), `RateLimit-Remaining`,
  `RateLimit-Reset` (seconds until the bucket is full) and
  `RateLimit-Policy: <rate>;w=<period seconds>;burst=<burst>`. A refused request gets 429
  with the same headers plus `Retry-After` (whole seconds, at least 1).

Add the limits to plans or tenant overrides like any other entitlement, for example
`limits: {rps: 50, rps_burst: 100}`. Changes reach the gateway as soon as the source cache
refreshes.

Backends:

| `rate_limit.backend` | Behavior |
|---|---|
| `off` (default) | no rate limiting |
| `local` | in-memory buckets in each replica (`gateway.LocalLimiter`). With N replicas behind a round-robin balancer, a tenant can get up to N times its rate. |
| `redis` | one shared bucket per tenant (`gateway.RedisLimiter`). GCRA runs in a Lua script: one key per tenant, one round trip per check, and Redis server time as the clock, so replica clock skew does not matter. Keys expire when the bucket is full again. |

`fail_open` (default `true`) lets requests through when the limiter fails, for example while
Redis is down, and increments `tenarium_gateway_limiter_errors_total`. Set it to `false` to
answer 503 instead.

Traefik does not pass the auth response's headers to the client on success, so `RateLimit-*`
appear only on 429s there. Envoy (`allowed_client_headers_on_success`) and NGINX (`add_header`
from `auth_request_set` variables) can return them on every response.

## Configuration

`tenarium-gateway -config gateway.yaml`. `${VAR}` references in the file are expanded from the
environment, and unknown keys are rejected. The full example is
[`deploy/gateway/gateway.yaml`](https://github.com/AimTune/tenarium/blob/main/deploy/gateway/gateway.yaml).

```yaml
listen: ":8090"
tenarium:
  url: http://tenarium:8080
  api_key: ${TENARIUM_API_KEY}     # default: $TENARIUM_API_KEY
source:
  type: redis                      # redis (plugin cache) | api; default redis if redis.addr is set
  cache_ttl: 30s
  negative_ttl: 5s
redis:
  addr: redis:6379
  prefix: "tenarium:"              # the redis plugin's key_prefix
resolve:                           # tried in order, first match wins
  - token: true                    # Tenarium access token (OpenID discovery on tenarium.url)
  - subdomain: app.example.com
  - header: X-Tenant-ID
  - path: /t/
  - custom_domain: true
allowed_statuses: [active]
cell: { label: cell, default: shared, plans: { enterprise: dedicated } }
expose_features: true
features:
  - { path_prefix: /api/reports, feature: reports }
  - { host: sso.example.com, feature: sso, methods: [GET, POST] }
rate_limit:
  backend: redis
  metric: rps
  burst_metric: rps_burst
  default_rate: 50
  fail_open: true
```

| Key | Default | Notes |
|---|---|---|
| `listen` / `metrics_listen` | `:8090` / unset | `metrics_listen` moves `/metrics` to its own address |
| `tenarium.url`, `api_key`, `timeout` | | `timeout` defaults to 5s. The URL is needed for `source.type: api`, `custom_domain` and `token` discovery. |
| `tenarium.jwks_url`, `issuer`, `audience` | | Skip OpenID discovery at startup. `issuer` must match the server's `users.public_url` or `auth.tokens.issuer`. Without them, discovery is retried with backoff until Tenarium answers. |
| `source.type` | `redis` if `redis.addr` is set, else `api` | |
| `source.cache_ttl`, `negative_ttl`, `max_entries`, `domain_cache_ttl` | 30s, 5s, 10000, 5m | A negative `cache_ttl` turns the in-memory cache off. |
| `redis.addr`, `username`, `password`, `db`, `tls`, `prefix` | prefix `tenarium:` | Shared by the source and the limiter. |
| `resolve` | required | Each entry sets exactly one of `token`, `subdomain`, `header`, `path`, `custom_domain`. |
| `allowed_statuses` | `[active]` | |
| `optional` | false | Requests without a tenant pass with empty tenant headers and the default cell. |
| `cell.label`, `cell.default`, `cell.plans` | `cell`, `default`, none | |
| `expose_features` | false | |
| `features[]` | | `host` (exact), `path_prefix`, `methods`, `feature` (required) |
| `rate_limit.*` | `backend: off` | `metric`, `burst_metric`, `period`, `default_rate`, `default_burst`, `fail_open`, `prefix` (`tenarium:gw:rl:`) |
| `log.level`, `log.format` | `info`, `json` | |
| `timeouts.read_header`, `idle`, `shutdown` | 5s, 2m, 15s | |

Flags override the file: `-config` (or `$TENARIUM_GATEWAY_CONFIG`), `-listen`, `-tenarium-url`,
`-redis-addr`, `-source`, `-rate-limit`, `-log-level`, and `-check-config`, which validates the
configuration and exits.

**Choosing a source.** In production, use the redis plugin's cache (`source.type: redis`):
each tenant load is one `GET`, or two for a slug. The API source makes two API calls per load
and needs an API key. Either way the in-memory cache sits in front. A tenant may be up to
`cache_ttl` stale, and that includes suspensions and limit changes.

## Metrics

| Metric | Labels |
|---|---|
| `tenarium_gateway_decisions_total` | `mode` (`check`, `envoy`, `nginx`, `traefik`), `decision` (`allow`, `deny`), `code` |
| `tenarium_gateway_check_duration_seconds` (histogram) | `mode`, `decision` |
| `tenarium_gateway_rate_limited_total` | |
| `tenarium_gateway_limiter_errors_total` | |

Go runtime and process collectors are registered too. Tenant IDs are not used as labels.

## Go API

```go
gw, err := gateway.New(gateway.Options{
	Resolver: tenantmw.NewResolver(tenantmw.FromToken(verifier), tenantmw.FromSubdomain("app.example.com")),
	Source:   tenantmw.CachingSource(tenantmw.RedisSource(rdb, ""), 30*time.Second),
	Cell:     gateway.CellOptions{Label: "cell", Default: "shared", Plans: map[string]string{"enterprise": "dedicated"}},
	Features: []gateway.FeatureRule{{PathPrefix: "/api/reports", Feature: "reports"}},
	RateLimit: gateway.RateLimitOptions{
		Limiter: gateway.NewRedisLimiter(rdb, ""), Metric: "rps", DefaultRate: 50, FailOpen: true,
	},
	Metrics: gateway.NewMetrics(prometheus.DefaultRegisterer),
})
http.ListenAndServe(":8090", gw) // /check, /envoy, /nginx, /traefik
```

- `gw.Check(ctx, gateway.Request{Method, Scheme, Host, URI, Header})` returns a `Result`
  (`Allowed`, `Status`, `Code`, `Tenant`, `Claims`, `Cell`, `Headers`, `RateLimit`). Use it to
  embed the decision in another protocol, such as a gRPC `ext_authz` server.
- `gateway.OriginalRequest(r, mode, prefix)` and `gateway.WriteResult(w, mode, res)` are the
  protocol adapters, and `gw.Handler(mode, prefix)` combines them.
- `gateway.Limiter` is the limiter interface. `NewLocalLimiter(gateway.WithClock(now))`
  accepts a clock for tests.

## Example deployments

`deploy/gateway/` contains:

- `gateway.yaml`: a gateway configuration covering every option;
- `envoy.yaml`: `ext_authz` with `path_prefix: /envoy`, header-matched routes per cell and
  `clear_route_cache`;
- `nginx.conf`: `auth_request`, `auth_request_set`, a `map` from cell to upstream, and the
  `@tenarium_denied` status restore;
- `traefik.yml` (static) and `traefik-dynamic.yml` (file provider): ForwardAuth and the
  two-hop cell routing.

All four were tested with Envoy 1.34, NGINX 1.27 and Traefik 3.3, using the Redis source and
the Redis limiter. The tests covered routing to all three cells, replacement of spoofed
`X-Tenant-*` headers, 403/404 denials, feature rules and 429s with `Retry-After`.

## Tests

```sh
go test ./pkg/gateway/ ./cmd/tenarium-gateway/
TENARIUM_TEST_REDIS_ADDR=localhost:6379 go test ./pkg/gateway/ -run Redis   # shared limiter
```

The unit tests cover each protocol shape, cells, feature rules, the limiter (with a fake clock)
and metrics. The end-to-end test runs the gateway against an `httptest` Tenarium API through
`APISource`, with token verification against a JWKS. It also includes a small forward-auth
proxy that routes to cell backends in both Traefik and NGINX styles.
