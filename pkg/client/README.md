# pkg/client: Go client for the Tenarium API

`github.com/AimTune/tenarium/pkg/client` is the official Go client for the
Tenarium REST API. It uses only the standard library and the `pkg/sdk` model
types (`sdk.Tenant`, `sdk.Plan`, `sdk.Member`, `sdk.User`, `sdk.Event`,
`sdk.Entitlements`, `sdk.Principal`).

```go
c, err := client.New("https://tenarium.example.com",
	client.WithAPIKey(os.Getenv("TENARIUM_API_KEY")),
	client.WithRetry(3, 200*time.Millisecond),
)

t, err := c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "acme", Name: "Acme"})
t, err = c.Tenants.Update(ctx, "acme",
	client.UpdateTenantRequest{Plan: client.Ptr("pro")},
	client.IfMatch(t.Version)) // 412 -> client.IsVersionConflict(err)

for t, err := range c.Tenants.All(ctx, client.TenantListOptions{Status: sdk.StatusActive}) {
	if err != nil { return err }
	fmt.Println(t.Slug)
}
```

## Options

| Option | Purpose |
|---|---|
| `WithAPIKey(key)` / `WithToken(tok)` | Static bearer credentials |
| `WithTokenSource(p)` | Any `TokenProvider`; a `Reauthenticator` gets one refresh and retry on 401 |
| `WithHTTPClient(hc)` | Custom transport, timeouts, proxies |
| `WithUserAgent(ua)` | User-Agent header |
| `WithRetry(max, backoff)` | Retry network errors, 502/503/504, and 429 that carries `Retry-After` |

Retries only apply to requests that are safe to repeat: GET, HEAD, PUT,
DELETE and OPTIONS, plus POSTs that carry an `Idempotency-Key`. When retries
are on, `Create` calls (and `Members.Add`, `Usage.Record`) get an
automatic key, so the server replays the first response instead of creating
a duplicate.

Per-call options: `IfMatch(version)`, `WithIdempotencyKey(key)` and
`WithHeader(k, v)`. `c.With(opts...)` derives a client with different
options, for example with other credentials.

## Services

| Service | Methods |
|---|---|
| `c.Tenants` | `Create Get List All Update Delete Suspend Resume RetryProvisioning Children AllChildren Entitlements` |
| `c.Members` | `List Add Get Update Remove` |
| `c.Usage` | `Get Record` |
| `c.Plans` | `List Create Get Update Delete` |
| `c.Users` | `List All Create Get Update Delete Disable Enable SetPassword ResendInvitation RevokeSessions Memberships` |
| `c.Auth` | `Login Refresh Logout RequestPasswordReset ConfirmPasswordReset AcceptInvitation` |
| `c.Events` | `List All Tail LastSeq` |
| `c.DeadLetters` | `List Get Replay Discard` |
| `c.Plugins` | `List` |
| `c` | `Me MyMemberships ChangeMyPassword Do` |

Tenant arguments accept an ID or a slug. User arguments accept an ID or an
email address.

## Errors

Non-2xx responses are returned as `*client.Error`, which has the fields
`Status`, `Code`, `Message`, `Field`, `RequestID` and `RetryAfter`.

```go
_, err := c.Usage.Record(ctx, "acme", "api_calls", 1)
switch {
case client.IsQuotaExceeded(err): // 429 quota_exceeded; Field is the metric
case client.IsVersionConflict(err): // 412
case client.IsNotFound(err), client.IsConflict(err), client.IsForbidden(err), client.IsUnauthorized(err):
}
if e, ok := client.AsError(err); ok {
	log.Printf("%s (request %s)", e.Code, e.RequestID)
}
```

## User login and token refresh

```go
pub, _ := client.New(url)
pair, err := pub.Auth.Login(ctx, client.LoginRequest{Email: e, Password: p, Tenant: "acme"}) // Tenant is optional
ts := client.NewTokenSource(pub.Auth, pair,
	client.OnRefresh(func(p client.TokenPair) { save(p) })) // refresh tokens rotate; persist them
c := pub.With(client.WithTokenSource(ts))
```

`TokenSource` refreshes the access token shortly before it expires. If the
server rejects a token with 401, it refreshes once and retries the request.
Refreshes are serialized, so a rotated refresh token is never reused. Reusing
one would make the server revoke the session.

## Events

```go
// Print every new tenant event until ctx is cancelled.
last, _ := c.Events.LastSeq(ctx)
err := c.Events.Tail(ctx, last, func(e sdk.Event) error {
	fmt.Println(e.Seq, e.Type, e.TenantID)
	return nil
}, client.TailType("tenant.*"), client.TailInterval(time.Second))
```

## Adding endpoints

Each resource group is a small service struct that holds the `*Client`. Its
methods call the unexported `c.do(ctx, method, path, query, body, &out, opts...)`.
To add a resource (for example audit log, API keys, domains or webhooks):

1. Define the request structs, using pointer fields for partial updates.
2. Add a `FooService` with methods that follow the existing ones. Return a
   `Page[T]` from `List`, and use `paginate` to build an `All` iterator.
3. Register the service in `Client.bind()`.

Until a typed method exists, `c.Do(ctx, method, path, query, in, &out)` calls
any endpoint.

## Tests

`go test ./pkg/client/` runs end-to-end against a real in-process server
(`pkg/server`, memory store). A fault-injecting reverse proxy covers the
retry behaviour.
