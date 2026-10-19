# Go client and tenariumctl

Two tools call the [REST API](api.md) from outside the server:

- `github.com/AimTune/tenarium/pkg/client` is a Go client that uses only the standard library
  and the `pkg/sdk` model types (`sdk.Tenant`, `sdk.Plan`, `sdk.Member`, `sdk.User`,
  `sdk.Event`, `sdk.Entitlements`, `sdk.Principal`).
- `tenariumctl` is a command-line client built on it.

For resolving the current tenant inside your own application's request handlers, see
[Tenant middleware](middleware.md) instead.

## Go client

### Construction and authentication

```go
import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
)

c, err := client.New("https://tenarium.example.com",
	client.WithAPIKey(os.Getenv("TENARIUM_API_KEY")),
	client.WithRetry(3, 200*time.Millisecond),
)
```

`New` accepts an `http://` or `https://` base URL. A `*Client` has no global state and is
safe for concurrent use. Every method takes a `context.Context`.

| Option | Purpose |
|---|---|
| `WithAPIKey(key)` | Static API key, sent as `Authorization: Bearer <key>` |
| `WithToken(tok)` | Static bearer token, for example an access token from an external IdP |
| `WithTokenSource(p)` | Any `TokenProvider`. If it also implements `Reauthenticator`, a 401 triggers one refresh and retry |
| `WithHTTPClient(hc)` | Custom `*http.Client` (timeouts, transport, proxies). Default: `http.DefaultClient` |
| `WithUserAgent(ua)` | User-Agent header (default `tenarium-go-client/1`) |
| `WithRetry(max, backoff)` | Retry policy, see below. Off by default |

`c.With(opts...)` returns a copy with more options applied, for example the same server with
other credentials. `c.BaseURL()` returns the server URL.

### Retries and idempotency

With `WithRetry(max, backoff)`, a failed request is retried up to `max` more times. The client
waits with exponential backoff and jitter, starting at `backoff` and capped at 30s. A
`Retry-After` header from the server overrides the computed delay. These failures are retried:

- network errors;
- 502, 503 and 504;
- 429 if the response carries `Retry-After`.

Only requests that are safe to repeat are retried: GET, HEAD, PUT, DELETE and OPTIONS, and
POSTs that carry an `Idempotency-Key`. When retries are on, `Create` calls, `Members.Add` and
`Usage.Record` get a random key automatically, so a retried POST makes the server replay the
first response instead of creating a duplicate.

Per-call options:

| Call option | Effect |
|---|---|
| `IfMatch(version)` | Sends `If-Match: "<version>"`. The call fails with 412 if the resource changed |
| `WithIdempotencyKey(key)` | Sends your own `Idempotency-Key` (also makes the POST retryable) |
| `WithHeader(k, v)` | Adds a header to this call |

```go
t, err := c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "acme", Name: "Acme", Plan: "free"},
	client.WithIdempotencyKey("signup-4711"))
if err != nil {
	return err
}
t, err = c.Tenants.Update(ctx, "acme",
	client.UpdateTenantRequest{Plan: client.Ptr("pro")},
	client.IfMatch(t.Version))
if client.IsVersionConflict(err) {
	// reload and try again
}
```

Update requests use pointer fields, and only the fields you set are sent. Use `client.Ptr(v)`
to set one. For `Labels`, `Features` and `Limits`, the value you send replaces the whole map.

### Services

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

Tenant arguments take an ID or a slug. User arguments take an ID or an email address.
`c.Do(ctx, method, path, query, in, &out)` calls any endpoint that has no typed method yet,
with the same authentication, retries and error handling.

### Pagination

`List` methods return one `client.Page[T]` with `Items` and a `Next` cursor, which is empty on
the last page. Pass `Next` back as `After` to get the following page. `All` methods return an
`iter.Seq2[T, error]` that follows the cursors for you. Iteration stops after the first error,
which the iterator yields once.

```go
for t, err := range c.Tenants.All(ctx, client.TenantListOptions{Status: sdk.StatusActive, Plan: "pro"}) {
	if err != nil {
		return err
	}
	fmt.Println(t.Slug, t.Version)
}

users, err := client.Collect(c.Users.All(ctx, client.UserListOptions{Query: "example.com"}))
```

`TenantListOptions` filters by `Status`, `Plan`, `ParentID`, `Labels` and `IncludeDeleted`, and
takes `After` and `Limit` (page size; the server default when 0).

### Errors

Non-2xx responses are returned as `*client.Error`, with the fields `Status`, `Code` (for
example `not_found`, `version_conflict`, `quota_exceeded`, `validation_failed`), `Message`,
`Field`, `RequestID` (the server's `X-Request-ID`) and `RetryAfter`.

```go
_, err := c.Usage.Record(ctx, "acme", "api_calls", 1)
switch {
case client.IsQuotaExceeded(err): // 429 quota_exceeded; Error.Field is the metric
case client.IsNotFound(err): // 404
case client.IsConflict(err): // 409: already exists, invalid state transition
case client.IsVersionConflict(err): // 412: IfMatch version is stale
case client.IsValidation(err): // 400 validation_failed
case client.IsForbidden(err), client.IsUnauthorized(err):
}
if e, ok := client.AsError(err); ok {
	log.Printf("%s: %s (request %s)", e.Code, e.Message, e.RequestID)
}
```

### User login and token refresh

`c.Auth` calls the public `/v1/auth` endpoints and never sends the client's own credentials.
`TokenSource` holds a token pair and implements `Reauthenticator`.

```go
pub, err := client.New("https://tenarium.example.com")
if err != nil {
	return err
}
pair, err := pub.Auth.Login(ctx, client.LoginRequest{
	Email: email, Password: password,
	Tenant: "acme", // optional: a tenant-scoped session; empty = platform session
})
if err != nil {
	return err
}
ts := client.NewTokenSource(pub.Auth, pair,
	client.OnRefresh(func(p client.TokenPair) { save(p) }), // refresh tokens rotate: persist them
)
c := pub.With(client.WithTokenSource(ts))
me, err := c.Me(ctx)
```

- The access token is refreshed shortly before it expires: 30s before by default
  (`WithRefreshSkew`), and at most half of the token's lifetime before.
- If the server answers 401, the source refreshes once and the request is retried.
- Refreshes are serialized. Reusing a rotated refresh token would make the server revoke the
  session, and serialization prevents that. `OnRefresh` runs while the source is locked, so
  keep it short.
- `ts.Pair()` returns the current pair and `ts.Refresh(ctx)` forces a refresh. A refresh
  without a refresh token fails with `client.ErrNoRefreshToken`.
- `c.Auth.Logout(ctx, refreshToken)` revokes the session.

### Events

```go
// Print every new tenant event until ctx is cancelled.
last, err := c.Events.LastSeq(ctx)
if err != nil {
	return err
}
err = c.Events.Tail(ctx, last, func(e sdk.Event) error {
	fmt.Println(e.Seq, e.Type, e.TenantID)
	return nil
}, client.TailType("tenant.*"), client.TailInterval(time.Second))
```

`Tail` reads all events after the given sequence number and then polls for new ones every
`TailInterval` (default 1s). It stops when the context ends or the callback returns an error.
`TailTenant(id)` limits it to one tenant. `c.DeadLetters` lists, inspects, replays and
discards dead-lettered deliveries.

## tenariumctl

### Install

```sh
go install github.com/AimTune/tenarium/cmd/tenariumctl@latest
tenariumctl --version
```

General form: `tenariumctl [global flags] <command> <verb> [args] [flags]`. Run
`tenariumctl help`, `tenariumctl <command> --help` or `tenariumctl <command> <verb> --help` for
the flags of each command.

### Login and profiles

```sh
# User login. The password is prompted for; tokens are stored and refreshed automatically.
tenariumctl login --url https://tenarium.example.com --email admin@example.com

# Non-interactive, scoped to one tenant.
echo "$PASSWORD" | tenariumctl login --url http://localhost:8080 \
  --email ada@example.com --tenant acme --password-stdin

# Verify an API key and store it in a separate profile.
tenariumctl --profile ci login --url http://localhost:8080 --api-key "$TENARIUM_API_KEY"

tenariumctl me                          # show the authenticated caller
tenariumctl config list                 # * marks the current profile
tenariumctl config use-profile default
tenariumctl config delete-profile ci    # forgets credentials, does not revoke the session
tenariumctl config path
tenariumctl logout                      # revokes the session and forgets the tokens
```

`login` saves the profile and makes it the current one. On a terminal, the password prompt
turns echo off through `stty` where that is available (not on Windows). Otherwise the input is
visible. Use `--password-stdin` in scripts.

Profiles are stored as JSON in `<user config dir>/tenarium/config.json`, written atomically with
mode 0600:

| OS | User config dir |
|---|---|
| Linux and other Unix | `$XDG_CONFIG_HOME` or `~/.config` |
| macOS | `~/Library/Application Support` |
| Windows | `%APPDATA%` |

`TENARIUM_CONFIG` overrides the path. A profile holds the URL and either an API key or a user's
token pair. Refreshed tokens are written back to the file. Stored tokens are only used when the
server URL in effect is the profile's URL.

### Settings and environment

Each setting is taken from the first of:

1. flags: `--url`, `--api-key`, `--token`, `--profile`;
2. environment: `TENARIUM_URL`, `TENARIUM_API_KEY`, `TENARIUM_TOKEN`, `TENARIUM_PROFILE`;
3. the active profile (`--profile`, `TENARIUM_PROFILE`, the config's current profile, or
   `default`).

| Global flag | Meaning |
|---|---|
| `--url URL` | Server URL |
| `--api-key KEY` | API key |
| `--token TOKEN` | Bearer access token |
| `-o`, `--output table\|json` | Output format (default `table`) |
| `--profile NAME` | Config profile |
| `--version` | Print the version |

Global flags work before the command and after the verb (`tenariumctl tenants list -o json`).
Requests use a 60s timeout and are retried twice on transient failures, using the client's
retry rules.

### Commands

| Command | Verbs |
|---|---|
| `tenants` | `list get create update delete suspend resume retry-provisioning children entitlements` |
| `members` | `list add remove set-role` (members by ID or email) |
| `usage` | `get record` |
| `plans` | `list get create update delete` |
| `users` | `list get create disable enable delete set-password invite` |
| `events` | `list tail` |
| `dead-letters` | `list get replay discard` |
| `plugins` | `list` |
| `me`, `login`, `logout`, `config` | |

```sh
tenariumctl tenants create --slug acme --name "Acme Inc" --plan pro --label region=eu
tenariumctl tenants list --status active --label region=eu
tenariumctl tenants update acme --name "Acme Corp" --if-match 3   # version_conflict if stale
tenariumctl tenants suspend acme --reason "unpaid invoice"
tenariumctl tenants entitlements acme

tenariumctl plans create --id pro --name Pro --feature sso --quota members=50
tenariumctl members add acme --email ada@example.com --role admin
tenariumctl members set-role acme ada@example.com viewer
tenariumctl usage record acme api_calls 10
tenariumctl usage record acme api_calls --delta -5
tenariumctl usage get acme

echo "$PW" | tenariumctl users create --email bot@example.com --password-stdin
tenariumctl users invite new.hire@example.com --name "New Hire"

tenariumctl events list --tenant acme --type 'tenant.*'
tenariumctl events tail --type 'tenant.*'          # follow new events; Ctrl-C to stop
tenariumctl events tail --from-start --max 10 -o json

tenariumctl dead-letters list --subscription kafka/publish
tenariumctl dead-letters replay <id> [<id>...]
```

On `update`, repeatable flags such as `--label`, `--feature` and `--quota` replace the whole
map. `tenants update --clear-labels` removes all labels, and `--settings` takes a JSON merge
patch.

### Output and exit codes

`table` output is aligned with `text/tabwriter`. `json` pretty-prints the API objects.
`events tail -o json` writes one JSON object per line.

| Exit code | Meaning |
|---|---|
| 0 | success, including `--help` |
| 1 | API, network or configuration error |
| 2 | usage error: unknown command, bad flags, missing arguments |

API errors are printed to stderr as `error: <code>: <message> [HTTP <status>]`.
