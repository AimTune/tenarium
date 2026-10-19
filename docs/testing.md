# Testing

Tenarium has six layers of tests. Unit, integration and admin UI tests run in CI on every change;
fuzzing, load and chaos tests are run by hand (or on a schedule) because they take long or need a
running server.

| Layer | Where | Command |
|---|---|---|
| Unit tests | next to the code | `make test` (`go test -short ./...`) |
| Integration tests | next to the code, enabled by env vars | `make test-db`, then `make test-integration` |
| Admin UI tests (Playwright) | `tests/ui` | `make test-ui` |
| Fuzz tests | `*_fuzz_test.go` | `go test -run '^$' -fuzz FuzzX ./pkg` |
| Load tests (k6) | `tests/load` | `k6 run tests/load/mixed.js` |
| Chaos / failover tests | `tests/chaos` | `go test -tags chaos ./tests/chaos` |

## Unit and integration tests

```sh
make test               # fast unit tests, in-memory store and fakes
make test-db            # throwaway PostgreSQL 17 on localhost:55432
make test-integration   # the full suite, including PostgreSQL (TENARIUM_TEST_POSTGRES_DSN)
make lint               # golangci-lint
```

Both stores pass the same conformance suite (`internal/store/storetest`). Plugins and other
integrations have tests against real services, skipped unless an environment variable points at
one. The common ones are listed in
[CONTRIBUTING.md](https://github.com/AimTune/tenarium/blob/main/CONTRIBUTING.md); every plugin
README lists its own (`TENARIUM_TEST_MYSQL_DSN`, `TENARIUM_TEST_OPENFGA_URL`, ...). Two that
belong to the core:

| Variable | Enables |
|---|---|
| `TENARIUM_TEST_VAULT_ADDR`, `TENARIUM_TEST_VAULT_TOKEN`, `TENARIUM_TEST_AWS_ENDPOINT` | [secrets](secrets.md) providers against a Vault dev server and LocalStack KMS |
| `TENARIUM_TEST_PEBBLE_URL`, `TENARIUM_TEST_PEBBLE_CA` | [ACME](tls.md) issuance against Pebble, with two managers sharing one store |

```sh
docker run -d --name tenarium-test-pebble -p 127.0.0.1:14000:14000 \
  -e PEBBLE_VA_ALWAYS_VALID=1 -e PEBBLE_WFE_NONCEREJECT=0 ghcr.io/letsencrypt/pebble
TENARIUM_TEST_PEBBLE_URL=https://localhost:14000/dir go test ./internal/certs -run Pebble -v
```

## Admin UI tests

[`tests/ui`](https://github.com/AimTune/tenarium/tree/main/tests/ui) drives the embedded admin UI
in Chromium with [Playwright](https://playwright.dev). The global setup starts a fake OpenID
provider and DNS ([`tests/ui/fakes`](https://github.com/AimTune/tenarium/tree/main/tests/ui/fakes)),
builds [`tests/ui/testserver`](https://github.com/AimTune/tenarium/tree/main/tests/ui/testserver)
(the server of `cmd/tenarium` with all plugins, except that domain-verification TXT lookups go to
the fake DNS), starts it on a free port with the in-memory store, a seeded platform admin, two
plans, two regions, sign-in links, passkeys, tenant SSO and a social login provider, and stops
both after the run. The browser opens the UI on `http://localhost:<port>`, which is also
`users.public_url`: passkeys need a domain name as relying party (not an IP address), and
Chromium treats localhost as a secure context. The tests go through the UI only:

- signing in with a password, a wrong password and an emailed link (read from the server log,
  since the default mailer logs emails); switching to Turkish and back;
- passkeys: registering one on the account page and signing in with it, using Chromium's virtual
  authenticator (CTAP2, internal transport, resident keys, user verification) added over CDP, and
  the message shown when the browser prompt fails;
- tenant SSO with OpenID Connect: adding a domain, a failed and a successful verification (the
  test publishes the TXT record to the fake DNS), a connection refused for an unverified email
  domain, then a round trip through the fake provider (which checks PKCE, client credentials and
  the redirect URI, and signs ID tokens with the request's nonce, its issuer and the client as
  audience) that provisions the user, and an unverified email refused;
- social login with an `oidc` provider pointing at the fake: the button round trip, the session
  taken from (and removed from) the URL fragment, and the messages for an unverified email and
  for a user with no tenant to sign in to;
- the dashboard, tenants made from a template with labels, branding, maintenance and health,
  members and API keys, plans and their revisions, rollouts, users and sessions, two-factor
  enrollment on the account page, the event, audit and dead-letter pages, and a 375px phone
  viewport, which must not scroll sideways;
- keyboard access: tenant, child tenant and user rows are reached with Tab and opened with Enter;
  event, event schema and audit rows show their details with Enter and Space (open details and
  focus survive the events page's live refresh).

The fake provider serves any number of issuers (`<fake>/<realm>`: one per SSO test, `social` for
the configured provider). Who signs in is set per browser context with a cookie (`signInAtIdP` in
`fakes/client.ts`), so tests stay independent and run in parallel. SAML is not driven in the
browser (a fake identity provider would have to sign XML assertions); `pkg/server/saml_test.go`
covers it.

A test fails on any console error, uncaught exception or 5xx answer in a page it visits.
Chromium's "Failed to load resource" messages for 4xx answers are ignored, since the UI probes
endpoints that are switched off or not allowed by design.

```sh
cd tests/ui
npm ci
npx playwright install chromium   # once; downloads the browser into the user cache
npx playwright test               # or `make test-ui` from the repository root
npx playwright test --ui          # pick and watch tests interactively
```

`TENARIUM_BIN=/path/to/testserver` skips the build and starts that binary instead: an absolute
path to a build of `./tests/ui/testserver` (with a plain `tenarium` binary the SSO test cannot
verify its domain). The UI is embedded, so rebuild after changing `internal/ui/static`. The server's config and log are kept in
`tests/ui/.server`. Tests share the server and run in parallel, so each one works on its own
uniquely named tenants, plans and users. Select by role, label and visible text; when the UI lacks
an accessible name for something, add one (a `<label>` or an `aria-label`) rather than selecting
by CSS class. When the `ui` job fails in CI, it uploads the HTML report, traces and the server log.

## Fuzz tests

Go native fuzz targets cover the code that parses untrusted input:

| Package | Targets |
|---|---|
| `internal/api` | `FuzzHandler` (the whole HTTP handler) |
| `internal/tenant` | `FuzzCreateTenant`, `FuzzCreatePlan`, `FuzzAddMember`, `FuzzMergePatch` |
| `internal/scim` | `FuzzFilter`, `FuzzPage`, `FuzzPatchUser` |
| `internal/identity` | `FuzzVerifyTOTP`, `FuzzHashRecoveryCode` |
| `internal/netguard` | `FuzzCheckAddr`, `FuzzCheckHost` (the SSRF guard) |
| `pkg/extplugin` | `FuzzDecodePrincipal`, `FuzzEventFromCloudEvent`, `FuzzHandler` |
| `plugins/external` | `FuzzInitResponse`, `FuzzRemoteReplies` |

`go test ./...` runs every target once over its seed corpus and `testdata/fuzz`. To fuzz, pick
one target at a time:

```sh
go test -run '^$' -fuzz '^FuzzCheckHost$' -fuzztime 5m ./internal/netguard
```

A failure writes the input to the package's `testdata/fuzz/<Target>/`; committing it there makes
it a regression test. Inputs for bugs that are not fixed yet are kept in
[`tests/fuzz/reproducers`](https://github.com/AimTune/tenarium/tree/main/tests/fuzz/reproducers)
instead, so the default test run stays green; its README lists each open finding and how to
reproduce it.

## Load tests (k6)

[`tests/load`](https://github.com/AimTune/tenarium/tree/main/tests/load) holds plain
[k6](https://k6.io) scripts: tenant CRUD, member adds, usage recording (the hot path, at a
constant arrival rate), event and audit paging, and `mixed.js` combining them. Each script
creates its own tenants in `setup()` and deletes them in `teardown()`, and fails when error rate
or latency thresholds are exceeded.

```sh
export TENARIUM_API_KEY=dev-key TENARIUM_ADMIN_PASSWORD='change-me-please'
go run ./cmd/tenarium -config config.example.yaml          # defines the plans and metric used

k6 run -e API_KEY=dev-key tests/load/scenarios/usage.js
k6 run -e API_KEY=dev-key -e VUS=50 -e RATE=500 -e DURATION=5m tests/load/mixed.js
```

Without a local k6, use the `grafana/k6` image. Thresholds (`P95_MS`, `P99_MS`,
`MAX_ERROR_RATE`) and the load shape are set with `-e`; the defaults are loose enough for the
in-memory store on a laptop. Run against PostgreSQL to measure lock contention (member limits
lock the tenant row, usage updates one counter row per tenant and period). The
[load test README](https://github.com/AimTune/tenarium/blob/main/tests/load/README.md) lists every
variable.

## Chaos and failover tests

[`tests/chaos`](https://github.com/AimTune/tenarium/tree/main/tests/chaos) runs several full
replicas in one process against a shared PostgreSQL database, each behind its own TCP proxy, and
breaks things while events flow:

- `TestLeaseHolderFailover` kills the replica holding the subscription lease (by cutting its
  database link and cancelling it, or only cancelling it) and checks that another replica takes
  over within `lease_ttl + lease_ttl/3 + 1s`, that every event is delivered at least once, and
  that no event is ever skipped;
- `TestDatabaseRestart` cuts every replica's database link for 3 seconds, like a PostgreSQL
  restart or managed failover, and checks that writes and delivery resume with the same
  guarantees.

```sh
docker run -d --name tenarium-chaos-pg -p 127.0.0.1:55433:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine
TENARIUM_TEST_POSTGRES_DSN='postgres://postgres:postgres@localhost:55433/postgres?sslmode=disable' \
  go test -tags chaos -v -count=1 -timeout 5m ./tests/chaos
```

They are behind the `chaos` build tag and skipped without `TENARIUM_TEST_POSTGRES_DSN`.
`CHAOS_VERBOSE=1` shows the replicas' logs. The "kill" is a context cancellation plus a network
cut rather than a real SIGKILL, and PostgreSQL itself is not restarted; see the
[chaos README](https://github.com/AimTune/tenarium/blob/main/tests/chaos/README.md) for the
limits.
