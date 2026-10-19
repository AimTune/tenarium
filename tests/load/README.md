# Load tests (k6)

Plain [k6](https://k6.io) JavaScript, no build step. Each scenario bootstraps
its own data in `setup()` (a set of tenants on the `pro` plan with the member
cap lifted), runs the load, and deletes the bootstrapped tenants in
`teardown()`.

| Script | What it exercises | Executor |
|---|---|---|
| `scenarios/tenants.js` | tenant CRUD: create, get, list by label, PATCH (settings merge patch + `If-Match`), delete | constant VUs |
| `scenarios/members.js` | member adds (invites new users), member reads, member lists | constant VUs |
| `scenarios/usage.js` | usage recording, the hot path (`POST /v1/tenants/{id}/usage/{metric}`) | constant arrival rate |
| `scenarios/events.js` | event log paging (`/v1/events`), platform audit with filters (`/v1/audit`), tenant audit | constant VUs |
| `mixed.js` | all of the above at once, usage-heavy | mixed |

## Thresholds

Every script fails (non-zero exit) when:

- `http_req_failed` rate is at or above `MAX_ERROR_RATE` (default 1%),
- overall p95 latency is at or above `P95_MS` (default 300 ms) or p99 at or above `P99_MS` (default 1000 ms),
- any endpoint's p95 is at or above `P95_MS` (latency is tagged per endpoint, e.g. `name:GET /v1/tenants/{id}`),
- usage recording's p95 is at or above `P95_MS / 2` (it is the hot path),
- fewer than `1 - MAX_ERROR_RATE` of the checks pass.

Tune the defaults for your hardware and store. They are deliberately loose
enough to pass against the in-memory store on a laptop.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `BASE_URL` | `http://localhost:8080` | Tenarium base URL |
| `API_KEY` | (empty) | platform API key, sent as `Authorization: Bearer` |
| `TENANTS` | `20` | tenants created by `setup()` |
| `PLAN` | `pro` | plan of the bootstrapped tenants (must exist) |
| `METRIC` | `api_calls` | usage metric recorded |
| `VUS` / `DURATION` | `10` / `30s` | load shape |
| `RATE` | `50` | iterations/s for the usage (open model) scenario |
| `P95_MS`, `P99_MS`, `MAX_ERROR_RATE` | `300`, `1000`, `0.01` | thresholds |
| `RUN_ID` | random | prefix of created slugs, so repeated runs do not collide |
| `KEEP_DATA` | unset | set to keep the bootstrapped tenants after the run |

## Running

Start a server (in-memory store, example configuration, which defines the
`free` and `pro` plans and an `api_calls` metric):

```sh
export TENARIUM_API_KEY=dev-key TENARIUM_ADMIN_PASSWORD='change-me-please'
go run ./cmd/tenarium -config config.example.yaml
```

With k6 installed:

```sh
k6 run -e API_KEY=dev-key tests/load/scenarios/usage.js
k6 run -e API_KEY=dev-key -e VUS=50 -e RATE=500 -e DURATION=5m tests/load/mixed.js
```

With Docker (no k6 install). On Docker Desktop (macOS/Windows) the host is
`host.docker.internal`; on Linux add `--network host` and keep `localhost`:

```sh
docker run --rm -i -v "$PWD/tests/load:/scripts" grafana/k6:0.54.0 run \
  -e BASE_URL=http://host.docker.internal:8080 -e API_KEY=dev-key \
  /scripts/scenarios/tenants.js
```

Git Bash on Windows rewrites `/scripts` paths; prefix the command with
`MSYS_NO_PATHCONV=1`.

To check that the scripts parse without load, run k6's `inspect` (it
evaluates the init context, so every import must resolve):

```sh
docker run --rm -i -v "$PWD/tests/load:/scripts" grafana/k6:0.54.0 inspect /scripts/mixed.js
```

`node --check` does not work for these files: they import k6 built-ins
(`k6`, `k6/http`) and use k6 globals (`__ENV`, `__VU`, `__ITER`) that only
exist inside the k6 runtime.

## Notes

- Against PostgreSQL the write scenarios also measure lock contention:
  member adds lock the tenant row (to enforce the member limit) and usage
  recording updates one counter row per tenant and period. Raise `TENANTS`
  to spread the load, lower it to stress a hot tenant.
- `members.js` creates invited users; with the default log mailer every
  invitation is written to the server log, which costs some throughput.
- Tenants are soft-deleted when `tenants.deletion_grace_period` is set, so
  `GET /v1/tenants?include_deleted=true` still lists them after a run.
