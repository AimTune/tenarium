# Chaos / failover tests

Go tests that run several Tenarium replicas in one process against a shared
PostgreSQL database and break things while events are flowing. They are
behind the `chaos` build tag, so `go test ./...` does not run them.

## Running

```sh
docker run -d --name tenarium-chaos-pg -p 127.0.0.1:55433:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine

TENARIUM_TEST_POSTGRES_DSN='postgres://postgres:postgres@localhost:55433/postgres?sslmode=disable' \
  go test -tags chaos -v -count=1 -timeout 5m ./tests/chaos
```

Each test creates (and drops) its own database, like the other PostgreSQL
tests (`internal/store/postgres/pgtest`). Without `TENARIUM_TEST_POSTGRES_DSN`
the tests are skipped. Set `CHAOS_VERBOSE=1` to see the replicas' logs.

## Setup

- Every replica is a full server (`pkg/server.New` + `Serve`) on its own
  port, with `events.lease_ttl: 3s`, `events.poll_interval: 50ms` and a
  distinct `events.instance_id`.
- Each replica talks to PostgreSQL through its own in-process TCP proxy.
  Cutting a proxy closes that replica's connections with a TCP reset and
  refuses new ones, which looks like a crashed or partitioned database.
- A test plugin (`chaos-sink`) subscribes to every event (`sink/all`) and
  records which replica delivered which event sequence number, and when.
- A producer creates tenants through the live replicas, round-robin, every
  20-25 ms (each one appends a `tenant.created` event). Failed writes are
  counted, not fatal.

## Tests

`TestLeaseHolderFailover` runs with three replicas, in two modes:

- `crash`: the lease holder's database link is cut and its context is
  cancelled at the same moment. It cannot release its lease or write a
  cursor on the way down, as if the process were killed.
- `cancel`: only the context is cancelled. The replica shuts down and
  releases its lease, so takeover is faster.

The lease holder is the replica that delivered the latest event. After it
is killed (2 s into the stream) the test checks that:

1. another replica delivers within `lease_ttl + lease_ttl/3 + 1s`. The lease
   expires at most `lease_ttl` after the holder's last renewal, and
   standbys retry acquisition every `min(lease_ttl/3, 5 * poll_interval)`;
2. every event in the log (read back through `/v1/events`) is delivered at
   least once;
3. no event is skipped. Whenever the delivery stream moves forward in the
   log, every earlier event has already been delivered. Rewinds
   (redeliveries after a failover) are allowed: delivery is at-least-once.

`TestDatabaseRestart` runs with two replicas. It cuts every replica's
database link for 3 s, like a PostgreSQL restart or managed-database
failover, then restores it. It checks that writes succeed again, that
delivery resumes, and the same delivery and no-skip guarantees as above.
Writes made during the outage fail with 500, which is expected; the log
holds only committed events.

## Limits

- The replicas share one process. The kill is a context cancellation plus
  a network cut, not a SIGKILL, so goroutines of the "dead" replica may
  still run briefly. They cannot reach the database, so they cannot
  deliver anything new. A handler call that was already in flight may still
  complete, which shows up as a redelivery.
- PostgreSQL itself is not restarted: the proxy simulates the restart from
  the replicas' point of view (every connection reset, new connections
  refused). Restarting the container gives the same result but takes longer
  and depends on Docker, so it is not automated here.
- Timing bounds assume a reasonably idle machine; under heavy load
  (e.g. fuzzing in parallel) raise `leaseTTL` in `chaos_test.go`.
