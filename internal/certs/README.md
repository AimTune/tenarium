# internal/certs: managed certificates

ACME issuance and renewal inside Tenarium for the platform's own hostnames and for tenants'
verified custom domains, as an alternative to the Caddy on-demand TLS setup described in
[docs/tenants.md](../../docs/tenants.md#custom-domains). The server wires it up in
[pkg/server/tls.go](../../pkg/server/tls.go) from the `server.tls` configuration; see
[docs/tls.md](../../docs/tls.md) for configuration and operation. Certificates and the ACME
account key are stored through the store's key-value table, encrypted when a `secrets` keyring
is configured.

## DNS for tenants

A custom domain needs two records:

1. The verification TXT record (unchanged): `_tenarium-challenge.app.acme.com TXT tenarium-verification=...`.
2. Traffic to the platform's TLS entry point, reachable on ports 443 (and 80 for http-01):
   - a subdomain: `app.acme.com CNAME edge.example.com` (preferred, you can move IPs later), or
   - an apex domain, which cannot be a CNAME: `acme.com A 203.0.113.10` / `AAAA 2001:db8::10`
     (or the DNS provider's ALIAS/ANAME flattening to `edge.example.com`).

The certificate is requested at the first TLS handshake for the name after it is verified. If
the tenant has a CAA record, it must allow the CA (`0 issue "letsencrypt.org"`).

## Replacing the Caddy setup

Today Caddy terminates TLS with `on_demand_tls { ask http://tenarium:8080/v1/domains/check }`.
With this package Tenarium terminates TLS itself:

1. Run Tenarium (or the edge that embeds this package) on 443/80 instead of Caddy, with
   `Checker` doing the same lookup as `/v1/domains/check` (verified domain, live tenant).
2. Keep `directory: staging` for a first deploy, open a custom domain, check `Status`, then
   switch to `production`.
3. Existing Caddy certificates are not imported; each hostname is issued again on its first
   handshake (watch the rate limits below when migrating many domains at once; migrate in
   batches or warm up with a script that dials each verified domain).

`/v1/domains/check` stays useful for setups that keep a separate TLS proxy.

## Multiple replicas

All state lives in the KV, so replicas share one ACME account and one certificate per hostname.
autocert has no hook around issuance, so the Manager wraps `GetCertificate`: when no valid
certificate exists in the KV, the replica takes a lock (`<prefix>lock/<host>`, `PutIfAbsent`
with an expiry). Other replicas poll the KV until the certificate appears, then serve it. The lock
is best-effort: a stale lock is broken with a non-atomic delete + put, and waiters give up after
`lock_wait`. The worst case is a duplicate issuance, which is harmless but wasteful.

Background renewals run inside autocert on every replica and cannot be locked. autocert re-reads
the KV just before renewing, and its timers are jittered, so replicas usually adopt the
certificate another replica renewed; occasionally two renew at the same moment. Renewal failures
are retried by autocert but not reported through `Hooks`; alert on `Status` expiry instead.

`OnIssued` fires on the replica that stored the certificate (first issuance and renewals).

## Rate limits

Let's Encrypt production limits (see letsencrypt.org/docs/rate-limits) include 50 certificates
per registered domain per week, 5 duplicate certificates per exact name set per week, 5 failed
validations per hostname per hour and 300 new orders per account per 3 hours. Consequences:

- Always test on `staging` first. A wrong `Checker`, broken DNS or a closed port 80/443 turns
  into failed validations quickly.
- The host policy is the protection against arbitrary SNI names: never allow hosts that are not
  verified domains or platform hostnames.
- `*.apps.example.com` platform patterns issue one certificate per name, all under the
  `example.com` limit of 50 per week. For many platform subdomains use a real wildcard
  certificate obtained with DNS-01 outside this package.
- The KV must be persistent: losing it means re-issuing everything.

## Tests

`go test ./internal/certs` runs unit tests (cache, policy, HTTP handler, lock, status). The
end-to-end test issues real certificates from [Pebble](https://github.com/letsencrypt/pebble)
with two managers sharing one KV and checks that exactly one certificate is issued:

```sh
docker run -d --name tenarium-test-pebble -p 127.0.0.1:14000:14000 \
  -e PEBBLE_VA_ALWAYS_VALID=1 -e PEBBLE_WFE_NONCEREJECT=0 ghcr.io/letsencrypt/pebble
docker cp tenarium-test-pebble:/test/certs/pebble.minica.pem /tmp/pebble.pem   # optional
TENARIUM_TEST_PEBBLE_URL=https://localhost:14000/dir TENARIUM_TEST_PEBBLE_CA=/tmp/pebble.pem \
  go test ./internal/certs -run Pebble -v
docker rm -f tenarium-test-pebble
```

Without `TENARIUM_TEST_PEBBLE_CA` the test skips TLS verification of Pebble's API.

Pebble (and possibly other CAs) finalizes orders asynchronously and does not send a `Location`
header on the finalize response, which `x/crypto/acme` needs to poll the order. The Manager's
ACME HTTP client adds the missing header (`transport.go`); CAs that send it are unaffected.
