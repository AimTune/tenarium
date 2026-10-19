# TLS and managed certificates

Tenarium serves plain HTTP by default and expects TLS to be terminated in front of it (ingress,
load balancer, Caddy). It can also serve HTTPS itself, with a certificate you provide or with
certificates it obtains through ACME (Let's Encrypt or any RFC 8555 CA) for the platform's own
hostnames **and every verified custom domain of a live tenant**.

## Static certificate

```yaml
server:
  addr: ":8443"
  tls:
    cert_file: /etc/tenarium/tls.crt   # PEM, full chain
    key_file: /etc/tenarium/tls.key
```

TLS 1.2 is the minimum. The files are read at startup; restart to pick up a renewed certificate.

## ACME

```yaml
server:
  addr: ":443"
  tls:
    acme:
      enabled: true
      email: ops@example.com             # ACME account contact (expiry and incident mail)
      directory: staging                 # staging (default) | production | full directory URL
      platform_hosts:                    # always allowed, no tenant lookup
        - tenarium.example.com
        - "*.apps.example.com"           # any single label below; one certificate per name
      http_addr: ":80"                   # http-01 + redirect to https (default); "" disables it
      # ca_roots_file: /etc/tenarium/private-ca.pem   # extra roots for a private CA or Pebble
      # renew_before: 720h               # default: 1/3 of the lifetime, at most 30 days
      # key_prefix: certs/               # namespace in the kv table
      # policy_cache_ttl: 1m             # how long "allowed" answers are cached
      # policy_deny_ttl: 30s             # "not allowed" answers
      # policy_error_ttl: 5s             # lookup errors
      # lock_ttl: 3m                     # issuance lock lifetime across replicas
      # lock_wait: 90s                   # how long a replica waits for another one's issuance
```

- A certificate is requested at the **first TLS handshake** for a hostname. Allowed hostnames
  are `platform_hosts` and verified [custom domains](tenants.md#custom-domains) of live tenants;
  every other SNI name is refused, so nobody can make Tenarium request certificates for
  arbitrary names.
- Challenges: `tls-alpn-01` on the HTTPS listener always works; with `http_addr` (default `:80`)
  `http-01` is answered too, and every other request on that port is redirected to https.
- `directory` defaults to Let's Encrypt **staging**, so a half-configured deployment cannot burn
  production rate limits. Staging certificates are not trusted by browsers: switch to
  `production` once a first domain works end to end.
- Answers of the host policy are cached for `policy_cache_ttl`, so a removed domain may still be
  served by a replica for up to a minute.
- When ACME is enabled, `cert_file` and `key_file` are ignored.

`GET /v1/tenants/{id}/domains/{hostname}/certificate` (`domains:read`) shows a domain's
certificate: `{"hostname", "issued": true, "certificate": {"issuer", "serial", "dns_names",
"not_before", "not_after", "key_type"}}`, or `"issued": false` before the first handshake. Alert
on certificates that get close to expiry: renewal failures are retried but not reported anywhere
else.

### DNS for tenants

A tenant's custom domain needs two records:

1. the verification TXT record, `_tenarium-challenge.app.acme.com TXT tenarium-verification=...`;
2. traffic to Tenarium on ports 443 (and 80 for http-01): `app.acme.com CNAME edge.example.com`
   for a subdomain, or `A`/`AAAA` records (or the DNS provider's ALIAS/ANAME flattening) for an
   apex domain.

If the tenant has a CAA record, it must allow the CA (`0 issue "letsencrypt.org"`).

### Several replicas

Certificates, the ACME account key and pending challenge tokens are stored in the database
(`kv` table), so all replicas serve the same certificates and any replica can answer a challenge
another one started. The first issuance for a hostname is serialised with a best-effort lock in
the same table; the worst case is a duplicate certificate, which is harmless but counts against
rate limits. Background renewals run on every replica and are not locked; they normally pick up
a certificate another replica renewed.

The `kv` table is part of the state: back it up. Losing it means issuing every certificate again.
Its values (certificates with their private keys, the account key) are encrypted with the
[`secrets`](secrets.md) keyring when a provider is configured.

### Rate limits

Let's Encrypt production limits include 50 certificates per registered domain per week,
5 duplicate certificates per exact set of names per week, 5 failed validations per hostname per
hour and 300 new orders per account per 3 hours. Consequences:

- Test on `staging` first: a wrong DNS record or a closed port quickly turns into failed
  validations.
- `*.apps.example.com` in `platform_hosts` issues one certificate per name, all under the
  `example.com` limit. For many platform subdomains, use a real wildcard certificate (DNS-01)
  obtained outside Tenarium and terminate TLS in front of it.
- When migrating from a proxy that held the certificates (for example Caddy with on-demand TLS
  asking `/v1/domains/check`), each hostname is issued again on its first handshake; migrate
  many domains in batches.

### Testing against Pebble

`internal/certs` has an end-to-end test that issues real certificates from
[Pebble](https://github.com/letsencrypt/pebble) with two managers sharing one store; see
[testing](testing.md#unit-and-integration-tests).
