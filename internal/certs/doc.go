// Package certs issues and renews TLS certificates for the platform's own
// hostnames and for tenants' verified custom domains through ACME (Let's
// Encrypt or any RFC 8555 CA), inside Tenarium. It replaces the Caddy
// on-demand TLS setup that asks GET /v1/domains/check.
//
// It wraps golang.org/x/crypto/acme/autocert:
//
//   - A Cache on top of a KV interface (database-backed in production) holds
//     certificates, the ACME account key and in-flight challenge tokens, so
//     every replica serves the same certificates and can answer a challenge
//     started by another replica. Values can be wrapped with Seal/Open
//     (encryption at rest).
//   - The host policy allows Config.PlatformHosts and whatever the
//     DomainChecker accepts (verified domains of live tenants), with a short
//     cache so handshakes do not hit the database each time.
//   - Manager.TLSConfig serves port 443 and answers tls-alpn-01;
//     Manager.HTTPHandler serves port 80, answers http-01 and redirects the
//     rest to https.
//   - First issuance for a hostname is serialised across replicas with a
//     best-effort lock in the KV (PutIfAbsent). Background renewals run
//     inside autocert on every replica and are not locked; autocert re-reads
//     the shared cache right before renewing, so a replica normally picks up
//     the certificate another one renewed, but two replicas renewing in the
//     same moment both obtain one. That is harmless (both are valid; the
//     last write wins) but counts against CA rate limits.
//   - Hooks report issued, failed and denied certificates for metrics;
//     Manager.Status reads a certificate's issuer and expiry from the cache.
//
// Minimal wiring (not done by this package):
//
//	m, err := certs.New(cfg.Certs, certs.Options{KV: dbKV, Checker: checkDomain})
//	srv := &http.Server{Addr: ":443", Handler: app, TLSConfig: m.TLSConfig()}
//	go http.ListenAndServe(":80", m.HTTPHandler(nil))
//	srv.ListenAndServeTLS("", "")
//
// See README.md in this directory for configuration, DNS setup, migration
// from Caddy and rate limits.
package certs
