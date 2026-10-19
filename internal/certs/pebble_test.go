package certs

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPebbleIssuance runs real ACME issuance against Pebble, Let's Encrypt's
// test CA. It is skipped unless TENARIUM_TEST_PEBBLE_URL points at Pebble's
// directory, e.g.
//
//	docker run -d --name tenarium-test-pebble -p 127.0.0.1:14000:14000 \
//	  -e PEBBLE_VA_ALWAYS_VALID=1 -e PEBBLE_WFE_NONCEREJECT=0 ghcr.io/letsencrypt/pebble
//	TENARIUM_TEST_PEBBLE_URL=https://127.0.0.1:14000/dir go test ./internal/certs -run Pebble -v
//
// PEBBLE_VA_ALWAYS_VALID=1 makes Pebble accept every challenge without
// connecting back, so no DNS or open ports are needed. Pebble serves its API
// with a certificate from its own minica root: set TENARIUM_TEST_PEBBLE_CA to
// that root's PEM file (docker cp tenarium-test-pebble:/test/certs/pebble.minica.pem .)
// to verify it, otherwise TLS verification of the ACME API is skipped (tests only).
//
// Two managers sharing one KV stand in for two replicas: both receive a
// handshake for the same new hostname at the same time, and the issuance lock
// must make exactly one of them talk to the CA.
func TestPebbleIssuance(t *testing.T) {
	dir := os.Getenv("TENARIUM_TEST_PEBBLE_URL")
	if dir == "" {
		t.Skip("TENARIUM_TEST_PEBBLE_URL not set")
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	if ca := os.Getenv("TENARIUM_TEST_PEBBLE_CA"); ca != "" {
		var err error
		if hc, err = httpClient(ca); err != nil {
			t.Fatal(err)
		}
	} else {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Pebble test CA only
		hc.Transport = tr
	}

	rnd := make([]byte, 4)
	_, _ = rand.Read(rnd)
	host := "e2e-" + hex.EncodeToString(rnd) + ".tenant.example.com"

	kv := NewMemKV()
	var issued, failed atomic.Int32
	newReplica := func() *Manager {
		m, err := New(Config{Directory: dir, Email: "ops@example.com", LockWait: 2 * time.Minute},
			Options{
				KV: kv,
				Checker: func(_ context.Context, h string) error {
					if h == host {
						return nil
					}
					return ErrHostNotAllowed
				},
				HTTPClient: hc,
				Hooks: Hooks{
					OnIssued: func(string, time.Time) { issued.Add(1) },
					OnFailed: func(h string, err error) { failed.Add(1); t.Logf("issuance failed for %s: %v", h, err) },
				},
			})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	replicas := []*Manager{newReplica(), newReplica()}

	// Each replica gets a real TLS listener; the handshake drives issuance.
	var addrs []string
	for _, m := range replicas {
		ln, err := tls.Listen("tcp", "127.0.0.1:0", m.TLSConfig())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					_ = c.(*tls.Conn).Handshake()
				}(c)
			}
		}()
		addrs = append(addrs, ln.Addr().String())
	}

	dial := func(addr, sni string) (*x509.Certificate, error) {
		d := &net.Dialer{Timeout: 3 * time.Minute}
		c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true}) // we inspect the cert ourselves
		if err != nil {
			return nil, err
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0], nil
	}

	var wg sync.WaitGroup
	certs := make([]*x509.Certificate, len(addrs))
	errs := make([]error, len(addrs))
	for i, a := range addrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			certs[i], errs[i] = dial(a, host)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d handshake: %v", i, err)
		}
	}
	if certs[0].SerialNumber.Cmp(certs[1].SerialNumber) != 0 {
		t.Errorf("replicas serve different certificates: %x vs %x", certs[0].SerialNumber, certs[1].SerialNumber)
	}
	if n := issued.Load(); n != 1 {
		t.Errorf("certificates issued = %d, want exactly 1 (issuance lock)", n)
	}
	if failed.Load() != 0 {
		t.Errorf("failures reported: %d", failed.Load())
	}
	if certs[0].VerifyHostname(host) != nil {
		t.Errorf("certificate does not cover %s: %v", host, certs[0].DNSNames)
	}

	st, err := replicas[1].Status(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(st.Issuer), "pebble") || !st.NotAfter.After(time.Now()) {
		t.Errorf("status = %+v", st)
	}
	t.Logf("issued %s by %q, expires %s", host, st.Issuer, st.NotAfter.Format(time.RFC3339))

	// The account key and the certificate live in the shared KV; challenge
	// tokens and the lock are gone.
	for _, k := range kv.Keys("") {
		if strings.Contains(k, "+token") || strings.Contains(k, "+http-01") || strings.Contains(k, "/lock/") {
			t.Errorf("leftover key %s", k)
		}
	}
	if _, err := kv.Get(context.Background(), "certs/acme_account+key"); err != nil {
		t.Errorf("account key not shared: %v", err)
	}

	// A denied host never reaches the CA.
	if _, err := dial(addrs[0], "not-a-tenant.example.com"); err == nil {
		t.Error("handshake for a denied host should fail")
	}
}
