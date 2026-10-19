package certs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// selfSigned returns a certificate for host in autocert's cache format.
func selfSigned(t *testing.T, host string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	return buf.Bytes()
}

func ecdsaHello(host string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:       host,
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
}

// unreachableCA makes any accidental ACME traffic fail fast.
const unreachableCA = "http://127.0.0.1:1/directory"

func TestCacheRoundTripAndNamespacing(t *testing.T) {
	ctx := context.Background()
	kv := NewMemKV()
	a := NewCache(kv, "a/")
	b := NewCache(kv, "b/")

	if _, err := a.Get(ctx, "x.example.com"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("missing key: got %v, want ErrCacheMiss", err)
	}
	if err := a.Put(ctx, "x.example.com", []byte("A")); err != nil {
		t.Fatal(err)
	}
	if err := b.Put(ctx, "x.example.com", []byte("B")); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.Get(ctx, "x.example.com"); string(got) != "A" {
		t.Fatalf("a: got %q", got)
	}
	if got, _ := b.Get(ctx, "x.example.com"); string(got) != "B" {
		t.Fatalf("b: got %q", got)
	}
	if keys := kv.Keys(""); strings.Join(keys, ",") != "a/x.example.com,b/x.example.com" {
		t.Fatalf("keys = %v", keys)
	}
	if err := a.Delete(ctx, "x.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := a.Delete(ctx, "x.example.com"); err != nil {
		t.Fatalf("delete of missing key: %v", err)
	}
	if _, err := a.Get(ctx, "x.example.com"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("after delete: %v", err)
	}
	if got, _ := b.Get(ctx, "x.example.com"); string(got) != "B" {
		t.Fatal("delete leaked across prefixes")
	}
	if NewCache(kv, "").Prefix != DefaultKeyPrefix {
		t.Fatal("empty prefix should default")
	}
}

func TestCacheSealOpen(t *testing.T) {
	ctx := context.Background()
	kv := NewMemKV()
	c := NewCache(kv, "")
	c.Seal = func(b []byte) ([]byte, error) { return append([]byte("sealed:"), b...), nil }
	c.Open = func(b []byte) ([]byte, error) {
		rest, ok := bytes.CutPrefix(b, []byte("sealed:"))
		if !ok {
			return nil, errors.New("not sealed")
		}
		return rest, nil
	}
	if err := c.Put(ctx, "acme_account+key", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	raw, _ := kv.Get(ctx, "certs/acme_account+key")
	if string(raw) != "sealed:secret" {
		t.Fatalf("stored %q, want sealed value", raw)
	}
	if got, err := c.Get(ctx, "acme_account+key"); err != nil || string(got) != "secret" {
		t.Fatalf("get = %q, %v", got, err)
	}
	_ = kv.Put(ctx, "certs/bad", []byte("plain"))
	if _, err := c.Get(ctx, "bad"); err == nil || errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("open failure should surface, got %v", err)
	}
}

func TestCertName(t *testing.T) {
	for name, want := range map[string]string{
		"a.example.com":       "a.example.com",
		"a.example.com+rsa":   "a.example.com",
		"a.example.com+token": "",
		"tok+http-01":         "",
		"acme_account+key":    "",
	} {
		got, ok := certName(name)
		if got != want || ok != (want != "") {
			t.Errorf("certName(%q) = %q, %v", name, got, ok)
		}
	}
}

func TestHostPolicy(t *testing.T) {
	ctx := context.Background()
	var calls atomic.Int32
	check := func(_ context.Context, host string) error {
		calls.Add(1)
		switch host {
		case "app.acme.com":
			return nil
		case "flaky.acme.com":
			return errors.New("db down")
		}
		return ErrHostNotAllowed
	}
	now := time.Unix(1_700_000_000, 0)
	p := newHostPolicy([]string{"Tenarium.Example.com.", "*.apps.example.com"}, check,
		time.Minute, 30*time.Second, 5*time.Second, func() time.Time { return now })

	for _, h := range []string{"tenarium.example.com", "TENARIUM.example.com:443", "x.apps.example.com"} {
		if err := p.allow(ctx, h); err != nil {
			t.Errorf("platform host %s denied: %v", h, err)
		}
	}
	for _, h := range []string{"apps.example.com", "a.b.apps.example.com", "127.0.0.1", ""} {
		if err := p.allow(ctx, h); err == nil {
			t.Errorf("%q should be denied", h)
		}
	}
	calls.Store(0) // the platform pattern misses above went to the checker

	if err := p.allow(ctx, "app.acme.com"); err != nil {
		t.Fatal(err)
	}
	if err := p.allow(ctx, "APP.acme.com."); err != nil {
		t.Fatal(err)
	}
	if err := p.allow(ctx, "evil.com"); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("evil.com: %v", err)
	}
	_ = p.allow(ctx, "evil.com")
	if n := calls.Load(); n != 2 {
		t.Fatalf("checker calls = %d, want 2 (answers cached)", n)
	}

	// Errors are cached for less time than denials, denials less than allows.
	if err := p.allow(ctx, "flaky.acme.com"); err == nil {
		t.Fatal("flaky should fail")
	}
	now = now.Add(10 * time.Second)
	calls.Store(0)
	_ = p.allow(ctx, "flaky.acme.com") // error TTL (5s) expired
	_ = p.allow(ctx, "evil.com")       // deny TTL (30s) not expired
	_ = p.allow(ctx, "app.acme.com")   // allow TTL (1m) not expired
	if n := calls.Load(); n != 1 {
		t.Fatalf("calls after 10s = %d, want 1", n)
	}
	now = now.Add(time.Minute)
	calls.Store(0)
	_ = p.allow(ctx, "app.acme.com")
	_ = p.allow(ctx, "evil.com")
	if n := calls.Load(); n != 2 {
		t.Fatalf("calls after expiry = %d, want 2", n)
	}

	p.forget("app.acme.com")
	calls.Store(0)
	_ = p.allow(ctx, "app.acme.com")
	if calls.Load() != 1 {
		t.Fatal("forget should drop the cached answer")
	}

	// A cancelled lookup is not cached.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	p2 := newHostPolicy(nil, func(ctx context.Context, _ string) error { return ctx.Err() }, time.Minute, time.Minute, time.Minute, time.Now)
	_ = p2.allow(cctx, "a.example.com")
	if len(p2.entries) != 0 {
		t.Fatal("cancelled lookup was cached")
	}

	// No checker: only platform hosts.
	p3 := newHostPolicy([]string{"a.example.com"}, nil, time.Minute, time.Minute, time.Minute, time.Now)
	if p3.allow(ctx, "a.example.com") != nil || p3.allow(ctx, "b.example.com") == nil {
		t.Fatal("nil checker policy wrong")
	}
}

func newTestManager(t *testing.T, kv KV, cfg Config, hooks Hooks) *Manager {
	t.Helper()
	if cfg.Directory == "" {
		cfg.Directory = unreachableCA
	}
	m, err := New(cfg, Options{
		KV: kv,
		Checker: func(_ context.Context, host string) error {
			if strings.HasSuffix(host, ".tenant.test") {
				return nil
			}
			return ErrHostNotAllowed
		},
		Hooks: hooks,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHTTPHandler(t *testing.T) {
	kv := NewMemKV()
	m := newTestManager(t, kv, Config{PlatformHosts: []string{"tenarium.example.com"}}, Hooks{})
	// What autocert writes while an http-01 challenge is pending (on any replica).
	_ = kv.Put(context.Background(), "certs/tok123+http-01", []byte("tok123.thumbprint"))

	h := m.HTTPHandler(nil)
	do := func(method, host, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://"+host+path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := do("GET", "app.tenant.test", "/.well-known/acme-challenge/tok123"); w.Code != 200 || w.Body.String() != "tok123.thumbprint" {
		t.Fatalf("challenge: %d %q", w.Code, w.Body.String())
	}
	if w := do("GET", "tenarium.example.com:80", "/.well-known/acme-challenge/tok123"); w.Code != 200 {
		t.Fatalf("platform challenge: %d", w.Code)
	}
	if w := do("GET", "app.tenant.test", "/.well-known/acme-challenge/unknown"); w.Code != 404 {
		t.Fatalf("unknown token: %d", w.Code)
	}
	if w := do("GET", "evil.com", "/.well-known/acme-challenge/tok123"); w.Code != 403 {
		t.Fatalf("denied host: %d", w.Code)
	}
	w := do("GET", "app.tenant.test", "/login?next=%2F")
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://app.tenant.test/login?next=%2F" {
		t.Fatalf("redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := do("POST", "app.tenant.test", "/login"); w.Code != 400 {
		t.Fatalf("POST over http: %d", w.Code)
	}

	fb := m.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest("GET", "http://app.tenant.test/health", nil)
	rec := httptest.NewRecorder()
	fb.ServeHTTP(rec, r)
	if rec.Code != 204 {
		t.Fatalf("fallback: %d", rec.Code)
	}
}

func TestStatusAndIssuedHook(t *testing.T) {
	ctx := context.Background()
	kv := NewMemKV()
	var issued []string
	m := newTestManager(t, kv, Config{}, Hooks{OnIssued: func(h string, _ time.Time) { issued = append(issued, h) }})

	if _, err := m.Status(ctx, "app.tenant.test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("status before issuance: %v", err)
	}
	exp := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	// autocert writes through the cache; tokens and the account key are not certificates.
	_ = m.Cache().Put(ctx, "acme_account+key", []byte("k"))
	_ = m.Cache().Put(ctx, "tok+http-01", []byte("t"))
	if err := m.Cache().Put(ctx, "app.tenant.test", selfSigned(t, "app.tenant.test", exp)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(issued, ",") != "app.tenant.test" {
		t.Fatalf("OnIssued calls = %v", issued)
	}
	st, err := m.Status(ctx, "App.Tenant.Test.")
	if err != nil {
		t.Fatal(err)
	}
	if st.Issuer != "app.tenant.test" || !st.NotAfter.Equal(exp) || st.KeyType != "ecdsa" || st.DNSNames[0] != "app.tenant.test" {
		t.Fatalf("status = %+v", st)
	}
}

func TestGetCertificateFromSharedCache(t *testing.T) {
	kv := NewMemKV()
	var denied, failed atomic.Int32
	hooks := Hooks{
		OnDenied: func(string, error) { denied.Add(1) },
		OnFailed: func(string, error) { failed.Add(1) },
	}
	// Replica A's work, as found in the database.
	_ = kv.Put(context.Background(), "certs/app.tenant.test", selfSigned(t, "app.tenant.test", time.Now().Add(60*24*time.Hour)))

	m := newTestManager(t, kv, Config{}, hooks) // replica B, CA unreachable
	cert, err := m.GetCertificate(ecdsaHello("app.tenant.test"))
	if err != nil {
		t.Fatalf("served from shared cache: %v", err)
	}
	if cert.Leaf == nil || cert.Leaf.DNSNames[0] != "app.tenant.test" {
		t.Fatal("wrong certificate")
	}
	if _, err := m.GetCertificate(ecdsaHello("evil.com")); !errors.Is(err, ErrHostNotAllowed) || denied.Load() != 1 {
		t.Fatalf("denied host: %v (denied=%d)", err, denied.Load())
	}
	// A missing cert must go to the CA, which is unreachable here.
	if _, err := m.GetCertificate(ecdsaHello("new.tenant.test")); err == nil || failed.Load() != 1 {
		t.Fatalf("issuance against unreachable CA: %v (failed=%d)", err, failed.Load())
	}
	if keys := kv.Keys("certs/lock/"); len(keys) != 0 {
		t.Fatalf("lock not released: %v", keys)
	}
}

func TestGetCertificateWaitsForOtherReplica(t *testing.T) {
	ctx := context.Background()
	kv := NewMemKV()
	other := newTestManager(t, kv, Config{}, Hooks{})
	lk := lockKey(DefaultKeyPrefix, "app.tenant.test")
	if ok, err := other.tryLock(ctx, lk); !ok || err != nil {
		t.Fatalf("other replica lock: %v %v", ok, err)
	}

	m := newTestManager(t, kv, Config{LockWait: time.Minute}, Hooks{})
	var (
		wg   sync.WaitGroup
		cert *tls.Certificate
		err  error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		cert, err = m.GetCertificate(ecdsaHello("app.tenant.test"))
	}()
	time.Sleep(700 * time.Millisecond)
	// The other replica finishes issuance: stores the cert, releases the lock.
	_ = other.Cache().Put(ctx, "app.tenant.test", selfSigned(t, "app.tenant.test", time.Now().Add(60*24*time.Hour)))
	other.unlock(lk)
	wg.Wait()
	if err != nil {
		t.Fatalf("waiting replica should pick up the shared cert (CA is unreachable): %v", err)
	}
	if cert.Leaf.SerialNumber.Int64() != 4242 {
		t.Fatal("unexpected certificate")
	}
}

func TestLock(t *testing.T) {
	ctx := context.Background()
	kv := NewMemKV()
	a := newTestManager(t, kv, Config{LockTTL: time.Minute}, Hooks{})
	b := newTestManager(t, kv, Config{LockTTL: time.Minute}, Hooks{})
	key := lockKey("certs/", "x.example.com")

	if ok, _ := a.tryLock(ctx, key); !ok {
		t.Fatal("a should take the lock")
	}
	if ok, _ := a.tryLock(ctx, key); !ok {
		t.Fatal("re-entrant for the owner")
	}
	if ok, _ := b.tryLock(ctx, key); ok {
		t.Fatal("b must not take a live lock")
	}
	if !b.lockHeld(ctx, key) {
		t.Fatal("lockHeld")
	}
	b.unlock(key) // not the owner: no-op
	if !a.lockHeld(ctx, key) {
		t.Fatal("non-owner released the lock")
	}

	// a crashes; after the TTL b breaks the stale lock.
	b.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if ok, _ := b.tryLock(ctx, key); !ok {
		t.Fatal("b should break a stale lock")
	}
	b.unlock(key)
	if _, err := kv.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatal("unlock should delete")
	}
}

func TestConfigDirectory(t *testing.T) {
	for in, want := range map[string]string{
		"":                         LetsEncryptStaging,
		"staging":                  LetsEncryptStaging,
		"Production":               LetsEncryptProduction,
		"https://pebble:14000/dir": "https://pebble:14000/dir",
	} {
		if got := (Config{Directory: in}).DirectoryURL(); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	if _, err := New(Config{}, Options{}); err == nil {
		t.Error("KV is required")
	}
	if _, err := New(Config{CARootsFile: "does-not-exist.pem"}, Options{KV: NewMemKV()}); err == nil {
		t.Error("missing CA file should fail")
	}
}
