package tenantmw_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/tenantmw"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeSource serves tenants from a map and counts loads.
type fakeSource struct {
	mu      sync.Mutex
	tenants map[string]*tenantmw.Tenant // by ID
	calls   atomic.Int64
	delay   time.Duration
}

func newFakeSource(ts ...*tenantmw.Tenant) *fakeSource {
	s := &fakeSource{tenants: map[string]*tenantmw.Tenant{}}
	for _, t := range ts {
		s.tenants[t.ID] = t
	}
	return s
}

func (s *fakeSource) Tenant(_ context.Context, ref string) (*tenantmw.Tenant, error) {
	s.calls.Add(1)
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tenants {
		if t.ID == ref || t.Slug == ref {
			return t, nil
		}
	}
	return nil, tenantmw.ErrNotFound
}

var (
	acme   = &tenantmw.Tenant{ID: "11111111-0000-0000-0000-000000000001", Slug: "acme", Status: tenantmw.StatusActive, Plan: "pro", Features: map[string]bool{"sso": true}, Limits: map[string]int64{"seats": 10}}
	globex = &tenantmw.Tenant{ID: "22222222-0000-0000-0000-000000000002", Slug: "globex", Status: tenantmw.StatusActive, Features: map[string]bool{}}
	frozen = &tenantmw.Tenant{ID: "33333333-0000-0000-0000-000000000003", Slug: "frozen", Status: tenantmw.StatusSuspended}
)

// issuer signs Tenarium-style tokens and serves their JWKS.
type issuer struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	keys    []jose.JSONWebKey // private keys
	fetches atomic.Int64
}

const testIssuer = "https://tenarium.test"

func newIssuer(t *testing.T) *issuer {
	is := &issuer{t: t}
	is.rotate()
	is.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.fetches.Add(1)
		is.mu.Lock()
		defer is.mu.Unlock()
		set := jose.JSONWebKeySet{}
		for _, k := range is.keys {
			set.Keys = append(set.Keys, k.Public())
		}
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(is.srv.Close)
	return is
}

// rotate adds a new signing key.
func (is *issuer) rotate() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		is.t.Fatal(err)
	}
	is.mu.Lock()
	defer is.mu.Unlock()
	is.keys = append(is.keys, jose.JSONWebKey{Key: priv, KeyID: "k" + string(rune('0'+len(is.keys))), Algorithm: "ES256", Use: "sig"})
}

func (is *issuer) verifier(minRefresh time.Duration) *tenantmw.Verifier {
	v, err := tenantmw.NewVerifier(tenantmw.VerifierConfig{JWKSURL: is.srv.URL, Issuer: testIssuer, MinRefreshInterval: minRefresh})
	if err != nil {
		is.t.Fatal(err)
	}
	return v
}

type tokenOpts struct {
	iss, aud string
	exp      time.Duration
}

func (is *issuer) token(tid string, o tokenOpts) string {
	is.mu.Lock()
	key := is.keys[len(is.keys)-1]
	is.mu.Unlock()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: &key},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader(jose.HeaderKey("kid"), key.KeyID))
	if err != nil {
		is.t.Fatal(err)
	}
	if o.iss == "" {
		o.iss = testIssuer
	}
	if o.aud == "" {
		o.aud = "tenarium"
	}
	if o.exp == 0 {
		o.exp = time.Minute
	}
	now := time.Now()
	claims := map[string]any{
		"iss": o.iss, "sub": "user-1", "aud": []string{o.aud}, "tid": tid, "roles": []string{"admin"},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(o.exp).Unix(),
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		is.t.Fatal(err)
	}
	return tok
}

type response struct {
	code   int
	body   string
	tenant *tenantmw.Tenant
}

// serve runs req through h wrapping a handler that records the tenant.
func serve(mw func(http.Handler) http.Handler, req *http.Request) response {
	var got *tenantmw.Tenant
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = tenantmw.FromContext(r.Context())
		_, _ = io.WriteString(w, "ok")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return response{code: rec.Code, body: strings.TrimSpace(rec.Body.String()), tenant: got}
}

func request(host, path string, headers ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return r
}

func base64URLDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
func base64URLEncode(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func itoa(v int64) string                      { return strconv.FormatInt(v, 10) }
