package social

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	testClientID     = "client-1"
	testClientSecret = "secret-1"
)

// grant is what the fake provider remembers about an authorization code.
type grant struct {
	challenge string
	nonce     string
}

// fakeOIDC is an OpenID provider: discovery, JWKS and a token endpoint
// issuing signed ID tokens. It enforces PKCE and client authentication.
type fakeOIDC struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	mu sync.Mutex
	// discoveryIssuer is the issuer in discovery (default: server URL).
	discoveryIssuer string
	// tokenIssuer is the iss of ID tokens (default: discoveryIssuer).
	tokenIssuer string
	// claims are added to (and override) the ID token's claims.
	claims      map[string]any
	codes       map[string]grant
	discoveries int
	tokenFail   bool
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOIDC{t: t, key: key, codes: map[string]grant{}, claims: map[string]any{
		"email": "Ada@Example.com", "email_verified": true, "name": "Ada Lovelace",
	}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOIDC) issuer() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.discoveryIssuer != "" {
		return f.discoveryIssuer
	}
	return f.srv.URL
}

func (f *fakeOIDC) set(fn func(f *fakeOIDC)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeOIDC) authorize(code, challenge, nonce string) {
	f.set(func(f *fakeOIDC) { f.codes[code] = grant{challenge: challenge, nonce: nonce} })
}

func (f *fakeOIDC) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
		f.set(func(f *fakeOIDC) { f.discoveries++ })
		writeJSON(w, map[string]any{
			"issuer":                                f.issuer(),
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case r.URL.Path == "/jwks":
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	case r.URL.Path == "/token":
		f.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeOIDC) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	g, ok := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code"))
	fail := f.tokenFail
	claims := map[string]any{}
	for k, v := range f.claims {
		claims[k] = v
	}
	iss := f.tokenIssuer
	f.mu.Unlock()
	if iss == "" {
		iss = f.issuer()
	}
	if fail {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	if !ok || r.PostForm.Get("grant_type") != "authorization_code" || !clientAuthOK(r) ||
		r.PostForm.Get("redirect_uri") == "" || !pkceOK(g.challenge, r.PostForm.Get("code_verifier")) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	now := time.Now()
	base := map[string]any{
		"iss": iss, "sub": "user-123", "aud": testClientID, "nonce": g.nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), "k1"))
	if err != nil {
		f.t.Error(err)
		return
	}
	raw, err := jwt.Signed(signer).Claims(base).Serialize()
	if err != nil {
		f.t.Error(err)
		return
	}
	writeJSON(w, map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 300, "id_token": raw})
}

func clientAuthOK(r *http.Request) bool {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	return id == testClientID && secret == testClientSecret
}

func pkceOK(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

type ghEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// fakeGitHub serves GitHub's OAuth token endpoint and user API.
type fakeGitHub struct {
	srv *httptest.Server

	mu     sync.Mutex
	codes  map[string]string // code -> PKCE challenge
	emails []ghEmail
	user   map[string]any
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{
		codes:  map[string]string{},
		emails: []ghEmail{{"old@example.com", false, true}, {"Grace@Example.com", true, true}},
		user:   map[string]any{"id": 4242, "login": "grace", "name": ""},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/login/oauth/access_token":
		_ = r.ParseForm()
		ch, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		if !ok || !clientAuthOK(r) || !pkceOK(ch, r.PostForm.Get("code_verifier")) {
			// GitHub reports errors with 200 OK.
			writeJSON(w, map[string]any{"error": "bad_verification_code"})
			return
		}
		writeJSON(w, map[string]any{"access_token": "gh-token", "token_type": "bearer", "scope": "read:user,user:email"})
	case "/api/user", "/api/user/emails":
		if r.Header.Get("Authorization") != "Bearer gh-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/user" {
			writeJSON(w, f.user)
		} else {
			writeJSON(w, f.emails)
		}
	default:
		http.NotFound(w, r)
	}
}
