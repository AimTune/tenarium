package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/server"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIdP is a minimal OpenID provider: it "authenticates" whoever it is
// told to and checks PKCE and client credentials at the token endpoint.
type fakeIdP struct {
	t     *testing.T
	srv   *httptest.Server
	key   *ecdsa.PrivateKey
	mu    sync.Mutex
	email string
	codes map[string]idpCode
}

type idpCode struct{ nonce, challenge, clientID string }

func newFakeIdP(t *testing.T) *fakeIdP {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := &fakeIdP{t: t, key: key, codes: map[string]idpCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize", "token_endpoint": p.srv.URL + "/token",
			"jwks_uri": p.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"ES256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
			http.Error(w, "pkce and nonce required", 400)
			return
		}
		code := randomString()
		p.mu.Lock()
		p.codes[code] = idpCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), clientID: q.Get("client_id")}
		p.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, secret, ok := r.BasicAuth()
		if !ok {
			id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		p.mu.Lock()
		c, found := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		email := p.email
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !found || id != "tenarium" || secret != "s3cret" || c.clientID != id ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		now := time.Now()
		idt, _ := jwt.Signed(signer).Claims(jwt.Claims{
			Issuer: p.srv.URL, Subject: "sub-" + email, Audience: jwt.Audience{id},
			IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute)),
		}).Claims(map[string]any{"email": email, "email_verified": true, "name": "Ann", "nonce": c.nonce}).Serialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idt, "expires_in": 60})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeIdP) assert(email string) {
	p.mu.Lock()
	p.email = email
	p.mu.Unlock()
}

func randomString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// browserLogin follows the SSO redirects like a browser and returns the
// fragment Tenarium sends back.
func browserLogin(t *testing.T, base, query string) (url.Values, int) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	var fragment string
	errDone := errors.New("done")
	hc := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Path == "/ui/" {
			fragment = req.URL.Fragment
			return errDone
		}
		return nil
	}}
	resp, err := hc.Get(base + "/v1/auth/sso/start?" + query)
	if err != nil && !errors.Is(err, errDone) {
		t.Fatal(err)
	}
	if resp != nil {
		resp.Body.Close()
		if fragment == "" {
			return nil, resp.StatusCode
		}
	}
	v, _ := url.ParseQuery(fragment)
	return v, http.StatusFound
}

func TestTenantSSO(t *testing.T) {
	idp := newFakeIdP(t)
	dns := &fakeDNS{records: map[string][]string{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	cfg.Users.PublicURL = base
	cfg.Auth.RateLimit = 0
	cfg.Auth.SSO.AllowPrivateIssuers = true
	cfg.Bootstrap.Users = []server.BootstrapUser{{Email: "root@acme.example", Password: "root password long enough", Roles: []string{"admin"}}}
	serveOn(t, ln, cfg, server.WithTXTResolver(dns.lookup))
	c := client{t: t, base: base}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})

	conn := map[string]any{"issuer": idp.srv.URL, "client_id": "tenarium", "client_secret": "s3cret",
		"domains": []string{"acme.example"}, "auto_provision": true}
	if code, body := c.do("PUT", "/v1/tenants/acme/sso", conn); code != 400 {
		t.Fatalf("unverified domain accepted: %d %v", code, body)
	}
	_, added := c.do("POST", "/v1/tenants/acme/domains", map[string]any{"hostname": "acme.example"})
	instr := added["instructions"].(map[string]any)
	dns.mu.Lock()
	dns.records[instr["name"].(string)] = []string{instr["value"].(string)}
	dns.mu.Unlock()
	c.do("POST", "/v1/tenants/acme/domains/acme.example/verify", nil)
	code, saved := c.do("PUT", "/v1/tenants/acme/sso", conn)
	if code != 200 || saved["client_secret"] != nil || saved["default_role"] != "member" {
		t.Fatalf("put sso: %d %v", code, saved)
	}

	// First sign-in provisions the user and membership.
	idp.assert("ann@acme.example")
	frag, status := browserLogin(t, base, "tenant=acme")
	if frag.Get("access_token") == "" {
		t.Fatalf("no session: %d %v", status, frag)
	}
	me := as(c, frag.Get("access_token"))
	if code, who := me("GET", "/v1/me", nil); code != 200 || who["tenant_id"] == nil || who["authenticator"] != "core/token" {
		t.Fatalf("me: %d %v", code, who)
	}
	if code, _ := me("GET", "/v1/tenants/acme", nil); code != 200 {
		t.Fatalf("member read: %d", code)
	}
	// Domain discovery by email, and the session is reused on a second login.
	if frag, _ := browserLogin(t, base, "email=ann@acme.example"); frag.Get("refresh_token") == "" {
		t.Fatalf("login by email domain: %v", frag)
	}
	_, users := c.do("GET", "/v1/users", nil)
	anns := 0
	for _, u := range users["items"].([]any) {
		if u.(map[string]any)["email"] == "ann@acme.example" {
			anns++
		}
	}
	if anns != 1 {
		t.Fatalf("ann provisioned %d times", anns)
	}

	// The provider cannot assert identities outside the tenant's domains.
	idp.assert("root@elsewhere.example")
	if frag, _ := browserLogin(t, base, "tenant=acme"); frag.Get("error") != "sso_rejected" || frag.Get("access_token") != "" {
		t.Fatalf("foreign domain: %v", frag)
	}

	// Enforcement blocks password logins of the domain, except break-glass
	// platform logins.
	conn["enforce"] = true
	c.do("PUT", "/v1/tenants/acme/sso", conn)
	pw := func(email, tenant string) (int, map[string]any) {
		return c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "password", "email": email, "password": "root password long enough", "tenant": tenant})
	}
	if code, body := pw("ghost@acme.example", ""); code != 403 || body["error"].(map[string]any)["code"] != "sso_required" {
		t.Fatalf("unknown user of enforced domain: %d %v", code, body)
	}
	if code, _ := pw("root@acme.example", "acme"); code != 403 {
		t.Fatalf("tenant password login under enforcement: %d", code)
	}
	if code, _ := pw("root@acme.example", ""); code != 200 {
		t.Fatalf("break-glass platform login: %d", code)
	}
	resp, _ := http.Get(base + "/v1/auth/sso/discover?email=x@acme.example")
	var disc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&disc)
	resp.Body.Close()
	if disc["sso"] != true || disc["enforced"] != true || disc["tenant"] != "acme" {
		t.Fatalf("discover: %v", disc)
	}

	// Open redirects and forged callbacks are refused.
	if _, code := browserLogin(t, base, "tenant=acme&return_to="+url.QueryEscape("https://evil.example/x")); code != 400 {
		t.Fatalf("foreign return_to: %d", code)
	}
	resp, _ = http.Get(base + "/v1/auth/sso/callback?code=x&state=y")
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("callback without state cookie: %d", resp.StatusCode)
	}
	if code, _ := c.do("DELETE", "/v1/tenants/acme/sso", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if _, code := browserLogin(t, base, "tenant=acme"); code != 404 {
		t.Fatalf("start without connection: %d", code)
	}
}
