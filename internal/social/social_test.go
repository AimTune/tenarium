package social

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/internal/tenant"
)

const publicURL = "https://tenarium.test"

// recorder is a SignInFunc that records its calls.
type recorder struct {
	mu    sync.Mutex
	calls []call
	err   error
}

type call struct {
	id     Identity
	tenant string
}

func (s *recorder) signIn(_ context.Context, id Identity, ref string) (tenant.TokenPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, call{id, ref})
	if s.err != nil {
		return tenant.TokenPair{}, s.err
	}
	return tenant.TokenPair{AccessToken: "access-1", RefreshToken: "refresh-1", TokenType: "Bearer", ExpiresIn: 900, TenantID: "t-1"}, nil
}

func (s *recorder) last(t *testing.T) call {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		t.Fatal("sign-in function not called")
	}
	return s.calls[len(s.calls)-1]
}

func (s *recorder) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

type env struct {
	t    *testing.T
	h    *Handler
	mux  *http.ServeMux
	rec  *recorder
	oidc *fakeOIDC
	gh   *fakeGitHub
}

func newEnv(t *testing.T, mutate ...func(*Config)) *env {
	t.Helper()
	iss := identity.NewIssuer(memory.New(), publicURL, "tenarium", time.Minute)
	if err := iss.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, rec: &recorder{}, oidc: newFakeOIDC(t), gh: newFakeGitHub(t)}
	cfg := Config{
		PublicURL:           publicURL + "/",
		AllowedRedirects:    []string{"https://app.example.com"},
		AllowPrivateIssuers: true,
		Providers: []ProviderConfig{
			{Name: "okta", Type: TypeOIDC, Label: "Okta", ClientID: testClientID, ClientSecret: testClientSecret, Issuer: e.oidc.srv.URL, AutoCreate: true},
			{Name: "github", Type: TypeGitHub, ClientID: testClientID, ClientSecret: testClientSecret,
				AuthURL: e.gh.srv.URL + "/login/oauth/authorize", TokenURL: e.gh.srv.URL + "/login/oauth/access_token", APIURL: e.gh.srv.URL + "/api/"},
		},
	}
	for _, m := range mutate {
		m(&cfg)
	}
	h, err := New(cfg, iss, e.rec.signIn, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	e.mux = http.NewServeMux()
	for _, r := range h.Routes() {
		e.mux.HandleFunc(r.Pattern, r.Handler)
	}
	return e
}

func (e *env) get(target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	return w
}

// flow is a started sign-in: the state cookie and the authorization URL.
type flow struct {
	cookie *http.Cookie
	auth   *url.URL
}

func (e *env) start(provider, query string) flow {
	e.t.Helper()
	w := e.get("/v1/auth/social/" + provider + "/start?" + query)
	if w.Code != http.StatusFound {
		e.t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			return flow{cookie: c, auth: loc}
		}
	}
	e.t.Fatal("no state cookie")
	return flow{}
}

func (f flow) param(k string) string { return f.auth.Query().Get(k) }

// callback calls back with code (registered at the fake for this flow)
// and returns the redirect target.
func (e *env) callback(provider string, f flow, extra string) (*httptest.ResponseRecorder, url.Values) {
	e.t.Helper()
	q := url.Values{"state": {f.param("state")}, "code": {"code-1"}}
	w := e.get("/v1/auth/social/"+provider+"/callback?"+q.Encode()+extra, f.cookie)
	if w.Code != http.StatusFound {
		return w, nil
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	frag, err := url.ParseQuery(loc.Fragment)
	if err != nil {
		e.t.Fatal(err)
	}
	return w, frag
}

// oidcFlow runs the whole OIDC flow and returns the fragment.
func (e *env) oidcFlow(provider string) url.Values {
	e.t.Helper()
	f := e.start(provider, "")
	e.oidc.authorize("code-1", f.param("code_challenge"), f.param("nonce"))
	w, frag := e.callback(provider, f, "")
	if frag == nil {
		e.t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	return frag
}

func TestOIDCSignIn(t *testing.T) {
	e := newEnv(t)
	f := e.start("okta", "tenant=acme&return_to="+url.QueryEscape("https://app.example.com/after?x=1#old"))

	if got := f.auth.Scheme + "://" + f.auth.Host + f.auth.Path; got != e.oidc.srv.URL+"/authorize" {
		t.Fatalf("authorization endpoint %s", got)
	}
	want := map[string]string{
		"client_id": testClientID, "response_type": "code", "code_challenge_method": "S256",
		"redirect_uri": publicURL + "/v1/auth/social/okta/callback", "scope": "openid email profile",
	}
	for k, v := range want {
		if got := f.param(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if f.param(k) == "" {
			t.Errorf("missing %s", k)
		}
	}
	if !f.cookie.HttpOnly || !f.cookie.Secure || f.cookie.Path != cookiePath || f.cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie attributes: %+v", f.cookie)
	}
	if strings.Contains(f.cookie.Value, f.param("nonce")) {
		t.Error("state cookie should be a signed token, not plain")
	}

	// The fake token endpoint only answers when the PKCE verifier matches.
	e.oidc.authorize("code-1", f.param("code_challenge"), f.param("nonce"))
	w, frag := e.callback("okta", f, "")
	if frag == nil {
		t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if got := loc.Scheme + "://" + loc.Host + loc.Path + "?" + loc.RawQuery; got != "https://app.example.com/after?x=1" {
		t.Errorf("redirected to %s", got)
	}
	if frag.Get("access_token") != "access-1" || frag.Get("refresh_token") != "refresh-1" || frag.Get("token_type") != "Bearer" ||
		frag.Get("expires_in") != "900" || frag.Get("tenant_id") != "t-1" || frag.Get("error") != "" {
		t.Errorf("fragment %v", frag)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Error("missing no-store / no-referrer")
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		cleared = cleared || (c.Name == cookieName && c.MaxAge < 0)
	}
	if !cleared {
		t.Error("state cookie not cleared")
	}
	c := e.rec.last(t)
	wantID := Identity{Provider: "okta", Type: TypeOIDC, Subject: "user-123", Email: "ada@example.com", Name: "Ada Lovelace", AutoCreate: true}
	if c.id != wantID || c.tenant != "acme" {
		t.Errorf("sign-in got %+v tenant %q", c.id, c.tenant)
	}

	// The code cannot be replayed with the same state.
	if _, frag := e.callback("okta", f, ""); frag.Get("error") != "idp_error" {
		t.Errorf("replay: %v", frag)
	}
}

func TestDefaultReturnTo(t *testing.T) {
	e := newEnv(t)
	f := e.start("okta", "")
	e.oidc.authorize("code-1", f.param("code_challenge"), f.param("nonce"))
	w, _ := e.callback("okta", f, "")
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, publicURL+"/ui/#") {
		t.Errorf("redirected to %s", loc)
	}
}

func TestDiscoveryCached(t *testing.T) {
	e := newEnv(t)
	e.oidcFlow("okta")
	e.oidcFlow("okta")
	if e.oidc.discoveries != 1 {
		t.Errorf("discovery fetched %d times", e.oidc.discoveries)
	}
}

func TestGoogleType(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.Providers = []ProviderConfig{{Name: "google", Type: TypeGoogle, ClientID: testClientID, ClientSecret: testClientSecret, Issuer: c.Providers[0].Issuer}}
	})
	if frag := e.oidcFlow("google"); frag.Get("access_token") == "" {
		t.Fatalf("google: %v", frag)
	}
	if id := e.rec.last(t).id; id.Type != TypeGoogle || id.Provider != "google" || id.AutoCreate {
		t.Errorf("identity %+v", id)
	}
}

func TestMicrosoftMultiTenant(t *testing.T) {
	setup := func(t *testing.T) *env {
		e := newEnv(t, func(c *Config) {
			c.Providers = []ProviderConfig{{Name: "microsoft", Type: TypeMicrosoft, ClientID: testClientID, ClientSecret: testClientSecret,
				Issuer: c.Providers[0].Issuer + "/organizations/v2.0", AllowedDomains: []string{"Contoso.com"}}}
		})
		e.oidc.set(func(f *fakeOIDC) {
			f.discoveryIssuer = f.srv.URL + "/{tenantid}/v2.0"
			f.tokenIssuer = f.srv.URL + "/tid-1/v2.0"
			f.claims = map[string]any{"email": "bob@contoso.com", "email_verified": nil, "xms_edov": true, "tid": "tid-1", "name": "Bob"}
		})
		return e
	}

	t.Run("ok", func(t *testing.T) {
		e := setup(t)
		if frag := e.oidcFlow("microsoft"); frag.Get("access_token") == "" {
			t.Fatalf("fragment %v", frag)
		}
		if id := e.rec.last(t).id; id.Email != "bob@contoso.com" || id.Type != TypeMicrosoft {
			t.Errorf("identity %+v", id)
		}
	})
	t.Run("issuer of another directory", func(t *testing.T) {
		e := setup(t)
		e.oidc.set(func(f *fakeOIDC) { f.tokenIssuer = f.srv.URL + "/tid-2/v2.0" })
		if frag := e.oidcFlow("microsoft"); frag.Get("error") != "idp_error" {
			t.Fatalf("fragment %v", frag)
		}
	})
	t.Run("missing tid", func(t *testing.T) {
		e := setup(t)
		e.oidc.set(func(f *fakeOIDC) { f.claims["tid"] = nil })
		if frag := e.oidcFlow("microsoft"); frag.Get("error") != "idp_error" {
			t.Fatalf("fragment %v", frag)
		}
	})
	t.Run("email not domain-verified", func(t *testing.T) {
		e := setup(t)
		e.oidc.set(func(f *fakeOIDC) { f.claims["xms_edov"] = nil })
		if frag := e.oidcFlow("microsoft"); frag.Get("error") != "email_unverified" {
			t.Fatalf("fragment %v", frag)
		}
	})
	t.Run("single tenant", func(t *testing.T) {
		e := setup(t)
		e.oidc.set(func(f *fakeOIDC) { f.discoveryIssuer = f.srv.URL + "/tid-1/v2.0" })
		if frag := e.oidcFlow("microsoft"); frag.Get("access_token") == "" {
			t.Fatalf("fragment %v", frag)
		}
	})
}

func TestGitHub(t *testing.T) {
	run := func(e *env) url.Values {
		f := e.start("github", "tenant=t-9")
		if f.param("nonce") != "" || f.param("code_challenge_method") != "S256" || f.param("scope") != "read:user user:email" {
			t.Errorf("authorization URL %s", f.auth)
		}
		e.gh.mu.Lock()
		e.gh.codes["code-1"] = f.param("code_challenge")
		e.gh.mu.Unlock()
		w, frag := e.callback("github", f, "")
		if frag == nil {
			t.Fatalf("callback: %d %s", w.Code, w.Body)
		}
		return frag
	}
	t.Run("primary verified", func(t *testing.T) {
		e := newEnv(t)
		if frag := run(e); frag.Get("access_token") != "access-1" {
			t.Fatalf("fragment %v", frag)
		}
		c := e.rec.last(t)
		want := Identity{Provider: "github", Type: TypeGitHub, Subject: "4242", Email: "grace@example.com", Name: "grace"}
		if c.id != want || c.tenant != "t-9" {
			t.Errorf("got %+v %q", c.id, c.tenant)
		}
	})
	t.Run("primary unverified", func(t *testing.T) {
		e := newEnv(t)
		e.gh.emails = []ghEmail{{"verified@example.com", false, true}, {"primary@example.com", true, false}}
		if frag := run(e); frag.Get("error") != "email_unverified" {
			t.Fatalf("fragment %v", frag)
		}
		if e.rec.count() != 0 {
			t.Error("sign-in called")
		}
	})
	t.Run("no emails", func(t *testing.T) {
		e := newEnv(t)
		e.gh.emails = nil
		if frag := run(e); frag.Get("error") != "email_unverified" {
			t.Fatalf("fragment %v", frag)
		}
	})
	t.Run("token error", func(t *testing.T) {
		e := newEnv(t)
		f := e.start("github", "")
		// Not registered at the fake: GitHub answers 200 with an error.
		if _, frag := e.callback("github", f, ""); frag.Get("error") != "idp_error" {
			t.Fatalf("fragment %v", frag)
		}
	})
	t.Run("api error", func(t *testing.T) {
		e := newEnv(t)
		e.gh.user = nil // encodes as null: no id
		if frag := run(e); frag.Get("error") != "idp_error" {
			t.Fatalf("fragment %v", frag)
		}
	})
}

func TestStateProtection(t *testing.T) {
	e := newEnv(t)
	started := func() flow {
		f := e.start("okta", "")
		e.oidc.authorize("code-1", f.param("code_challenge"), f.param("nonce"))
		return f
	}
	expectInvalid := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_state") {
			t.Fatalf("got %d %s", w.Code, w.Body)
		}
		if e.rec.count() != 0 {
			t.Fatal("sign-in called")
		}
	}

	t.Run("missing cookie", func(t *testing.T) {
		f := started()
		expectInvalid(t, e.get("/v1/auth/social/okta/callback?code=code-1&state="+url.QueryEscape(f.param("state"))))
	})
	t.Run("state mismatch", func(t *testing.T) {
		f := started()
		expectInvalid(t, e.get("/v1/auth/social/okta/callback?code=code-1&state=forged", f.cookie))
	})
	t.Run("tampered cookie", func(t *testing.T) {
		f := started()
		parts := strings.Split(f.cookie.Value, ".")
		payload := parts[1]
		parts[1] = payload[:len(payload)-2] + flip(payload[len(payload)-2:])
		f.cookie.Value = strings.Join(parts, ".")
		w, _ := e.callback("okta", f, "")
		expectInvalid(t, w)
	})
	t.Run("forged signature", func(t *testing.T) {
		other := newEnv(t)
		f := other.start("okta", "") // signed by another key
		w, _ := e.callback("okta", f, "")
		expectInvalid(t, w)
	})
	t.Run("other provider", func(t *testing.T) {
		f := started()
		w, _ := e.callback("github", f, "")
		expectInvalid(t, w)
	})
	t.Run("expired", func(t *testing.T) {
		f := started()
		e.h.now = func() time.Time { return time.Now().Add(stateTTL + time.Second) }
		defer func() { e.h.now = time.Now }()
		w, _ := e.callback("okta", f, "")
		expectInvalid(t, w)
	})
}

func flip(s string) string {
	if strings.HasPrefix(s, "A") {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}

func TestIDTokenChecks(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		domain []string
		code   string
	}{
		{"nonce mismatch", map[string]any{"nonce": "other"}, nil, "idp_error"},
		{"wrong audience", map[string]any{"aud": "someone-else"}, nil, "idp_error"},
		{"expired", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}, nil, "idp_error"},
		{"unverified email", map[string]any{"email_verified": false}, nil, "email_unverified"},
		{"email_verified absent", map[string]any{"email_verified": nil}, nil, "email_unverified"},
		{"no email", map[string]any{"email": nil}, nil, "email_unverified"},
		{"verified as string", map[string]any{"email_verified": "true"}, nil, ""},
		{"disallowed domain", nil, []string{"corp.example"}, "domain_not_allowed"},
		{"subdomain is not the domain", map[string]any{"email": "a@evil.example.com"}, []string{"example.com"}, "domain_not_allowed"},
		{"allowed domain", nil, []string{"other.org", "EXAMPLE.com"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, func(c *Config) { c.Providers[0].AllowedDomains = tc.domain })
			e.oidc.set(func(f *fakeOIDC) {
				for k, v := range tc.claims {
					f.claims[k] = v
				}
			})
			// nonce/aud/exp overrides are applied after the base claims.
			frag := e.oidcFlow("okta")
			if got := frag.Get("error"); got != tc.code {
				t.Fatalf("error = %q, want %q (%v)", got, tc.code, frag)
			}
			if (tc.code == "") != (e.rec.count() == 1) {
				t.Errorf("sign-in calls: %d", e.rec.count())
			}
			if tc.code != "" && frag.Get("access_token") != "" {
				t.Error("tokens returned on failure")
			}
		})
	}
}

func TestProviderErrors(t *testing.T) {
	t.Run("error from provider", func(t *testing.T) {
		e := newEnv(t)
		f := e.start("okta", "")
		if _, frag := e.callback("okta", f, "&error=access_denied"); frag.Get("error") != "idp_error" {
			t.Fatalf("fragment %v", frag)
		}
	})
	t.Run("token endpoint fails", func(t *testing.T) {
		e := newEnv(t)
		e.oidc.set(func(f *fakeOIDC) { f.tokenFail = true })
		if frag := e.oidcFlow("okta"); frag.Get("error") != "idp_error" {
			t.Fatalf("fragment %v", frag)
		}
	})
	t.Run("wrong PKCE verifier", func(t *testing.T) {
		e := newEnv(t)
		f := e.start("okta", "")
		e.oidc.authorize("code-1", "challenge-of-another-verifier", f.param("nonce"))
		if _, frag := e.callback("okta", f, ""); frag.Get("error") != "idp_error" {
			t.Fatalf("fragment %v", frag)
		}
	})
	t.Run("discovery fails", func(t *testing.T) {
		e := newEnv(t)
		e.oidc.srv.Close()
		w := e.get("/v1/auth/social/okta/start")
		if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "idp_unavailable") {
			t.Fatalf("got %d %s", w.Code, w.Body)
		}
	})
	t.Run("issuer mismatch", func(t *testing.T) {
		e := newEnv(t)
		e.oidc.set(func(f *fakeOIDC) { f.discoveryIssuer = "https://evil.example" })
		if w := e.get("/v1/auth/social/okta/start"); w.Code != http.StatusBadGateway {
			t.Fatalf("got %d %s", w.Code, w.Body)
		}
	})
}

func TestSignInErrors(t *testing.T) {
	for err, code := range map[error]string{
		ErrRejected:                                 "access_denied",
		fmt.Errorf("wrapped: %w", ErrRejected):      "access_denied",
		tenant.ErrSSORejected:                       "access_denied",
		tenant.ErrSSORequired:                       "sso_required",
		tenant.ErrMFARequired:                       "mfa_required",
		tenant.ErrTenantRequired:                    "tenant_required",
		tenant.ErrAccountLocked:                     "account_locked",
		errors.New("database on fire: secret info"): "server_error",
	} {
		e := newEnv(t)
		e.rec.err = err
		frag := e.oidcFlow("okta")
		if frag.Get("error") != code || frag.Get("access_token") != "" || len(frag) != 1 {
			t.Errorf("%v: fragment %v, want %s", err, frag, code)
		}
	}
}

func TestReturnTo(t *testing.T) {
	e := newEnv(t)
	for _, bad := range []string{
		"https://evil.example/",
		"//evil.example/",
		"/relative",
		"javascript:alert(1)",
		"https://tenarium.test@evil.example/",
		"https://user:pw@tenarium.test/",
		"https://tenarium.test.evil.example/",
		"https://app.example.com.evil.example/",
		"http://app.example.com/", // scheme is part of the origin
		"https://tenarium.test:8443/",
		"https:\\\\evil.example",
		"data:text/html,hi",
		"ftp://tenarium.test/",
	} {
		w := e.get("/v1/auth/social/okta/start?return_to=" + url.QueryEscape(bad))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_return_to") {
			t.Errorf("%q: %d %s", bad, w.Code, w.Body)
		}
	}
	for _, good := range []string{"https://tenarium.test/ui/x", "https://APP.example.com/cb", "https://app.example.com"} {
		if w := e.get("/v1/auth/social/okta/start?return_to=" + url.QueryEscape(good)); w.Code != http.StatusFound {
			t.Errorf("%q: %d %s", good, w.Code, w.Body)
		}
	}
}

func TestUnknownProvider(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/v1/auth/social/nope/start", "/v1/auth/social/nope/callback?state=x&code=y"} {
		w := e.get(p)
		if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "unknown_provider") {
			t.Errorf("%s: %d %s", p, w.Code, w.Body)
		}
	}
	if w := e.get("/v1/auth/social/okta/start?tenant=" + strings.Repeat("a", 300)); w.Code != http.StatusBadRequest {
		t.Errorf("long tenant: %d", w.Code)
	}
}

func TestList(t *testing.T) {
	e := newEnv(t)
	w := e.get("/v1/auth/social")
	body := w.Body.String()
	want := `{"providers":[{"name":"okta","label":"Okta","type":"oidc"},{"name":"github","label":"GitHub","type":"github"}]}`
	if w.Code != http.StatusOK || strings.TrimSpace(body) != want {
		t.Fatalf("got %d %s", w.Code, body)
	}
	if strings.Contains(body, testClientSecret) || strings.Contains(body, testClientID) {
		t.Error("list leaks client credentials")
	}
	if !e.h.Enabled() || e.h.CallbackURL("github") != publicURL+"/v1/auth/social/github/callback" {
		t.Error("Enabled/CallbackURL")
	}
}

func TestValidate(t *testing.T) {
	ok := ProviderConfig{Name: "g", Type: TypeGoogle, ClientID: "id", ClientSecret: "s"}
	cases := []struct {
		name string
		cfg  Config
		err  string
	}{
		{"ok", Config{PublicURL: publicURL, Providers: []ProviderConfig{ok}}, ""},
		{"no providers", Config{PublicURL: publicURL}, ""},
		{"no public url", Config{Providers: []ProviderConfig{ok}}, "public_url"},
		{"bad redirect", Config{PublicURL: publicURL, AllowedRedirects: []string{"/x"}}, "allowed_redirects"},
		{"bad name", Config{PublicURL: publicURL, Providers: []ProviderConfig{{Name: "Bad Name", Type: TypeGoogle, ClientID: "i", ClientSecret: "s"}}}, "name"},
		{"duplicate", Config{PublicURL: publicURL, Providers: []ProviderConfig{ok, ok}}, "duplicate"},
		{"unknown type", Config{PublicURL: publicURL, Providers: []ProviderConfig{{Name: "x", Type: "saml", ClientID: "i", ClientSecret: "s"}}}, "unknown type"},
		{"no secret", Config{PublicURL: publicURL, Providers: []ProviderConfig{{Name: "x", Type: TypeGoogle, ClientID: "i"}}}, "client_secret"},
		{"oidc without issuer", Config{PublicURL: publicURL, Providers: []ProviderConfig{{Name: "x", Type: TypeOIDC, ClientID: "i", ClientSecret: "s"}}}, "issuer"},
		{"http issuer", Config{PublicURL: publicURL, Providers: []ProviderConfig{{Name: "x", Type: TypeOIDC, ClientID: "i", ClientSecret: "s", Issuer: "http://idp.example"}}}, "https"},
		{"private issuer", Config{PublicURL: publicURL, Providers: []ProviderConfig{{Name: "x", Type: TypeOIDC, ClientID: "i", ClientSecret: "s", Issuer: "https://127.0.0.1"}}}, "not allowed"},
		{"private issuer allowed", Config{PublicURL: publicURL, AllowPrivateIssuers: true, Providers: []ProviderConfig{{Name: "x", Type: TypeOIDC, ClientID: "i", ClientSecret: "s", Issuer: "http://127.0.0.1"}}}, ""},
		{"microsoft without tenant", Config{PublicURL: publicURL, Providers: []ProviderConfig{{Name: "m", Type: TypeMicrosoft, ClientID: "i", ClientSecret: "s"}}}, "tenant"},
		{"microsoft bad tenant", Config{PublicURL: publicURL, Providers: []ProviderConfig{{Name: "m", Type: TypeMicrosoft, ClientID: "i", ClientSecret: "s", Tenant: "a/b"}}}, "tenant"},
		{"microsoft", Config{PublicURL: publicURL, Providers: []ProviderConfig{{Name: "m", Type: TypeMicrosoft, ClientID: "i", ClientSecret: "s", Tenant: "organizations"}}}, ""},
		{"github bad url", Config{PublicURL: publicURL, Providers: []ProviderConfig{{Name: "gh", Type: TypeGitHub, ClientID: "i", ClientSecret: "s", APIURL: "http://x"}}}, "https"},
		{"bad domain", Config{PublicURL: publicURL, Providers: []ProviderConfig{{Name: "g", Type: TypeGoogle, ClientID: "i", ClientSecret: "s", AllowedDomains: []string{"@x.com"}}}}, "allowed_domains"},
	}
	for _, tc := range cases {
		err := tc.cfg.Validate()
		if (err == nil) != (tc.err == "") || (err != nil && !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestProviderDefaults(t *testing.T) {
	g := newProvider(ProviderConfig{Name: "g", Type: TypeGoogle, Scopes: []string{"email"}})
	if g.issuer != googleIssuer || strings.Join(g.scopes, " ") != "openid email" || g.label != "Google" {
		t.Errorf("google: %+v", g)
	}
	m := newProvider(ProviderConfig{Name: "m", Type: TypeMicrosoft, Tenant: "common"})
	if m.issuer != "https://login.microsoftonline.com/common/v2.0" || m.label != "Microsoft" {
		t.Errorf("microsoft: %+v", m)
	}
	gh := newProvider(ProviderConfig{Name: "gh", Type: TypeGitHub})
	if gh.cfg.AuthURL != githubAuthURL || gh.cfg.TokenURL != githubTokenURL || gh.cfg.APIURL != githubAPIURL {
		t.Errorf("github: %+v", gh.cfg)
	}
}

func TestNewRequiresDeps(t *testing.T) {
	if _, err := New(Config{PublicURL: publicURL}, nil, nil, nil); err == nil {
		t.Error("expected error")
	}
	if _, err := New(Config{}, nil, nil, nil); err == nil {
		t.Error("expected validation error")
	}
}
