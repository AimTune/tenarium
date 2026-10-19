package server_test

import (
	"context"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var flowRe = regexp.MustCompile(`name="flow" value="([^"]+)"`)

func formFlow(t *testing.T, body string) string {
	t.Helper()
	m := flowRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no flow in page: %s", body)
	}
	return html.UnescapeString(m[1])
}

func TestOpenIDProvider(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	cfg.Users.PublicURL = base
	cfg.Auth.RateLimit = 0
	serveOn(t, ln, cfg)
	c := client{t: t, base: base}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	c.do("POST", "/v1/users", map[string]any{"email": "ann@example.com", "name": "Ann", "password": "ann long passphrase"})
	c.do("POST", "/v1/tenants/acme/members", map[string]any{"email": "ann@example.com", "role": "admin"})

	const redirect = "http://127.0.0.1:9/callback"
	code, created := c.do("POST", "/v1/oauth-clients", map[string]any{"name": "Acme App", "redirect_uris": []string{redirect}})
	if code != 201 || created["client_secret"] == nil {
		t.Fatalf("create client: %d %v", code, created)
	}
	clientID := created["client"].(map[string]any)["client_id"].(string)

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, base)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	oc := oauth2.Config{ClientID: clientID, ClientSecret: created["client_secret"].(string), Endpoint: provider.Endpoint(),
		RedirectURL: redirect, Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
	verifier := oauth2.GenerateVerifier()
	authURL := oc.AuthCodeURL("st-1", oidc.Nonce("n-1"), oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("tenant", "acme"))

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(u string) (*http.Response, string) {
		resp, err := browser.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}
	post := func(path string, form url.Values) (*http.Response, string) {
		resp, err := browser.PostForm(base+path, form)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}

	resp, page := get(authURL)
	if resp.StatusCode != 200 || !strings.Contains(page, "Acme App") {
		t.Fatalf("login page: %d %s", resp.StatusCode, page)
	}
	if resp, _ := post("/oauth/login", url.Values{"flow": {formFlow(t, page)}, "email": {"ann@example.com"}, "password": {"wrong"}}); resp.StatusCode != 401 {
		t.Fatalf("wrong password: %d", resp.StatusCode)
	}
	resp, page = post("/oauth/login", url.Values{"flow": {formFlow(t, page)}, "email": {"ann@example.com"}, "password": {"ann long passphrase"}})
	if resp.StatusCode != 200 || !strings.Contains(page, "See your email address") {
		t.Fatalf("consent page: %d %s", resp.StatusCode, page)
	}
	resp, _ = post("/oauth/consent", url.Values{"flow": {formFlow(t, page)}, "decision": {"allow"}})
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc.Query().Get("state") != "st-1" || loc.Query().Get("code") == "" || loc.Query().Get("iss") != base {
		t.Fatalf("callback: %d %v", resp.StatusCode, loc)
	}
	authCode := loc.Query().Get("code")

	tok, err := oc.Exchange(ctx, authCode, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.RefreshToken != "" {
		t.Fatal("refresh token without offline_access")
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, rawID)
	if err != nil {
		t.Fatalf("id token: %v", err)
	}
	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
		TID   string `json:"tid"`
	}
	_ = idt.Claims(&claims)
	if idt.Nonce != "n-1" || claims.Email != "ann@example.com" || claims.Name != "Ann" || claims.TID == "" {
		t.Fatalf("claims: %+v nonce=%s", claims, idt.Nonce)
	}
	ui, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil || ui.Email != "ann@example.com" {
		t.Fatalf("userinfo: %+v %v", ui, err)
	}
	// The access token works against the Tenarium API, scoped to the tenant.
	if code, _ := as(c, tok.AccessToken)("GET", "/v1/tenants/acme", nil); code != 200 {
		t.Fatalf("api with access token: %d", code)
	}
	if _, err := oc.Exchange(ctx, authCode, oauth2.VerifierOption(verifier)); err == nil {
		t.Fatal("code redeemed twice")
	}

	// Second sign-in: session cookie and stored consent mean a direct redirect.
	resp, _ = get(oc.AuthCodeURL("st-2", oidc.Nonce("n-2"), oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("tenant", "acme")))
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), redirect) {
		t.Fatalf("silent re-auth: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Wrong PKCE verifier fails.
	l2, _ := url.Parse(resp.Header.Get("Location"))
	if _, err := oc.Exchange(ctx, l2.Query().Get("code"), oauth2.VerifierOption("wrong-verifier-wrong-verifier-wrong-verifier")); err == nil {
		t.Fatal("wrong verifier accepted")
	}

	// An unregistered redirect URI is never redirected to.
	bad := strings.Replace(authURL, url.QueryEscape(redirect), url.QueryEscape("https://evil.example/cb"), 1)
	if resp, _ := get(bad); resp.StatusCode != 400 {
		t.Fatalf("unregistered redirect: %d", resp.StatusCode)
	}
	// Public clients must use PKCE.
	_, pub := c.do("POST", "/v1/oauth-clients", map[string]any{"name": "SPA", "public": true, "redirect_uris": []string{redirect}})
	pubID := pub["client"].(map[string]any)["client_id"].(string)
	resp, _ = get(base + "/oauth/authorize?" + url.Values{"client_id": {pubID}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid"}}.Encode())
	if l, _ := url.Parse(resp.Header.Get("Location")); resp.StatusCode != 302 || l.Query().Get("error") != "invalid_request" {
		t.Fatalf("public client without PKCE: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}
