// Package sso implements the OpenID Connect authorization code flow
// (with PKCE and nonce) against each tenant's own identity provider. The
// tenant service decides who may sign in; this package only speaks the
// protocol.
package sso

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/netguard"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	cookieName    = "tenarium_sso"
	stateAudience = "tenarium-sso-state"
	stateTTL      = 10 * time.Minute
	providerTTL   = time.Hour
)

// Config configures the flow.
type Config struct {
	// PublicURL is where Tenarium is reachable; the callback registered at
	// providers is PublicURL + "/v1/auth/sso/callback".
	PublicURL string
	// AllowedRedirects are extra origins return_to may point to (besides
	// PublicURL's), e.g. the application's frontend.
	AllowedRedirects []string
	// AllowPrivateIssuers lets providers live on internal addresses
	// (development and tests).
	AllowPrivateIssuers bool
}

type Handler struct {
	tenants *tenant.Service
	issuer  *identity.Issuer
	cfg     Config
	client  *http.Client
	log     *slog.Logger

	mu        sync.Mutex
	providers map[string]cachedProvider
}

type cachedProvider struct {
	p       *oidc.Provider
	fetched time.Time
}

func New(tenants *tenant.Service, issuer *identity.Issuer, cfg Config, log *slog.Logger) *Handler {
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	return &Handler{
		tenants: tenants, issuer: issuer, cfg: cfg, log: log,
		// Issuers are chosen by tenants: guard against SSRF. Discovery may
		// redirect (each hop is checked at dial time).
		client:    netguard.NewClient(netguard.Options{Timeout: 10 * time.Second, AllowPrivate: cfg.AllowPrivateIssuers, FollowRedirects: true}),
		providers: map[string]cachedProvider{},
	}
}

func (h *Handler) callbackURL() string { return h.cfg.PublicURL + "/v1/auth/sso/callback" }

func (h *Handler) provider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	h.mu.Lock()
	c, ok := h.providers[issuer]
	h.mu.Unlock()
	if ok && time.Since(c.fetched) < providerTTL {
		return c.p, nil
	}
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, h.client), issuer)
	if err != nil {
		return nil, fmt.Errorf("identity provider %s: %w", issuer, err)
	}
	h.mu.Lock()
	h.providers[issuer] = cachedProvider{p: p, fetched: time.Now()}
	h.mu.Unlock()
	return p, nil
}

func oauthConfig(c store.SSOConnection, p *oidc.Provider, redirect string) *oauth2.Config {
	return &oauth2.Config{
		ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: redirect, Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
	}
}

// state travels in an HttpOnly cookie, bound to the browser that started
// the flow; only its random "state" value goes through the provider.
type state struct {
	TenantID string `json:"tid"`
	Issuer   string `json:"iss_url"`
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	ReturnTo string `json:"return_to"`
}

func random() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// returnTo validates where the browser is sent back with the tokens: only
// to Tenarium itself or an allowed origin, never an arbitrary site.
func (h *Handler) returnTo(raw string) (string, error) {
	if raw == "" {
		return h.cfg.PublicURL + "/ui/", nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return "", errors.New("return_to must be an absolute URL")
	}
	origin := u.Scheme + "://" + u.Host
	for _, allowed := range append([]string{h.cfg.PublicURL}, h.cfg.AllowedRedirects...) {
		if a, err := url.Parse(allowed); err == nil && strings.EqualFold(origin, a.Scheme+"://"+a.Host) {
			u.Fragment = ""
			return u.String(), nil
		}
	}
	return "", errors.New("return_to is not an allowed origin")
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":{"code":%q,"message":%q}}`, code, msg)
}

// Start redirects to the provider of ?tenant= (ID or slug) or, failing
// that, of ?email='s domain.
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ret, err := h.returnTo(q.Get("return_to"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_return_to", err.Error())
		return
	}
	conn, t, err := h.tenants.FindSSO(r.Context(), q.Get("tenant"), q.Get("email"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "sso_not_configured", "no single sign-on is configured for this tenant or email domain")
		return
	}
	if conn.Protocol == tenant.SSOProtocolSAML {
		h.startSAML(w, r, conn, t, ret)
		return
	}
	p, err := h.provider(r.Context(), conn.Issuer)
	if err != nil {
		h.log.Warn("sso discovery failed", "tenant", t.ID, "err", err)
		writeErr(w, http.StatusBadGateway, "idp_unavailable", "the identity provider could not be reached")
		return
	}
	st := state{TenantID: t.ID, Issuer: conn.Issuer, State: random(), Nonce: random(), Verifier: oauth2.GenerateVerifier(), ReturnTo: ret}
	signed, err := h.issuer.SignClaims(stateAudience, stateTTL, st)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: signed, Path: "/v1/auth/sso", MaxAge: int(stateTTL.Seconds()),
		HttpOnly: true, Secure: strings.HasPrefix(h.cfg.PublicURL, "https://"), SameSite: http.SameSiteLaxMode,
	})
	opts := []oauth2.AuthCodeOption{oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)}
	if e := q.Get("email"); e != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", e))
	}
	http.Redirect(w, r, oauthConfig(conn, p, h.callbackURL()).AuthCodeURL(st.State, opts...), http.StatusFound)
}

// Callback finishes the flow and sends the browser back to return_to with
// the session in the URL fragment (never sent to servers or logged).
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_state", "sign-in session expired or missing; start again")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/v1/auth/sso", MaxAge: -1, HttpOnly: true})
	var st state
	if err := h.issuer.VerifyClaims(c.Value, stateAudience, &st); err != nil ||
		subtle.ConstantTimeCompare([]byte(st.State), []byte(r.URL.Query().Get("state"))) != 1 {
		writeErr(w, http.StatusBadRequest, "invalid_state", "sign-in session is invalid; start again")
		return
	}
	pair, err := h.finish(r, st)
	if err != nil {
		code := "sso_failed"
		switch {
		case errors.Is(err, tenant.ErrSSORejected):
			code = "sso_rejected"
		case errors.Is(err, errProvider):
			code = "idp_error"
		}
		h.log.Info("sso sign-in failed", "tenant", st.TenantID, "err", err)
		redirectFragment(w, r, st.ReturnTo, url.Values{"error": {code}})
		return
	}
	redirectFragment(w, r, st.ReturnTo, sessionFragment(pair))
}

var errProvider = errors.New("identity provider error")

func (h *Handler) finish(r *http.Request, st state) (tenant.TokenPair, error) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		return tenant.TokenPair{}, fmt.Errorf("%w: %s", errProvider, e)
	}
	conn, _, err := h.tenants.FindSSO(r.Context(), st.TenantID, "")
	if err != nil || conn.Issuer != st.Issuer {
		return tenant.TokenPair{}, tenant.ErrSSORejected // changed since the flow started
	}
	ctx := oidc.ClientContext(r.Context(), h.client)
	p, err := h.provider(ctx, conn.Issuer)
	if err != nil {
		return tenant.TokenPair{}, fmt.Errorf("%w: %w", errProvider, err)
	}
	tok, err := oauthConfig(conn, p, h.callbackURL()).Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return tenant.TokenPair{}, fmt.Errorf("%w: code exchange: %w", errProvider, err)
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := p.Verifier(&oidc.Config{ClientID: conn.ClientID}).Verify(ctx, raw)
	if err != nil {
		return tenant.TokenPair{}, fmt.Errorf("%w: id token: %w", errProvider, err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		return tenant.TokenPair{}, fmt.Errorf("%w: nonce mismatch", errProvider)
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idt.Claims(&claims); err != nil {
		return tenant.TokenPair{}, fmt.Errorf("%w: claims: %w", errProvider, err)
	}
	return h.tenants.SSOSession(r.Context(), st.TenantID, tenant.SSOIdentity{
		Issuer: idt.Issuer, Subject: idt.Subject, Email: claims.Email, Name: claims.Name, EmailVerified: claims.EmailVerified,
	})
}

func redirectFragment(w http.ResponseWriter, r *http.Request, to string, v url.Values) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, to+"#"+v.Encode(), http.StatusFound)
}

// Discover tells a login form whether an email must (or can) use SSO.
func (h *Handler) Discover(w http.ResponseWriter, r *http.Request) {
	conn, t, err := h.tenants.FindSSO(r.Context(), "", r.URL.Query().Get("email"))
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_, _ = w.Write([]byte(`{"sso":false}`))
		return
	}
	_, _ = fmt.Fprintf(w, `{"sso":true,"enforced":%t,"tenant":%q}`, conn.Enforce, t.Slug)
}

// sessionFragment is the session handed to the browser after sign-in.
func sessionFragment(pair tenant.TokenPair) url.Values {
	return url.Values{
		"access_token": {pair.AccessToken}, "refresh_token": {pair.RefreshToken}, "token_type": {pair.TokenType},
		"expires_in": {strconv.Itoa(pair.ExpiresIn)}, "tenant_id": {pair.TenantID},
	}
}
