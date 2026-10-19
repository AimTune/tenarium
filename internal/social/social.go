// Package social implements platform-level social sign-in ("Sign in with
// Google / GitHub / Microsoft / any OpenID Connect provider") for
// Tenarium's users. It speaks the protocols (authorization code flow with
// PKCE, nonce and a signed, browser-bound state) and checks the email the
// provider vouches for; the tenant service, reached through SignInFunc,
// decides who may sign in and opens the session.
package social

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/netguard"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	cookieName    = "tenarium_social"
	cookiePath    = "/v1/auth/social"
	stateAudience = "tenarium-social-state"
	stateTTL      = 10 * time.Minute
	maxTenantRef  = 256
)

// Identity is a user authenticated by a provider. Email is lower-cased,
// verified by the provider and within the provider's AllowedDomains.
type Identity struct {
	// Provider is the configured provider name (ProviderConfig.Name).
	Provider string
	// Type is the provider type ("google", "github", ...).
	Type string
	// Subject is the provider's stable user ID.
	Subject string
	Email   string
	Name    string
	// AutoCreate is the provider's AutoCreate setting: the user may be
	// created when no user has Email yet.
	AutoCreate bool
}

// SignInFunc signs id in and opens a session. tenantRef is the ?tenant=
// of the start request (tenant ID or slug; empty for none). It is called
// only after the provider authenticated the user and the email was found
// verified and allowed. It must find the user by Email (creating it only
// if id.AutoCreate), refuse disabled users, enforce SSO and MFA policy,
// and open the session. Errors are reported to the browser as
// error=<code>: ErrRejected or tenant.ErrSSORejected → "access_denied",
// tenant.ErrSSORequired → "sso_required", tenant.ErrMFARequired →
// "mfa_required", tenant.ErrTenantRequired → "tenant_required",
// tenant.ErrAccountLocked → "account_locked"; anything else →
// "server_error" (and is logged).
type SignInFunc func(ctx context.Context, id Identity, tenantRef string) (tenant.TokenPair, error)

// ErrRejected is returned by a SignInFunc when the identity may not sign
// in (unknown user without AutoCreate, disabled user, ...).
var ErrRejected = errors.New("this identity cannot sign in")

// StateSigner signs the flow state; *identity.Issuer implements it.
type StateSigner interface {
	SignClaims(audience string, ttl time.Duration, extra any) (string, error)
	VerifyClaims(raw, audience string, out any) error
}

// Handler serves the social sign-in endpoints.
type Handler struct {
	cfg       Config
	states    StateSigner
	signIn    SignInFunc
	log       *slog.Logger
	client    *http.Client
	now       func() time.Time
	providers map[string]*provider
	order     []*provider
}

// New validates cfg and returns the handler.
func New(cfg Config, states StateSigner, signIn SignInFunc, log *slog.Logger) (*Handler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if states == nil || signIn == nil {
		return nil, errors.New("social: state signer and sign-in function are required")
	}
	if log == nil {
		log = slog.Default()
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	h := &Handler{
		cfg: cfg, states: states, signIn: signIn, log: log, now: time.Now,
		// Discovery may redirect; every hop is still checked at dial time.
		client:    netguard.NewClient(netguard.Options{Timeout: 10 * time.Second, AllowPrivate: cfg.AllowPrivateIssuers, FollowRedirects: true}),
		providers: map[string]*provider{},
	}
	for _, c := range cfg.Providers {
		p := newProvider(c)
		h.providers[c.Name] = p
		h.order = append(h.order, p)
		if c.AutoCreate && len(c.AllowedDomains) == 0 {
			log.Warn("social provider creates users for any email domain; consider allowed_domains", "provider", c.Name)
		}
	}
	return h, nil
}

// Enabled reports whether any provider is configured.
func (h *Handler) Enabled() bool { return len(h.order) > 0 }

// CallbackURL is the redirect URI to register at the provider name.
func (h *Handler) CallbackURL(name string) string {
	return h.cfg.PublicURL + cookiePath + "/" + name + "/callback"
}

// Route is an endpoint to mount.
type Route struct {
	Pattern string // net/http ServeMux pattern, with method
	Handler http.HandlerFunc
}

// Routes lists the endpoints (patterns use {provider}).
func (h *Handler) Routes() []Route {
	return []Route{
		{"GET /v1/auth/social", h.List},
		{"GET /v1/auth/social/{provider}/start", h.Start},
		{"GET /v1/auth/social/{provider}/callback", h.Callback},
	}
}

// ProviderInfo describes a provider to sign-in pages.
type ProviderInfo struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Type  string `json:"type"`
}

// Providers lists the configured providers, in configuration order.
func (h *Handler) Providers() []ProviderInfo {
	out := make([]ProviderInfo, 0, len(h.order))
	for _, p := range h.order {
		out = append(out, ProviderInfo{Name: p.cfg.Name, Label: p.label, Type: p.cfg.Type})
	}
	return out
}

// List serves GET /v1/auth/social: {"providers":[{name,label,type}]}.
func (h *Handler) List(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"providers": h.Providers()})
}

// state travels in an HttpOnly cookie, bound to the browser that started
// the flow; only its random "state" value goes through the provider.
type state struct {
	Provider string `json:"provider"`
	Tenant   string `json:"tenant,omitempty"`
	State    string `json:"state"`
	Nonce    string `json:"nonce,omitempty"`
	Verifier string `json:"verifier"`
	ReturnTo string `json:"return_to"`
	Started  int64  `json:"started"`
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
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":{"code":%q,"message":%q}}`, code, msg)
}

// Start serves GET /v1/auth/social/{provider}/start?tenant=&return_to=
// and redirects to the provider.
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	p, ok := h.providers[r.PathValue("provider")]
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown_provider", "no such sign-in provider")
		return
	}
	q := r.URL.Query()
	ret, err := h.returnTo(q.Get("return_to"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_return_to", err.Error())
		return
	}
	ref := q.Get("tenant")
	if len(ref) > maxTenantRef {
		writeErr(w, http.StatusBadRequest, "invalid_tenant", "tenant is too long")
		return
	}
	oc, err := p.oauth(r.Context(), h.client, h.CallbackURL(p.cfg.Name))
	if err != nil {
		h.log.Warn("social discovery failed", "provider", p.cfg.Name, "err", err)
		writeErr(w, http.StatusBadGateway, "idp_unavailable", "the identity provider could not be reached")
		return
	}
	st := state{Provider: p.cfg.Name, Tenant: ref, State: random(), Verifier: oauth2.GenerateVerifier(), ReturnTo: ret, Started: h.now().Unix()}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(st.Verifier)}
	if p.isOIDC() {
		st.Nonce = random()
		opts = append(opts, oidc.Nonce(st.Nonce))
	}
	signed, err := h.states.SignClaims(stateAudience, stateTTL, st)
	if err != nil {
		h.log.Error("social state signing failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: signed, Path: cookiePath, MaxAge: int(stateTTL.Seconds()),
		HttpOnly: true, Secure: strings.HasPrefix(h.cfg.PublicURL, "https://"), SameSite: http.SameSiteLaxMode,
	})
	if hint := q.Get("login_hint"); hint != "" && p.isOIDC() && len(hint) <= 320 {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", hint))
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, oc.AuthCodeURL(st.State, opts...), http.StatusFound)
}

// Callback serves GET /v1/auth/social/{provider}/callback: it finishes
// the flow and sends the browser back to return_to with the session in
// the URL fragment (never sent to servers or logged), or error=<code>.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	p, ok := h.providers[r.PathValue("provider")]
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown_provider", "no such sign-in provider")
		return
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_state", "sign-in session expired or missing; start again")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: cookiePath, MaxAge: -1, HttpOnly: true,
		Secure: strings.HasPrefix(h.cfg.PublicURL, "https://"), SameSite: http.SameSiteLaxMode})
	var st state
	if err := h.states.VerifyClaims(c.Value, stateAudience, &st); err != nil ||
		subtle.ConstantTimeCompare([]byte(st.State), []byte(r.URL.Query().Get("state"))) != 1 ||
		st.Provider != p.cfg.Name {
		writeErr(w, http.StatusBadRequest, "invalid_state", "sign-in session is invalid; start again")
		return
	}
	if age := h.now().Sub(time.Unix(st.Started, 0)); age > stateTTL || age < -time.Minute {
		writeErr(w, http.StatusBadRequest, "invalid_state", "sign-in session expired; start again")
		return
	}
	pair, err := h.finish(r, p, st)
	if err != nil {
		code := errorCode(err)
		if code == "server_error" {
			h.log.Error("social sign-in failed", "provider", p.cfg.Name, "err", err)
		} else {
			h.log.Info("social sign-in refused", "provider", p.cfg.Name, "code", code, "err", err)
		}
		redirectFragment(w, r, st.ReturnTo, url.Values{"error": {code}})
		return
	}
	redirectFragment(w, r, st.ReturnTo, sessionFragment(pair))
}

var (
	errProvider       = errors.New("identity provider error")
	errUnverified     = errors.New("email not verified by the provider")
	errDomainNotAllow = errors.New("email domain not allowed")
)

func errorCode(err error) string {
	switch {
	case errors.Is(err, errProvider):
		return "idp_error"
	case errors.Is(err, errUnverified):
		return "email_unverified"
	case errors.Is(err, errDomainNotAllow):
		return "domain_not_allowed"
	case errors.Is(err, ErrRejected), errors.Is(err, tenant.ErrSSORejected):
		return "access_denied"
	case errors.Is(err, tenant.ErrSSORequired):
		return "sso_required"
	case errors.Is(err, tenant.ErrMFARequired):
		return "mfa_required"
	case errors.Is(err, tenant.ErrTenantRequired):
		return "tenant_required"
	case errors.Is(err, tenant.ErrAccountLocked):
		return "account_locked"
	}
	return "server_error"
}

func (h *Handler) finish(r *http.Request, p *provider, st state) (tenant.TokenPair, error) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		return tenant.TokenPair{}, fmt.Errorf("%w: %.100s", errProvider, e)
	}
	code := q.Get("code")
	if code == "" {
		return tenant.TokenPair{}, fmt.Errorf("%w: no code", errProvider)
	}
	ctx := oidc.ClientContext(r.Context(), h.client)
	oc, err := p.oauth(ctx, h.client, h.CallbackURL(p.cfg.Name))
	if err != nil {
		return tenant.TokenPair{}, fmt.Errorf("%w: %w", errProvider, err)
	}
	tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return tenant.TokenPair{}, fmt.Errorf("%w: code exchange: %w", errProvider, err)
	}
	var (
		id       Identity
		verified bool
	)
	if p.isOIDC() {
		id, verified, err = p.verifyIDToken(ctx, h.client, tok, st.Nonce, h.now)
	} else {
		id, verified, err = p.githubIdentity(ctx, h.client, tok)
	}
	if err != nil {
		return tenant.TokenPair{}, fmt.Errorf("%w: %w", errProvider, err)
	}
	id.Email = strings.ToLower(strings.TrimSpace(id.Email))
	at := strings.LastIndexByte(id.Email, '@')
	if !verified || at <= 0 || at == len(id.Email)-1 {
		return tenant.TokenPair{}, errUnverified
	}
	if len(p.domains) > 0 && !slices.Contains(p.domains, id.Email[at+1:]) {
		return tenant.TokenPair{}, errDomainNotAllow
	}
	if id.Subject == "" {
		return tenant.TokenPair{}, fmt.Errorf("%w: no subject", errProvider)
	}
	id.Provider, id.Type, id.AutoCreate = p.cfg.Name, p.cfg.Type, p.cfg.AutoCreate
	id.Name = strings.TrimSpace(id.Name)
	return h.signIn(r.Context(), id, st.Tenant)
}

func redirectFragment(w http.ResponseWriter, r *http.Request, to string, v url.Values) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, to+"#"+v.Encode(), http.StatusFound)
}

// sessionFragment is the session handed to the browser after sign-in
// (the same fields as the SSO flow's).
func sessionFragment(pair tenant.TokenPair) url.Values {
	return url.Values{
		"access_token": {pair.AccessToken}, "refresh_token": {pair.RefreshToken}, "token_type": {pair.TokenType},
		"expires_in": {strconv.Itoa(pair.ExpiresIn)}, "tenant_id": {pair.TenantID},
	}
}
