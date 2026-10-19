// Package oidcprovider makes Tenarium an OpenID Connect provider: apps
// redirect users to /oauth/authorize, users sign in on Tenarium's own page
// (password, then one-time code if enabled), approve the app, and the app
// exchanges the code (with PKCE) at /oauth/token for an ID token, an access
// token for the Tenarium API and, with offline_access, a refresh token.
package oidcprovider

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

const (
	flowAudience    = "tenarium-oauth-flow"
	sessionAudience = "tenarium-session"
	codeAudience    = "tenarium-oauth-code"
	codeKind        = "oauth_code"
	sessionCookie   = "tenarium_session"
	flowTTL         = 15 * time.Minute
	codeTTL         = time.Minute
)

// Config configures the provider.
type Config struct {
	// PublicURL is the issuer's base URL (users.public_url).
	PublicURL   string
	ProductName string
	// SessionTTL is how long the browser stays signed in (default 12h).
	SessionTTL time.Duration
}

type Handler struct {
	tenants *tenant.Service
	issuer  *identity.Issuer
	cfg     Config
	log     *slog.Logger
	now     func() time.Time
}

func New(tenants *tenant.Service, issuer *identity.Issuer, cfg Config, log *slog.Logger) *Handler {
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if cfg.ProductName == "" {
		cfg.ProductName = "Tenarium"
	}
	return &Handler{tenants: tenants, issuer: issuer, cfg: cfg, log: log, now: time.Now}
}

// authRequest is a validated authorization request, carried through the
// login and consent pages in a signed token.
type authRequest struct {
	ClientID      string   `json:"cid"`
	RedirectURI   string   `json:"ruri"`
	Scopes        []string `json:"scp"`
	State         string   `json:"st,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	CodeChallenge string   `json:"cc,omitempty"`
	Tenant        string   `json:"tnt,omitempty"`
}

type session struct {
	UserID   string `json:"uid"`
	AuthTime int64  `json:"at"`
}

// code is the payload of an authorization code; the code is also stored
// as a one-time token so it can be redeemed once.
type code struct {
	authRequest
	UserID   string `json:"uid"`
	AuthTime int64  `json:"at"`
}

func (h *Handler) secure() bool { return strings.HasPrefix(h.cfg.PublicURL, "https://") }

// validate checks the client and redirect URI; errors before the redirect
// URI is trusted are shown on a page, never redirected.
func (h *Handler) validate(r *http.Request, q url.Values) (authRequest, store.OAuthClient, *pageError, *redirectError) {
	c, err := h.tenants.GetOAuthClient(r.Context(), q.Get("client_id"))
	if err != nil {
		return authRequest{}, c, &pageError{"Unknown application."}, nil
	}
	ruri := q.Get("redirect_uri")
	if !slices.Contains(c.RedirectURIs, ruri) {
		return authRequest{}, c, &pageError{"The application's redirect address is not registered."}, nil
	}
	ar := authRequest{ClientID: c.ID, RedirectURI: ruri, State: q.Get("state"), Nonce: q.Get("nonce"),
		CodeChallenge: q.Get("code_challenge"), Tenant: q.Get("tenant")}
	if c.TenantID != "" {
		ar.Tenant = c.TenantID
	}
	fail := func(code, desc string) *redirectError { return &redirectError{ar, code, desc} }
	if q.Get("response_type") != "code" {
		return ar, c, nil, fail("unsupported_response_type", "only the authorization code flow is supported")
	}
	if ar.CodeChallenge != "" && q.Get("code_challenge_method") != "S256" {
		return ar, c, nil, fail("invalid_request", "code_challenge_method must be S256")
	}
	if c.SecretHash == "" && ar.CodeChallenge == "" {
		return ar, c, nil, fail("invalid_request", "public clients must use PKCE")
	}
	for _, sc := range strings.Fields(q.Get("scope")) {
		if !slices.Contains(c.Scopes, sc) {
			return ar, c, nil, fail("invalid_scope", "scope "+sc+" is not allowed for this client")
		}
		if !slices.Contains(ar.Scopes, sc) {
			ar.Scopes = append(ar.Scopes, sc)
		}
	}
	if !slices.Contains(ar.Scopes, "openid") {
		return ar, c, nil, fail("invalid_scope", "the openid scope is required")
	}
	return ar, c, nil, nil
}

type pageError struct{ msg string }

type redirectError struct {
	ar         authRequest
	code, desc string
}

func (h *Handler) redirectError(w http.ResponseWriter, r *http.Request, e *redirectError) {
	v := url.Values{"error": {e.code}, "error_description": {e.desc}}
	if e.ar.State != "" {
		v.Set("state", e.ar.State)
	}
	http.Redirect(w, r, withQuery(e.ar.RedirectURI, v), http.StatusFound)
}

func withQuery(raw string, v url.Values) string {
	sep := "?"
	if strings.Contains(raw, "?") {
		sep = "&"
	}
	return raw + sep + v.Encode()
}

func (h *Handler) currentSession(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	var s session
	if h.issuer.VerifyClaims(c.Value, sessionAudience, &s) != nil {
		return session{}, false
	}
	if ok, err := h.tenants.ActiveUser(r.Context(), s.UserID); err != nil || !ok {
		return session{}, false
	}
	return s, true
}

// Authorize handles GET /oauth/authorize.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	ar, c, pe, re := h.validate(r, r.URL.Query())
	switch {
	case pe != nil:
		h.renderError(w, http.StatusBadRequest, pe.msg)
		return
	case re != nil:
		h.redirectError(w, r, re)
		return
	}
	flow, err := h.issuer.SignClaims(flowAudience, flowTTL, ar)
	if err != nil {
		h.renderError(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	s, ok := h.currentSession(r)
	if !ok || r.URL.Query().Get("prompt") == "login" {
		h.renderLogin(w, c, flow, "", "", false)
		return
	}
	h.afterLogin(w, r, c, ar, flow, s)
}

// afterLogin shows the consent page if needed, else issues the code.
func (h *Handler) afterLogin(w http.ResponseWriter, r *http.Request, c store.OAuthClient, ar authRequest, flow string, s session) {
	if !c.FirstParty && !h.tenants.HasConsent(r.Context(), s.UserID, c.ID, ar.Scopes) {
		if r.URL.Query().Get("prompt") == "none" {
			h.redirectError(w, r, &redirectError{ar, "consent_required", "the user has not approved this application"})
			return
		}
		h.renderConsent(w, c, ar, flow)
		return
	}
	h.issueCode(w, r, ar, s)
}

func (h *Handler) issueCode(w http.ResponseWriter, r *http.Request, ar authRequest, s session) {
	cd, err := h.issuer.SignClaims(codeAudience, codeTTL, code{authRequest: ar, UserID: s.UserID, AuthTime: s.AuthTime})
	if err == nil {
		err = h.tenants.CreateOneTimeToken(r.Context(), codeKind, s.UserID, cd, int(codeTTL.Seconds()))
	}
	if err != nil {
		h.redirectError(w, r, &redirectError{ar, "server_error", "could not issue a code"})
		return
	}
	v := url.Values{"code": {cd}}
	if ar.State != "" {
		v.Set("state", ar.State)
	}
	v.Set("iss", h.cfg.PublicURL) // RFC 9207
	http.Redirect(w, r, withQuery(ar.RedirectURI, v), http.StatusFound)
}

func (h *Handler) openFlow(w http.ResponseWriter, r *http.Request) (authRequest, store.OAuthClient, bool) {
	var ar authRequest
	if err := h.issuer.VerifyClaims(r.PostForm.Get("flow"), flowAudience, &ar); err != nil {
		h.renderError(w, http.StatusBadRequest, "This sign-in has expired. Go back to the application and try again.")
		return ar, store.OAuthClient{}, false
	}
	c, err := h.tenants.GetOAuthClient(r.Context(), ar.ClientID)
	if err != nil || !slices.Contains(c.RedirectURIs, ar.RedirectURI) {
		h.renderError(w, http.StatusBadRequest, "Unknown application.")
		return ar, c, false
	}
	return ar, c, true
}

// Login handles POST /oauth/login (the sign-in form).
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		h.renderError(w, http.StatusBadRequest, "Invalid form.")
		return
	}
	ar, c, ok := h.openFlow(w, r)
	if !ok {
		return
	}
	flow, email := r.PostForm.Get("flow"), r.PostForm.Get("email")
	u, err := h.tenants.VerifyLogin(r.Context(), tenant.LoginInput{
		Email: email, Password: r.PostForm.Get("password"), Tenant: ar.Tenant, OTP: r.PostForm.Get("otp"),
	})
	switch {
	case errors.Is(err, tenant.ErrMFARequired):
		h.renderLogin(w, c, flow, email, "Enter the code from your authenticator app.", true)
		return
	case errors.Is(err, tenant.ErrInvalidOTP):
		h.renderLogin(w, c, flow, email, "That code is not valid.", true)
		return
	case errors.Is(err, tenant.ErrSSORequired):
		h.renderLogin(w, c, flow, email, "Your organization requires single sign-on.", false)
		return
	case errors.Is(err, tenant.ErrAccountLocked):
		h.renderLogin(w, c, flow, email, "Too many attempts. Try again later.", false)
		return
	case err != nil:
		h.renderLogin(w, c, flow, email, "Wrong email or password.", false)
		return
	}
	s := session{UserID: u.ID, AuthTime: h.now().Unix()}
	val, err := h.issuer.SignClaims(sessionAudience, h.cfg.SessionTTL, s)
	if err != nil {
		h.renderError(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: val, Path: "/oauth", MaxAge: int(h.cfg.SessionTTL.Seconds()),
		HttpOnly: true, Secure: h.secure(), SameSite: http.SameSiteLaxMode})
	h.afterLogin(w, r, c, ar, flow, s)
}

// Consent handles POST /oauth/consent.
func (h *Handler) Consent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		h.renderError(w, http.StatusBadRequest, "Invalid form.")
		return
	}
	ar, _, ok := h.openFlow(w, r)
	if !ok {
		return
	}
	s, ok := h.currentSession(r)
	if !ok {
		h.renderError(w, http.StatusBadRequest, "Your sign-in has expired. Go back to the application and try again.")
		return
	}
	if r.PostForm.Get("decision") != "allow" {
		h.redirectError(w, r, &redirectError{ar, "access_denied", "the user declined"})
		return
	}
	if err := h.tenants.GrantConsent(r.Context(), s.UserID, ar.ClientID, ar.Scopes); err != nil {
		h.redirectError(w, r, &redirectError{ar, "server_error", "could not record consent"})
		return
	}
	h.issueCode(w, r, ar, s)
}

// Logout handles GET /oauth/logout (RP-initiated logout).
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/oauth", MaxAge: -1, HttpOnly: true, Secure: h.secure(), SameSite: http.SameSiteLaxMode})
	q := r.URL.Query()
	if to := q.Get("post_logout_redirect_uri"); to != "" {
		if c, err := h.tenants.GetOAuthClient(r.Context(), q.Get("client_id")); err == nil && slices.Contains(c.PostLogoutRedirectURIs, to) {
			v := url.Values{}
			if st := q.Get("state"); st != "" {
				v.Set("state", st)
			}
			http.Redirect(w, r, withQuery(to, v), http.StatusFound)
			return
		}
	}
	h.renderMessage(w, "You are signed out.")
}

// tokenError answers the token endpoint's error format (RFC 6749 5.2).
func tokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

// Token handles POST /oauth/token.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	f := r.PostForm
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = f.Get("client_id"), f.Get("client_secret")
	} else if uid, err := url.QueryUnescape(id); err == nil {
		id = uid
		secret, _ = url.QueryUnescape(secret)
	}
	c, err := h.tenants.AuthenticateOAuthClient(r.Context(), id, secret)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="tenarium"`)
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	switch f.Get("grant_type") {
	case "authorization_code":
		h.exchangeCode(w, r, c, f)
	case "refresh_token":
		pair, err := h.tenants.Refresh(tenant.WithOAuthClient(r.Context(), c.ID), f.Get("refresh_token"))
		if err != nil {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
			return
		}
		writeTokens(w, pair, "", "")
	default:
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

func (h *Handler) exchangeCode(w http.ResponseWriter, r *http.Request, c store.OAuthClient, f url.Values) {
	raw := f.Get("code")
	var cd code
	if err := h.issuer.VerifyClaims(raw, codeAudience, &cd); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired code")
		return
	}
	// Redeem once: a replayed code fails here.
	if uid, err := h.tenants.ConsumeOneTimeToken(r.Context(), codeKind, raw); err != nil || uid != cd.UserID {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "code already used or expired")
		return
	}
	if cd.ClientID != c.ID || f.Get("redirect_uri") != cd.RedirectURI {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "code was issued to another client or redirect URI")
		return
	}
	if cd.CodeChallenge != "" {
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(cd.CodeChallenge)) != 1 {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	}
	u, err := h.tenants.GetUser(r.Context(), cd.UserID)
	if err != nil || u.Status != sdk.UserActive {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "user is no longer active")
		return
	}
	pair, err := h.tenants.OpenSession(tenant.WithOAuthClient(r.Context(), c.ID), u, cd.Tenant, slices.Contains(cd.Scopes, "offline_access"))
	if err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the user cannot sign in to this tenant")
		return
	}
	claims := map[string]any{"sub": u.ID, "auth_time": cd.AuthTime, "azp": c.ID}
	if cd.Nonce != "" {
		claims["nonce"] = cd.Nonce
	}
	if slices.Contains(cd.Scopes, "email") {
		claims["email"], claims["email_verified"] = u.Email, u.EmailVerified
	}
	if slices.Contains(cd.Scopes, "profile") && u.Name != "" {
		claims["name"] = u.Name
	}
	if pair.TenantID != "" {
		claims["tid"] = pair.TenantID
	}
	idToken, err := h.issuer.SignClaims(c.ID, time.Duration(pair.ExpiresIn)*time.Second, claims)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "could not sign the ID token")
		return
	}
	writeTokens(w, pair, idToken, strings.Join(cd.Scopes, " "))
}

func writeTokens(w http.ResponseWriter, pair tenant.TokenPair, idToken, scope string) {
	out := map[string]any{"access_token": pair.AccessToken, "token_type": "Bearer", "expires_in": pair.ExpiresIn}
	if pair.RefreshToken != "" {
		out["refresh_token"] = pair.RefreshToken
	}
	if idToken != "" {
		out["id_token"] = idToken
	}
	if scope != "" {
		out["scope"] = scope
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// UserInfo handles GET/POST /oauth/userinfo.
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	cl, err := h.issuer.Verify(raw)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	u, err := h.tenants.GetUser(r.Context(), cl.Subject)
	if err != nil || u.Status != sdk.UserActive {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	out := map[string]any{"sub": u.ID, "email": u.Email, "email_verified": u.EmailVerified}
	if u.Name != "" {
		out["name"] = u.Name
	}
	if cl.TenantID != "" {
		out["tid"] = cl.TenantID
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
