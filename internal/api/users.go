package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AimTune/tenarium/internal/authz"
	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// tokenAuthenticator accepts Tenarium-issued access tokens.
type tokenAuthenticator struct {
	issuer  *identity.Issuer
	tenants *tenant.Service
}

func (a *tokenAuthenticator) Name() string { return "token" }

func (a *tokenAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*sdk.Principal, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, sdk.ErrNoCredentials
	}
	claims, err := a.issuer.Verify(raw)
	if errors.Is(err, identity.ErrForeignToken) {
		return nil, sdk.ErrNoCredentials
	}
	if err != nil {
		return nil, err
	}
	return a.tenants.TokenPrincipal(ctx, claims)
}

// --- public auth endpoints ------------------------------------------------------

func (s *Server) mountAuth(root *http.ServeMux) {
	auth := http.NewServeMux()
	h := func(pattern string, fn http.HandlerFunc) { auth.HandleFunc(pattern, routed(pattern, fn)) }
	h("POST /v1/auth/token", s.token)
	h("POST /v1/auth/logout", s.logout)
	h("POST /v1/auth/password-reset", s.requestPasswordReset)
	h("POST /v1/auth/password-reset/confirm", s.confirmPasswordReset)
	h("POST /v1/auth/invitations/accept", s.acceptInvitation)
	h("POST /v1/auth/magic-link", s.requestMagicLink)
	h("GET /v1/auth/branding", s.publicBranding)
	h("POST /v1/auth/email-change/confirm", s.confirmEmailChange)
	h("POST /v1/auth/passkey/begin", s.beginPasskeyLogin)
	h("POST /v1/auth/passkey/finish", s.finishPasskeyLogin)
	h("GET /v1/auth/sso/start", s.ssoStart)
	h("GET /v1/auth/sso/callback", s.ssoCallback)
	h("GET /v1/auth/sso/discover", s.ssoDiscover)
	if s.Social != nil {
		for _, rt := range s.Social.Routes() {
			h(rt.Pattern, rt.Handler)
		}
	}
	h("GET /v1/auth/sso/saml/{tenant}/metadata", s.samlMetadata)
	h("POST /v1/auth/sso/saml/{tenant}/acs", s.samlACS)
	limiter := newRateLimiter(s.AuthRateLimit, time.Minute)
	if s.SharedRateLimit {
		limiter.shared = s.Store.IncrementRateCounter
	}
	s.authLimiter = limiter
	root.Handle("/v1/auth/", limiter.wrap(auth))
	s.mountOIDCProvider(root, limiter)

	if s.Issuer != nil {
		root.HandleFunc("GET /.well-known/openid-configuration", routed("GET /.well-known/openid-configuration",
			func(w http.ResponseWriter, _ *http.Request) { writeRaw(w, s.Issuer.Discovery()) }))
		root.HandleFunc("GET /.well-known/jwks.json", routed("GET /.well-known/jwks.json",
			func(w http.ResponseWriter, _ *http.Request) { writeRaw(w, s.Issuer.JWKS()) }))
	}
}

func writeRaw(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	var in struct {
		GrantType    string `json:"grant_type"`
		Email        string `json:"email"`
		Password     string `json:"password"`
		Tenant       string `json:"tenant"`
		RefreshToken string `json:"refresh_token"`
		OTP          string `json:"otp"`
		// Token is the emailed sign-in link token (grant_type magic_link).
		Token string `json:"token"`
	}
	if !decode(w, r, &in) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var (
		pair tenant.TokenPair
		err  error
	)
	switch in.GrantType {
	case "password":
		pair, err = s.Tenants.SignIn(r.Context(), tenant.LoginInput{Email: in.Email, Password: in.Password, Tenant: in.Tenant, OTP: in.OTP})
	case "refresh_token":
		pair, err = s.Tenants.Refresh(r.Context(), in.RefreshToken)
	case "magic_link":
		pair, err = s.Tenants.SignInWithMagicLink(r.Context(), in.Token, in.OTP)
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", `grant_type must be "password", "refresh_token" or "magic_link"`, "grant_type")
		return
	}
	if err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.Tenants.Logout(r.Context(), in.RefreshToken); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &in) {
		return
	}
	// Always 202: the response must not reveal whether the email exists.
	if err := s.Tenants.RequestPasswordReset(r.Context(), in.Email); err != nil {
		s.Log.Error("password reset request", "err", err)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "if the account exists, an email is on its way"})
}

func (s *Server) confirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.Tenants.ResetPassword(r.Context(), in.Token, in.Password); err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, err := s.Tenants.AcceptInvitation(r.Context(), in.Token, in.Password, in.Name)
	if err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"email": u.Email, "status": string(u.Status)})
}

func (s *Server) writeAuthErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, tenant.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", err.Error(), "")
	case errors.Is(err, tenant.ErrInvalidToken):
		writeError(w, http.StatusBadRequest, "invalid_token", err.Error(), "")
	case errors.Is(err, tenant.ErrMFARequired):
		writeError(w, http.StatusUnauthorized, "mfa_required", err.Error(), "otp")
	case errors.Is(err, tenant.ErrInvalidOTP):
		writeError(w, http.StatusUnauthorized, "invalid_otp", err.Error(), "otp")
	case errors.Is(err, tenant.ErrSSORequired):
		writeError(w, http.StatusForbidden, "sso_required", err.Error(), "")
	case errors.Is(err, tenant.ErrPasskeyRejected):
		writeError(w, http.StatusUnauthorized, "passkey_rejected", err.Error(), "")
	case errors.Is(err, tenant.ErrPasskeysDisabled), errors.Is(err, tenant.ErrMagicLinksDisabled):
		writeError(w, http.StatusNotFound, "not_found", err.Error(), "")
	case errors.Is(err, tenant.ErrAccountLocked):
		writeError(w, http.StatusTooManyRequests, "account_locked", err.Error(), "")
	case errors.Is(err, tenant.ErrTenantRequired):
		writeError(w, http.StatusBadRequest, "tenant_required", err.Error(), "tenant")
	case errors.Is(err, tenant.ErrPasswordLoginUnavailable), errors.Is(err, tenant.ErrTokensDisabled):
		writeError(w, http.StatusBadRequest, "password_login_unavailable", err.Error(), "")
	default:
		s.writeErr(w, r, err)
	}
}

// rateLimiter is a per-IP fixed-window limiter for unauthenticated
// endpoints. It complements per-account lockout against password spraying.
type rateLimiter struct {
	limit  int // guarded by mu; 0 disables limiting
	window time.Duration
	// shared, if set, counts in the store so all replicas share the limit;
	// on store errors the local counters are used.
	shared func(ctx context.Context, key string, window, expireBefore time.Time) (int, error)
	mu     sync.Mutex
	start  time.Time
	counts map[string]int
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, counts: map[string]int{}}
}

func (l *rateLimiter) allow(ctx context.Context, ip string, now time.Time) bool {
	l.mu.Lock()
	limit := l.limit
	l.mu.Unlock()
	if limit <= 0 {
		return true
	}
	if l.shared != nil {
		start := now.Truncate(l.window)
		if n, err := l.shared(ctx, "auth:"+ip, start, start.Add(-l.window)); err == nil {
			return n <= limit
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.start) >= l.window {
		l.start, l.counts = now, map[string]int{}
	}
	l.counts[ip]++
	return l.counts[ip] <= limit
}

// setLimit changes the limit while running (configuration reload).
func (l *rateLimiter) setLimit(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limit = n
}

func (l *rateLimiter) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !l.allow(r.Context(), ip, time.Now()) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests; try again later", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- user administration --------------------------------------------------------

func userResource(id string) sdk.Resource { return sdk.Resource{Type: "user", ID: id} }

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionUsersRead, userResource("")) {
		return
	}
	limit, err := queryLimit(r, 50, 500)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	q := r.URL.Query()
	items, err := s.Tenants.ListUsers(r.Context(), store.ListUsersQuery{
		Search: q.Get("q"), Status: sdk.UserStatus(q.Get("status")), After: q.Get("after"), Limit: limit,
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	resp := map[string]any{"items": nonNil(items)}
	if len(items) == limit {
		resp["next"] = items[len(items)-1].ID
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in tenant.UserInput
	if !decode(w, r, &in) {
		return
	}
	if !s.authorize(w, r, sdk.ActionUsersWrite, userResource("")) {
		return
	}
	u, err := s.Tenants.CreateUser(r.Context(), in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/users/"+u.ID)
	writeVersioned(w, http.StatusCreated, u.Version, u)
}

// loadUser resolves {id} (ID or email) and authorizes action on it.
func (s *Server) loadUser(w http.ResponseWriter, r *http.Request, action sdk.Action) (sdk.User, bool) {
	u, err := s.Tenants.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, r, err)
		return sdk.User{}, false
	}
	return u, s.authorize(w, r, action, userResource(u.ID))
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.loadUser(w, r, sdk.ActionUsersRead); ok {
		writeVersioned(w, http.StatusOK, u.Version, u)
	}
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	var in tenant.UserUpdate
	if !decode(w, r, &in) {
		return
	}
	expected, err := ifMatch(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	u, ok := s.loadUser(w, r, sdk.ActionUsersWrite)
	if !ok {
		return
	}
	if u, err = s.Tenants.UpdateUser(r.Context(), u.ID, in, expected); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeVersioned(w, http.StatusOK, u.Version, u)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	u, ok := s.loadUser(w, r, sdk.ActionUsersWrite)
	if !ok {
		return
	}
	if err := s.Tenants.DeleteUser(r.Context(), u.ID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) userAction(fn func(ctx context.Context, id string) (sdk.User, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.loadUser(w, r, sdk.ActionUsersWrite)
		if !ok {
			return
		}
		u, err := fn(r.Context(), u.ID)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		writeVersioned(w, http.StatusOK, u.Version, u)
	}
}

func (s *Server) setUserPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, ok := s.loadUser(w, r, sdk.ActionUsersWrite)
	if !ok {
		return
	}
	if err := s.Tenants.SetUserPassword(r.Context(), u.ID, in.Password); err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) resendInvitation(w http.ResponseWriter, r *http.Request) {
	u, ok := s.loadUser(w, r, sdk.ActionUsersWrite)
	if !ok {
		return
	}
	if err := s.Tenants.ResendInvitation(r.Context(), u.ID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "sent"})
}

func (s *Server) revokeSessions(w http.ResponseWriter, r *http.Request) {
	u, ok := s.loadUser(w, r, sdk.ActionUsersWrite)
	if !ok {
		return
	}
	if err := s.Tenants.RevokeSessions(r.Context(), u.ID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) userMemberships(w http.ResponseWriter, r *http.Request) {
	u, ok := s.loadUser(w, r, sdk.ActionUsersRead)
	if !ok {
		return
	}
	ms, err := s.Tenants.UserMemberships(r.Context(), u.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(ms)})
}

// --- self-service ------------------------------------------------------------------

// callerUserID returns the Tenarium user behind the caller, if any.
func callerUserID(r *http.Request) string {
	p, ok := sdk.PrincipalFrom(r.Context())
	if !ok {
		return ""
	}
	if p.Authenticator == authz.UserTokenAuthenticator {
		return p.Subject
	}
	id, _ := p.Claims["tenarium_user_id"].(string)
	return id
}

func (s *Server) myMemberships(w http.ResponseWriter, r *http.Request) {
	id := callerUserID(r)
	if id == "" {
		writeJSON(w, http.StatusOK, map[string]any{"items": []sdk.Member{}})
		return
	}
	ms, err := s.Tenants.UserMemberships(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(ms)})
}

func (s *Server) changeMyPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decode(w, r, &in) {
		return
	}
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	if err := s.Tenants.ChangePassword(r.Context(), id, in.CurrentPassword, in.NewPassword); err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetAuthRateLimit changes the per-IP limit of the unauthenticated auth
// endpoints (requests per minute; 0 disables it) while running. It must
// be called after Handler.
func (s *Server) SetAuthRateLimit(n int) {
	if s.authLimiter != nil {
		s.authLimiter.setLimit(n)
	}
}
