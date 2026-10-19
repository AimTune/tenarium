package client

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// AuthService covers the public /v1/auth endpoints. These calls never send
// the client's credentials.
type AuthService struct{ c *Client }

// TokenPair is the result of a login or refresh.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TenantID     string `json:"tenant_id,omitempty"`
	// Expiry is computed by the client from ExpiresIn when the pair is
	// received. It is zero if the server sent no lifetime.
	Expiry time.Time `json:"expiry,omitzero"`
}

// LoginRequest signs in with email and password.
type LoginRequest struct {
	Email    string
	Password string
	// Tenant (ID or slug) scopes the session to a tenant membership. Leave
	// empty for a platform session (requires platform roles).
	Tenant string
}

// InvitationResult is returned by AcceptInvitation.
type InvitationResult struct {
	Email  string `json:"email"`
	Status string `json:"status"`
}

// AcceptInvitationRequest activates an invited user.
type AcceptInvitationRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
	Name     string `json:"name,omitempty"`
}

// Login exchanges a password for a token pair.
func (s *AuthService) Login(ctx context.Context, req LoginRequest) (TokenPair, error) {
	return s.token(ctx, map[string]string{
		"grant_type": "password", "email": req.Email, "password": req.Password, "tenant": req.Tenant,
	})
}

// Refresh exchanges a refresh token for a new pair. Refresh tokens rotate:
// the old one becomes invalid, and reusing it revokes the session.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (TokenPair, error) {
	return s.token(ctx, map[string]string{"grant_type": "refresh_token", "refresh_token": refreshToken})
}

func (s *AuthService) token(ctx context.Context, body map[string]string) (TokenPair, error) {
	var p TokenPair
	if err := s.c.do(ctx, http.MethodPost, "/v1/auth/token", nil, body, &p, public()); err != nil {
		return TokenPair{}, err
	}
	if p.ExpiresIn > 0 {
		p.Expiry = time.Now().Add(time.Duration(p.ExpiresIn) * time.Second)
	}
	return p, nil
}

// Logout revokes a refresh token.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	body := map[string]string{"refresh_token": refreshToken}
	err := s.c.do(ctx, http.MethodPost, "/v1/auth/logout", nil, body, nil, public())
	return err
}

// RequestPasswordReset emails a reset link if the account exists. It
// succeeds either way so it cannot be used to probe for accounts.
func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) error {
	body := map[string]string{"email": email}
	err := s.c.do(ctx, http.MethodPost, "/v1/auth/password-reset", nil, body, nil, public())
	return err
}

// ConfirmPasswordReset sets a new password using the emailed token.
func (s *AuthService) ConfirmPasswordReset(ctx context.Context, token, password string) error {
	body := map[string]string{"token": token, "password": password}
	err := s.c.do(ctx, http.MethodPost, "/v1/auth/password-reset/confirm", nil, body, nil, public())
	return err
}

// AcceptInvitation activates an invited account.
func (s *AuthService) AcceptInvitation(ctx context.Context, req AcceptInvitationRequest) (InvitationResult, error) {
	var r InvitationResult
	err := s.c.do(ctx, http.MethodPost, "/v1/auth/invitations/accept", nil, req, &r, public())
	return r, err
}

// --- token providers --------------------------------------------------------------

// TokenProvider supplies the bearer token for each request.
type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// Reauthenticator is a TokenProvider that can replace a token the server
// rejected with 401. The client calls Reauth at most once per request.
type Reauthenticator interface {
	TokenProvider
	Reauth(ctx context.Context, rejected string) (string, error)
}

// StaticToken is a fixed bearer token or API key.
type StaticToken string

// Token implements TokenProvider.
func (t StaticToken) Token(context.Context) (string, error) { return string(t), nil }

// TokenSource holds a Tenarium token pair and refreshes the access token
// shortly before it expires, and once when the server rejects it with 401.
// It is safe for concurrent use; refreshes are serialized so a rotated
// refresh token is never reused.
//
//	pair, err := c.Auth.Login(ctx, client.LoginRequest{Email: e, Password: p})
//	ts := client.NewTokenSource(c.Auth, pair)
//	authed := c.With(client.WithTokenSource(ts))
type TokenSource struct {
	auth      *AuthService
	skew      time.Duration
	onRefresh func(TokenPair)
	now       func() time.Time

	mu   sync.Mutex
	pair TokenPair
}

// TokenSourceOption configures a TokenSource.
type TokenSourceOption func(*TokenSource)

// WithRefreshSkew sets how long before expiry the access token is
// refreshed (default 30s, capped at half the token's lifetime).
func WithRefreshSkew(d time.Duration) TokenSourceOption {
	return func(ts *TokenSource) { ts.skew = d }
}

// OnRefresh is called with every new pair, e.g. to persist the rotated
// refresh token. It runs while the source is locked; keep it short.
func OnRefresh(fn func(TokenPair)) TokenSourceOption {
	return func(ts *TokenSource) { ts.onRefresh = fn }
}

// ErrNoRefreshToken is returned when a refresh is needed but the pair has
// no refresh token.
var ErrNoRefreshToken = errors.New("tenarium: access token expired and no refresh token is available")

// NewTokenSource returns a TokenSource that refreshes through auth.
func NewTokenSource(auth *AuthService, pair TokenPair, opts ...TokenSourceOption) *TokenSource {
	ts := &TokenSource{auth: auth, pair: pair, skew: 30 * time.Second, now: time.Now}
	for _, o := range opts {
		o(ts)
	}
	return ts
}

// Token returns a valid access token, refreshing it if it expires soon.
func (ts *TokenSource) Token(ctx context.Context) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.pair.AccessToken != "" && !ts.expiringLocked() {
		return ts.pair.AccessToken, nil
	}
	if err := ts.refreshLocked(ctx); err != nil {
		return "", err
	}
	return ts.pair.AccessToken, nil
}

// Reauth refreshes after the server rejected the given token, unless a
// concurrent caller already replaced it.
func (ts *TokenSource) Reauth(ctx context.Context, rejected string) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.pair.AccessToken != rejected && ts.pair.AccessToken != "" {
		return ts.pair.AccessToken, nil
	}
	if err := ts.refreshLocked(ctx); err != nil {
		return "", err
	}
	return ts.pair.AccessToken, nil
}

// Refresh forces a refresh now.
func (ts *TokenSource) Refresh(ctx context.Context) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.refreshLocked(ctx)
}

// Pair returns the current token pair.
func (ts *TokenSource) Pair() TokenPair {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.pair
}

func (ts *TokenSource) expiringLocked() bool {
	if ts.pair.Expiry.IsZero() {
		return false
	}
	skew := ts.skew
	if ts.pair.ExpiresIn > 0 {
		skew = min(skew, time.Duration(ts.pair.ExpiresIn)*time.Second/2)
	}
	return !ts.now().Add(skew).Before(ts.pair.Expiry)
}

func (ts *TokenSource) refreshLocked(ctx context.Context) error {
	if ts.pair.RefreshToken == "" {
		return ErrNoRefreshToken
	}
	p, err := ts.auth.Refresh(ctx, ts.pair.RefreshToken)
	if err != nil {
		return err
	}
	ts.pair = p
	if ts.onRefresh != nil {
		ts.onRefresh(p)
	}
	return nil
}
