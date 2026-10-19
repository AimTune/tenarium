package tenant

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// OAuth client event types.
const (
	EventOAuthClientUpdated = "oauth_client.updated"
	EventOAuthClientDeleted = "oauth_client.deleted"
)

// SupportedScopes are the scopes Tenarium's OIDC provider understands.
var SupportedScopes = []string{"openid", "profile", "email", "offline_access"}

// ErrInvalidClient means unknown client or wrong client secret.
var ErrInvalidClient = errors.New("invalid client")

// OAuthClientInput creates or updates a client; Public clients get no
// secret and must use PKCE.
type OAuthClientInput struct {
	Name                   string   `json:"name"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	TenantID               string   `json:"tenant_id,omitempty"`
	Scopes                 []string `json:"scopes,omitempty"`
	FirstParty             bool     `json:"first_party,omitempty"`
	Public                 bool     `json:"public,omitempty"`
}

func validRedirect(raw string, allowHTTP bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Scheme == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		// Plain http only for loopback (native apps, RFC 8252) or dev.
		h := u.Hostname()
		return u.Host != "" && (allowHTTP || h == "localhost" || h == "127.0.0.1" || h == "::1")
	default:
		// Private-use schemes for native apps (com.example.app:/cb).
		return strings.Contains(u.Scheme, ".")
	}
}

func (s *Service) applyClient(ctx context.Context, c *store.OAuthClient, in OAuthClientInput) error {
	c.Name, c.FirstParty = strings.TrimSpace(in.Name), in.FirstParty
	c.RedirectURIs, c.PostLogoutRedirectURIs = slices.Clone(in.RedirectURIs), slices.Clone(in.PostLogoutRedirectURIs)
	c.Scopes = slices.Clone(in.Scopes)
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email"}
	}
	switch {
	case c.Name == "" || len(c.Name) > 200:
		return invalid("name", "must be 1-200 characters")
	case len(c.RedirectURIs) == 0 || len(c.RedirectURIs) > 20:
		return invalid("redirect_uris", "between 1 and 20 are required")
	}
	for _, u := range append(slices.Clone(c.RedirectURIs), c.PostLogoutRedirectURIs...) {
		if !validRedirect(u, s.ssoAllowPrivate) {
			return invalid("redirect_uris", "%q must be https, loopback http, or a private-use scheme, without fragment", u)
		}
	}
	for _, sc := range c.Scopes {
		if !slices.Contains(SupportedScopes, sc) {
			return invalid("scopes", "unsupported scope %q", sc)
		}
	}
	if in.TenantID != "" {
		t, err := s.Get(ctx, in.TenantID)
		if err != nil {
			return invalid("tenant_id", "unknown tenant")
		}
		c.TenantID = t.ID
	} else {
		c.TenantID = ""
	}
	return nil
}

// CreateOAuthClient registers an application; the secret (confidential
// clients only) is returned once.
func (s *Service) CreateOAuthClient(ctx context.Context, in OAuthClientInput) (store.OAuthClient, string, error) {
	now := s.now()
	id, _ := identity.NewToken()
	c := store.OAuthClient{ID: "tc_" + id[:24], CreatedAt: now, UpdatedAt: now}
	if err := s.applyClient(ctx, &c, in); err != nil {
		return c, "", err
	}
	var secret string
	if !in.Public {
		var hash string
		secret, hash = identity.NewToken()
		c.SecretHash = hash
	}
	if err := s.store.PutOAuthClient(ctx, c); err != nil {
		return c, "", err
	}
	return c, secret, s.RecordEvent(ctx, EventOAuthClientUpdated, c.TenantID, "oauth-clients/"+c.ID, c)
}

func (s *Service) GetOAuthClient(ctx context.Context, id string) (store.OAuthClient, error) {
	return s.store.GetOAuthClient(ctx, id)
}

func (s *Service) ListOAuthClients(ctx context.Context) ([]store.OAuthClient, error) {
	return s.store.ListOAuthClients(ctx)
}

// UpdateOAuthClient replaces a client's settings (not its secret or type).
func (s *Service) UpdateOAuthClient(ctx context.Context, id string, in OAuthClientInput) (store.OAuthClient, error) {
	c, err := s.store.GetOAuthClient(ctx, id)
	if err != nil {
		return c, err
	}
	if err := s.applyClient(ctx, &c, in); err != nil {
		return c, err
	}
	c.UpdatedAt = s.now()
	if err := s.store.PutOAuthClient(ctx, c); err != nil {
		return c, err
	}
	return c, s.RecordEvent(ctx, EventOAuthClientUpdated, c.TenantID, "oauth-clients/"+c.ID, c)
}

// RotateOAuthClientSecret replaces a confidential client's secret.
func (s *Service) RotateOAuthClientSecret(ctx context.Context, id string) (string, error) {
	c, err := s.store.GetOAuthClient(ctx, id)
	if err != nil {
		return "", err
	}
	if c.SecretHash == "" {
		return "", stateErr("public clients have no secret")
	}
	secret, hash := identity.NewToken()
	c.SecretHash, c.UpdatedAt = hash, s.now()
	if err := s.store.PutOAuthClient(ctx, c); err != nil {
		return "", err
	}
	return secret, s.RecordEvent(ctx, EventOAuthClientUpdated, c.TenantID, "oauth-clients/"+c.ID, c)
}

func (s *Service) DeleteOAuthClient(ctx context.Context, id string) error {
	c, err := s.store.GetOAuthClient(ctx, id)
	if err != nil {
		return err
	}
	if err := s.store.DeleteOAuthClient(ctx, id); err != nil {
		return err
	}
	return s.RecordEvent(ctx, EventOAuthClientDeleted, c.TenantID, "oauth-clients/"+c.ID, c)
}

// AuthenticateOAuthClient checks a confidential client's secret; public
// clients pass with an empty secret (PKCE protects them instead).
func (s *Service) AuthenticateOAuthClient(ctx context.Context, id, secret string) (store.OAuthClient, error) {
	c, err := s.store.GetOAuthClient(ctx, id)
	if err != nil {
		identity.BurnTime(secret)
		return c, ErrInvalidClient
	}
	if c.SecretHash == "" {
		if secret != "" {
			return c, ErrInvalidClient
		}
		return c, nil
	}
	if subtle.ConstantTimeCompare([]byte(identity.HashToken(secret)), []byte(c.SecretHash)) != 1 {
		return c, ErrInvalidClient
	}
	return c, nil
}

// HasConsent reports whether the user already granted all scopes.
func (s *Service) HasConsent(ctx context.Context, userID, clientID string, scopes []string) bool {
	c, err := s.store.GetOAuthConsent(ctx, userID, clientID)
	if err != nil {
		return false
	}
	for _, sc := range scopes {
		if !slices.Contains(c.Scopes, sc) {
			return false
		}
	}
	return true
}

// GrantConsent records the scopes a user allowed a client.
func (s *Service) GrantConsent(ctx context.Context, userID, clientID string, scopes []string) error {
	prev, _ := s.store.GetOAuthConsent(ctx, userID, clientID)
	merged := slices.Clone(prev.Scopes)
	for _, sc := range scopes {
		if !slices.Contains(merged, sc) {
			merged = append(merged, sc)
		}
	}
	return s.store.PutOAuthConsent(ctx, store.OAuthConsent{UserID: userID, ClientID: clientID, Scopes: merged, CreatedAt: s.now()})
}

// ActiveUser reports whether a user exists and is active.
func (s *Service) ActiveUser(ctx context.Context, id string) (bool, error) {
	u, err := s.store.GetUser(ctx, id)
	if err != nil {
		return false, err
	}
	return u.Status == sdk.UserActive, nil
}

// CreateOneTimeToken stores a single-use token (e.g. an authorization
// code) for later ConsumeOneTimeToken.
func (s *Service) CreateOneTimeToken(ctx context.Context, kind, userID, token string, ttlSeconds int) error {
	now := s.now()
	return s.store.CreateActionToken(ctx, store.ActionToken{
		Hash: identity.HashToken(token), Kind: kind, UserID: userID,
		ExpiresAt: now.Add(secondsDuration(ttlSeconds)), CreatedAt: now,
	})
}

// ConsumeOneTimeToken uses up a token from CreateOneTimeToken and returns
// its user; ErrInvalidToken if unknown, used or expired.
func (s *Service) ConsumeOneTimeToken(ctx context.Context, kind, token string) (string, error) {
	at, err := s.store.ConsumeActionToken(ctx, identity.HashToken(token), kind, s.now())
	if err != nil {
		return "", ErrInvalidToken
	}
	return at.UserID, nil
}

func secondsDuration(n int) time.Duration { return time.Duration(n) * time.Second }
