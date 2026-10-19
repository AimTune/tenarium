package tenant

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// Impersonation event types.
const (
	EventUserImpersonationConsented = "user.impersonation_consented"
	EventUserImpersonated           = "user.impersonated"
)

const tokenImpersonationConsent = "impersonation_consent"

// ImpersonationClaim is the principal claim naming the impersonator.
const ImpersonationClaim = "impersonator"

var (
	// ErrConsentRequired means the user has not granted (or the code is
	// wrong, used or expired) consent to be impersonated.
	ErrConsentRequired = errors.New("the user's consent code is missing, wrong or expired")
)

// ImpersonationOptions configure support access.
type ImpersonationOptions struct {
	// RequireConsent makes users issue a consent code first (default on).
	RequireConsent bool
	// MaxTTL bounds impersonation sessions (default 1h).
	MaxTTL time.Duration
}

// ImpersonationInput requests a session as another user.
type ImpersonationInput struct {
	Reason      string `json:"reason"`
	TTL         string `json:"ttl,omitempty"`
	Tenant      string `json:"tenant,omitempty"`
	ConsentCode string `json:"consent_code,omitempty"`
}

// GrantImpersonationConsent lets support act as the user for a while: it
// returns a single-use code the user hands to support.
func (s *Service) GrantImpersonationConsent(ctx context.Context, userID string, ttl time.Duration) (string, time.Time, error) {
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return "", time.Time{}, err
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	if ttl > 24*time.Hour {
		return "", time.Time{}, invalid("ttl", "at most 24h")
	}
	code, hash := identity.NewToken()
	now := s.now()
	exp := now.Add(ttl)
	if err := s.store.CreateActionToken(ctx, store.ActionToken{Hash: hash, Kind: tokenImpersonationConsent, UserID: u.ID, ExpiresAt: exp, CreatedAt: now}); err != nil {
		return "", time.Time{}, err
	}
	return code, exp, s.RecordEvent(ctx, EventUserImpersonationConsented, "", "users/"+u.ID,
		map[string]any{"user_id": u.ID, "expires_at": exp})
}

// Impersonate issues a short-lived access token (no refresh token) for the
// target user, marked with the impersonator in the "act" claim. Users with
// platform roles cannot be impersonated (that would be an escalation), and
// impersonated sessions cannot themselves impersonate.
func (s *Service) Impersonate(ctx context.Context, targetRef string, in ImpersonationInput) (TokenPair, error) {
	p, ok := sdk.PrincipalFrom(ctx)
	if !ok {
		return TokenPair{}, sdk.ErrForbidden
	}
	if _, nested := p.Claims[ImpersonationClaim]; nested {
		return TokenPair{}, errors.Join(sdk.ErrForbidden, errors.New("an impersonated session cannot impersonate"))
	}
	if strings.TrimSpace(in.Reason) == "" || len(in.Reason) > 500 {
		return TokenPair{}, invalid("reason", "a reason (up to 500 characters) is required")
	}
	o := s.userOpts.Impersonation
	maxTTL := o.MaxTTL
	if maxTTL <= 0 {
		maxTTL = time.Hour
	}
	ttl := 15 * time.Minute
	if in.TTL != "" {
		d, err := time.ParseDuration(in.TTL)
		if err != nil || d <= 0 || d > maxTTL {
			return TokenPair{}, invalid("ttl", "must be a duration up to %s", maxTTL)
		}
		ttl = d
	}
	u, err := s.GetUser(ctx, targetRef)
	if err != nil {
		return TokenPair{}, err
	}
	if u.Status != sdk.UserActive {
		return TokenPair{}, stateErr("only active users can be impersonated")
	}
	if len(u.Roles) > 0 {
		return TokenPair{}, errors.Join(sdk.ErrForbidden, errors.New("users with platform roles cannot be impersonated"))
	}
	if o.RequireConsent {
		if in.ConsentCode == "" {
			return TokenPair{}, ErrConsentRequired
		}
		at, err := s.store.ConsumeActionToken(ctx, identity.HashToken(in.ConsentCode), tokenImpersonationConsent, s.now())
		if err != nil || at.UserID != u.ID {
			return TokenPair{}, ErrConsentRequired
		}
	}
	if in.Tenant == "" {
		return TokenPair{}, invalid("tenant", "required: impersonated sessions are tenant-scoped")
	}
	tenantID, roles, err := s.sessionScope(ctx, u, in.Tenant)
	if err != nil {
		return TokenPair{}, err
	}
	if s.userOpts.Issuer == nil {
		return TokenPair{}, ErrTokensDisabled
	}
	impersonator := p.Authenticator + ":" + p.Subject
	c := identity.Claims{Email: u.Email, Name: u.Name, TenantID: tenantID, Roles: roles, Act: &identity.Actor{Subject: impersonator}}
	if t, err := s.store.GetTenant(ctx, tenantID); err == nil {
		c.Region = t.Region
	}
	access, exp, err := s.userOpts.Issuer.SignAccess(u.ID, c, ttl)
	if err != nil {
		return TokenPair{}, err
	}
	if err := s.RecordEvent(ctx, EventUserImpersonated, tenantID, "users/"+u.ID, map[string]any{
		"user_id": u.ID, "impersonator": impersonator, "reason": in.Reason, "tenant_id": tenantID,
		"expires_at": exp, "consent": o.RequireConsent,
	}); err != nil {
		return TokenPair{}, err
	}
	return TokenPair{AccessToken: access, TokenType: "Bearer", ExpiresIn: int(time.Until(exp).Seconds()), TenantID: tenantID}, nil
}
