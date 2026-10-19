package tenant

import (
	"context"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// OpenSession issues tokens for a verified user, scoped to tenantRef if
// given; withRefresh adds a refresh token.
func (s *Service) OpenSession(ctx context.Context, u sdk.User, tenantRef string, withRefresh bool) (TokenPair, error) {
	tenantID, roles, err := s.sessionScope(ctx, u, tenantRef)
	if err != nil {
		return TokenPair{}, err
	}
	now := s.now()
	if err := s.store.RecordLoginSuccess(ctx, u.ID, now); err != nil {
		return TokenPair{}, err
	}
	var refresh string
	if withRefresh {
		var hash string
		refresh, hash = identity.NewToken()
		c := clientFrom(ctx)
		if err := s.store.CreateRefreshToken(ctx, store.RefreshToken{
			Hash: hash, UserID: u.ID, TenantID: tenantID, Family: uuid.NewString(),
			ExpiresAt: now.Add(s.userOpts.RefreshTTL), CreatedAt: now,
			UserAgent: c.UserAgent, IP: c.IP,
			ClientID: oauthClientFrom(ctx),
		}); err != nil {
			return TokenPair{}, err
		}
	}
	return s.issue(ctx, u, tenantID, roles, refresh)
}
