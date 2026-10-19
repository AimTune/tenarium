package tenant

import (
	"context"

	"github.com/AimTune/tenarium/internal/store"
)

// EventUserSessionRevoked is emitted when a session is signed out remotely.
const EventUserSessionRevoked = "user.session_revoked"

type clientKey struct{}

// ClientInfo describes the client of a request, recorded on the sessions
// it opens so users can recognise them.
type ClientInfo struct {
	UserAgent string
	IP        string
}

// WithClient attaches the request's client to ctx.
func WithClient(ctx context.Context, c ClientInfo) context.Context {
	if len(c.UserAgent) > 512 {
		c.UserAgent = c.UserAgent[:512]
	}
	return context.WithValue(ctx, clientKey{}, c)
}

func clientFrom(ctx context.Context) ClientInfo {
	c, _ := ctx.Value(clientKey{}).(ClientInfo)
	return c
}

// ListSessions returns a user's signed-in clients (one per refresh token
// family), most recently used first.
func (s *Service) ListSessions(ctx context.Context, idOrEmail string) ([]store.Session, error) {
	u, err := s.GetUser(ctx, idOrEmail)
	if err != nil {
		return nil, err
	}
	return s.store.ListSessions(ctx, u.ID, s.now())
}

// RevokeSession signs one of a user's clients out. Access tokens already
// issued stay valid until they expire (minutes); the session can no longer
// be refreshed.
func (s *Service) RevokeSession(ctx context.Context, idOrEmail, sessionID string) error {
	u, err := s.GetUser(ctx, idOrEmail)
	if err != nil {
		return err
	}
	if err := s.store.RevokeSession(ctx, u.ID, sessionID, s.now()); err != nil {
		return err
	}
	return s.RecordEvent(ctx, EventUserSessionRevoked, "", "users/"+u.ID, map[string]string{"user_id": u.ID, "session_id": sessionID})
}

type oauthClientKey struct{}

// WithOAuthClient marks sessions opened or refreshed under ctx as belonging
// to an OAuth client of the OpenID provider. Such sessions can only be
// refreshed by that client, and first-party sessions by no client.
func WithOAuthClient(ctx context.Context, clientID string) context.Context {
	return context.WithValue(ctx, oauthClientKey{}, clientID)
}

func oauthClientFrom(ctx context.Context) string {
	id, _ := ctx.Value(oauthClientKey{}).(string)
	return id
}
