package tenant

import (
	"context"
	"errors"
	"strings"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// SocialIdentity is a user authenticated by a social login provider
// (Google, GitHub, ...) with a verified email address.
type SocialIdentity struct {
	Provider, Subject, Email, Name string
	// AutoCreate creates unknown users (as platform users without roles,
	// who can then be invited to tenants).
	AutoCreate bool
}

// SocialSession signs in a user vouched for by a social provider. Users
// with two-factor authentication get ErrMFARequired: the redirect flow
// cannot ask for a code, so they sign in with their password and code (or
// a passkey). Domains that enforce tenant SSO keep enforcing it.
func (s *Service) SocialSession(ctx context.Context, id SocialIdentity, tenantRef string) (TokenPair, error) {
	email := normalizeEmail(id.Email)
	if enforced, err := s.ssoEnforced(ctx, email); err != nil {
		return TokenPair{}, err
	} else if enforced {
		return TokenPair{}, ErrSSORequired
	}
	u, err := s.store.GetUserByEmail(ctx, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if !id.AutoCreate {
			return TokenPair{}, ErrSSORejected
		}
		if u, err = s.createSocialUser(ctx, email, id); err != nil {
			return TokenPair{}, err
		}
	case err != nil:
		return TokenPair{}, err
	case u.Status == sdk.UserDisabled:
		return TokenPair{}, ErrSSORejected
	case u.Status == sdk.UserInvited:
		// The provider verified the address, as the invitation would have.
		if err := s.store.InTx(ctx, func(tx store.Tx) error { return s.activateUser(ctx, tx, u) }); err != nil {
			return TokenPair{}, err
		}
		s.notify()
		if u, err = s.store.GetUser(ctx, u.ID); err != nil {
			return TokenPair{}, err
		}
	}
	creds, err := s.store.GetCredentials(ctx, u.ID)
	if err != nil {
		return TokenPair{}, err
	}
	if creds.LockedUntil != nil && s.now().Before(*creds.LockedUntil) {
		return TokenPair{}, ErrAccountLocked
	}
	if on, err := s.mfaEnabled(ctx, u.ID); err != nil {
		return TokenPair{}, err
	} else if on {
		return TokenPair{}, ErrMFARequired
	}
	return s.OpenSession(ctx, u, tenantRef, true)
}

func (s *Service) createSocialUser(ctx context.Context, email string, id SocialIdentity) (sdk.User, error) {
	now := s.now()
	u := sdk.User{
		ID: uuid.Must(uuid.NewV7()).String(), Email: email, Name: strings.TrimSpace(id.Name),
		Status: sdk.UserActive, EmailVerified: true, Directory: "social",
		Attributes: map[string]string{"social_provider": id.Provider, "social_subject": id.Subject},
		Version:    1, CreatedAt: now, UpdatedAt: now,
	}
	if err := validateUser(&u); err != nil {
		return sdk.User{}, ErrSSORejected
	}
	err := s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		return s.appendUserEvent(ctx, tx, sdk.EventUserCreated, u, nil)
	})
	if err != nil {
		return sdk.User{}, err
	}
	s.notify()
	return u, nil
}
