package tenant

import (
	"context"
	"errors"
	"strings"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

const (
	tokenMagicLink     = "magic_link"
	tokenEmailChange   = "email_change"
	noticeEmailChanged = "email_changed"

	magicLinkAudience = "tenarium-magic-link"
)

// ErrMagicLinksDisabled means auth.magic_links is off.
var ErrMagicLinksDisabled = errors.New("sign-in links are not enabled")

// The emailed link carries a signed token naming the user and tenant, so
// a second factor can be asked for without spending it; the nonce's
// action token makes it single-use.
type magicLinkClaims struct {
	UserID string `json:"uid"`
	Tenant string `json:"tenant,omitempty"`
	Nonce  string `json:"nonce"`
}

// MagicLinksEnabled reports whether passwordless email sign-in is on.
func (s *Service) MagicLinksEnabled() bool {
	return s.userOpts.MagicLinkTTL > 0 && s.userOpts.Issuer != nil
}

// RequestMagicLink emails a sign-in link (optionally for one tenant) if
// the user exists and is active. Like password resets, it never reveals
// whether the address is known.
func (s *Service) RequestMagicLink(ctx context.Context, email, tenantRef string) error {
	if !s.MagicLinksEnabled() {
		return ErrMagicLinksDisabled
	}
	email = normalizeEmail(email)
	if enforced, err := s.ssoEnforced(ctx, email); err != nil || enforced {
		return err
	}
	u, err := s.store.GetUserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) || (err == nil && u.Status != sdk.UserActive) {
		return nil
	}
	if err != nil {
		return err
	}
	nonce, hash := identity.NewToken()
	now, ttl := s.now(), s.userOpts.MagicLinkTTL
	if err := s.store.CreateActionToken(ctx, store.ActionToken{Hash: hash, Kind: tokenMagicLink, UserID: u.ID,
		ExpiresAt: now.Add(ttl), CreatedAt: now}); err != nil {
		return err
	}
	raw, err := s.userOpts.Issuer.SignClaims(magicLinkAudience, ttl, magicLinkClaims{UserID: u.ID, Tenant: tenantRef, Nonce: nonce})
	if err != nil {
		return err
	}
	msg, err := s.renderEmail(tokenMagicLink, u, s.uiLink("magic/"+raw), now.Add(ttl))
	if err != nil {
		return err
	}
	return s.userOpts.Mailer.Send(ctx, msg)
}

// SignInWithMagicLink opens a session from an emailed link. Users with
// two-factor authentication must also give a code; without one the link
// stays valid and ErrMFARequired is returned.
func (s *Service) SignInWithMagicLink(ctx context.Context, token, otp string) (TokenPair, error) {
	if !s.MagicLinksEnabled() {
		return TokenPair{}, ErrMagicLinksDisabled
	}
	var c magicLinkClaims
	if err := s.userOpts.Issuer.VerifyClaims(token, magicLinkAudience, &c); err != nil {
		return TokenPair{}, ErrInvalidToken
	}
	u, err := s.store.GetUser(ctx, c.UserID)
	if err != nil || u.Status != sdk.UserActive {
		return TokenPair{}, ErrInvalidToken
	}
	if enforced, err := s.ssoEnforced(ctx, u.Email); err != nil {
		return TokenPair{}, err
	} else if enforced && (c.Tenant != "" || len(u.Roles) == 0) {
		return TokenPair{}, ErrSSORequired
	}
	now := s.now()
	creds, err := s.store.GetCredentials(ctx, u.ID)
	if err != nil {
		return TokenPair{}, err
	}
	if creds.LockedUntil != nil && now.Before(*creds.LockedUntil) {
		return TokenPair{}, ErrAccountLocked
	}
	if on, err := s.mfaEnabled(ctx, u.ID); err != nil {
		return TokenPair{}, err
	} else if on {
		if err := s.checkOTP(ctx, u.ID, otp); err != nil {
			if errors.Is(err, ErrInvalidOTP) {
				_, _ = s.store.RecordLoginFailure(ctx, u.ID, s.userOpts.MaxFailures, s.userOpts.LockFor, now)
			}
			return TokenPair{}, err
		}
	}
	if _, err := s.store.ConsumeActionToken(ctx, identity.HashToken(c.Nonce), tokenMagicLink, now); err != nil {
		return TokenPair{}, ErrInvalidToken
	}
	// Following the link proves control of the address.
	if !u.EmailVerified {
		verified := true
		if u, err = s.UpdateUser(ctx, u.ID, UserUpdate{EmailVerified: &verified}, nil); err != nil {
			return TokenPair{}, err
		}
	}
	return s.OpenSession(ctx, u, c.Tenant, true)
}

// RequestEmailChange asks a user to confirm a new address: a link is sent
// there, and the address changes only when it is followed. The current
// password is required so a stolen session cannot take over the account.
func (s *Service) RequestEmailChange(ctx context.Context, userID, newEmail, password string) error {
	if !s.internalDirectory() {
		return stateErr("email addresses are managed by the %s directory", s.directoryName())
	}
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.checkPassword(ctx, u, password); err != nil {
		return ErrInvalidCredentials
	}
	next := u
	next.Email = normalizeEmail(newEmail)
	if err := validateUser(&next); err != nil {
		return err
	}
	if strings.EqualFold(next.Email, u.Email) {
		return invalid("email", "this is already your address")
	}
	if _, err := s.store.GetUserByEmail(ctx, next.Email); err == nil {
		return invalid("email", "the address is in use")
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	token, hash := identity.NewToken()
	now, ttl := s.now(), s.userOpts.EmailChangeTTL
	if err := s.store.CreateActionToken(ctx, store.ActionToken{Hash: hash, Kind: tokenEmailChange, UserID: u.ID,
		Data: next.Email, ExpiresAt: now.Add(ttl), CreatedAt: now}); err != nil {
		return err
	}
	// Rendered for the new address, which is where it goes.
	msg, err := s.renderEmail(tokenEmailChange, next, s.uiLink("confirm-email/"+token), now.Add(ttl))
	if err != nil {
		return err
	}
	return s.userOpts.Mailer.Send(ctx, msg)
}

// ConfirmEmailChange applies a confirmed address change and tells the old
// address about it.
func (s *Service) ConfirmEmailChange(ctx context.Context, token string) (sdk.User, error) {
	at, err := s.store.ConsumeActionToken(ctx, identity.HashToken(token), tokenEmailChange, s.now())
	if err != nil {
		return sdk.User{}, ErrInvalidToken
	}
	prev, err := s.store.GetUser(ctx, at.UserID)
	if err != nil {
		return sdk.User{}, ErrInvalidToken
	}
	verified := true
	u, err := s.UpdateUser(ctx, prev.ID, UserUpdate{Email: &at.Data, EmailVerified: &verified}, nil)
	if err != nil {
		return sdk.User{}, err
	}
	msg, err := s.renderEmail(noticeEmailChanged, prev, s.uiLink(""), s.now(), map[string]any{"NewEmail": u.Email})
	if err == nil {
		err = s.userOpts.Mailer.Send(ctx, msg)
	}
	if err != nil {
		s.userOpts.Log.Warn("could not notify the previous email address", "user_id", u.ID, "err", err)
	}
	return u, nil
}

func (s *Service) uiLink(fragment string) string {
	return strings.TrimRight(s.userOpts.PublicURL, "/") + "/ui/#/" + fragment
}
