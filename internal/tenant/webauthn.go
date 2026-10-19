package tenant

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// Passkey event types.
const (
	EventUserPasskeyAdded   = "user.passkey_added"
	EventUserPasskeyRemoved = "user.passkey_removed" //nolint:gosec // G101: an event type name, not a credential
)

const (
	ceremonyAudience = "tenarium-webauthn"
	ceremonyTTL      = 5 * time.Minute
	maxPasskeys      = 20
)

var (
	// ErrPasskeysDisabled means WebAuthn is not configured.
	ErrPasskeysDisabled = errors.New("passkeys are not enabled")
	// ErrPasskeyRejected covers failed or replayed WebAuthn ceremonies.
	ErrPasskeyRejected = errors.New("passkey verification failed")
)

// waUser adapts a user and its credentials to the WebAuthn library.
type waUser struct {
	u     sdk.User
	creds []webauthn.Credential
}

func (w waUser) WebAuthnID() []byte                         { return []byte(w.u.ID) }
func (w waUser) WebAuthnName() string                       { return w.u.Email }
func (w waUser) WebAuthnDisplayName() string                { return strings.TrimSpace(w.u.Name + " " + w.u.Email) }
func (w waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// ceremony is the server state of a registration or login, signed and
// handed to the client, so no replica needs to remember it.
type ceremony struct {
	Purpose string               `json:"purpose"`
	UserID  string               `json:"uid,omitempty"`
	Session webauthn.SessionData `json:"session"`
}

func (s *Service) webauthn() (*webauthn.WebAuthn, error) {
	if s.userOpts.WebAuthn == nil || s.userOpts.Issuer == nil {
		return nil, ErrPasskeysDisabled
	}
	return s.userOpts.WebAuthn, nil
}

func (s *Service) sealCeremony(c ceremony) (string, error) {
	return s.userOpts.Issuer.SignClaims(ceremonyAudience, ceremonyTTL, c)
}

func (s *Service) openCeremony(raw, purpose string) (ceremony, error) {
	var c ceremony
	if err := s.userOpts.Issuer.VerifyClaims(raw, ceremonyAudience, &c); err != nil || c.Purpose != purpose {
		return c, ErrPasskeyRejected
	}
	return c, nil
}

func (s *Service) waUser(ctx context.Context, u sdk.User) (waUser, error) {
	stored, err := s.store.ListWebAuthnCredentials(ctx, u.ID)
	if err != nil {
		return waUser{}, err
	}
	w := waUser{u: u}
	for _, sc := range stored {
		var c webauthn.Credential
		if err := json.Unmarshal(sc.Data, &c); err != nil {
			return waUser{}, fmt.Errorf("passkey %s: %w", sc.ID, err)
		}
		w.creds = append(w.creds, c)
	}
	return w, nil
}

func credID(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

// BeginPasskeyRegistration returns the options for navigator.credentials
// .create() and the ceremony to send back with the result.
func (s *Service) BeginPasskeyRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, string, error) {
	wa, err := s.webauthn()
	if err != nil {
		return nil, "", err
	}
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	w, err := s.waUser(ctx, u)
	if err != nil {
		return nil, "", err
	}
	if len(w.creds) >= maxPasskeys {
		return nil, "", invalid("passkeys", "at most %d passkeys per user", maxPasskeys)
	}
	var exclude []protocol.CredentialDescriptor
	for _, c := range w.creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, session, err := wa.BeginRegistration(w,
		webauthn.WithExclusions(exclude),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred))
	if err != nil {
		return nil, "", err
	}
	token, err := s.sealCeremony(ceremony{Purpose: "register", UserID: u.ID, Session: *session})
	return opts, token, err
}

// FinishPasskeyRegistration verifies the authenticator's response and
// stores the new credential.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, userID, token, name string, response []byte) (store.WebAuthnCredential, error) {
	wa, err := s.webauthn()
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	c, err := s.openCeremony(token, "register")
	if err != nil || c.UserID != userID {
		return store.WebAuthnCredential{}, ErrPasskeyRejected
	}
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	w, err := s.waUser(ctx, u)
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(response))
	if err != nil {
		return store.WebAuthnCredential{}, fmt.Errorf("%w: %w", ErrPasskeyRejected, err)
	}
	cred, err := wa.CreateCredential(w, c.Session, parsed)
	if err != nil {
		return store.WebAuthnCredential{}, fmt.Errorf("%w: %w", ErrPasskeyRejected, err)
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	if name = strings.TrimSpace(name); name == "" {
		name = "Passkey"
	}
	sc := store.WebAuthnCredential{ID: credID(cred.ID), UserID: u.ID, Name: name, Data: data, CreatedAt: s.now()}
	if err := s.store.PutWebAuthnCredential(ctx, sc); err != nil {
		return store.WebAuthnCredential{}, err
	}
	return sc, s.passkeyEvent(ctx, u, EventUserPasskeyAdded, sc)
}

func (s *Service) ListPasskeys(ctx context.Context, userID string) ([]store.WebAuthnCredential, error) {
	return s.store.ListWebAuthnCredentials(ctx, userID)
}

func (s *Service) DeletePasskey(ctx context.Context, userID, id string) error {
	sc, err := s.store.GetWebAuthnCredential(ctx, id)
	if err != nil || sc.UserID != userID {
		return store.ErrNotFound
	}
	if err := s.store.DeleteWebAuthnCredential(ctx, userID, id); err != nil {
		return err
	}
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	return s.passkeyEvent(ctx, u, EventUserPasskeyRemoved, sc)
}

func (s *Service) passkeyEvent(ctx context.Context, u sdk.User, typ string, c store.WebAuthnCredential) error {
	err := s.store.InTx(ctx, func(tx store.Tx) error {
		return s.appendEvent(ctx, tx, typ, "", "users/"+u.ID+"/passkeys/"+c.ID,
			map[string]any{"user_id": u.ID, "email": u.Email, "passkey_id": c.ID, "name": c.Name})
	})
	if err == nil {
		s.notify()
	}
	return err
}

// BeginPasskeyLogin starts a sign-in. Without an email the browser offers
// any passkey it holds for this site (discoverable credentials); with one,
// that user's passkeys are allowed. Unknown emails get the discoverable
// options too, so the answer does not reveal which accounts exist.
func (s *Service) BeginPasskeyLogin(ctx context.Context, email string) (*protocol.CredentialAssertion, string, error) {
	wa, err := s.webauthn()
	if err != nil {
		return nil, "", err
	}
	var allow []protocol.CredentialDescriptor
	if email != "" {
		if u, err := s.store.GetUserByEmail(ctx, normalizeEmail(email)); err == nil {
			if w, err := s.waUser(ctx, u); err == nil {
				for _, c := range w.creds {
					allow = append(allow, c.Descriptor())
				}
			}
		}
	}
	var opts []webauthn.LoginOption
	if len(allow) > 0 {
		opts = append(opts, webauthn.WithAllowedCredentials(allow))
	}
	assertion, session, err := wa.BeginDiscoverableLogin(opts...)
	if err != nil {
		return nil, "", err
	}
	token, err := s.sealCeremony(ceremony{Purpose: "login", Session: *session})
	return assertion, token, err
}

// FinishPasskeyLogin verifies the assertion and opens a session (scoped to
// tenantRef if given). A passkey is a strong factor on its own, so no
// one-time code is asked; SSO enforcement applies as for passwords.
func (s *Service) FinishPasskeyLogin(ctx context.Context, token string, response []byte, tenantRef string) (TokenPair, error) {
	wa, err := s.webauthn()
	if err != nil {
		return TokenPair{}, err
	}
	c, err := s.openCeremony(token, "login")
	if err != nil {
		return TokenPair{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(response))
	if err != nil {
		return TokenPair{}, ErrPasskeyRejected
	}
	var found waUser
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, err := s.store.GetUser(ctx, string(userHandle))
		if err != nil {
			return nil, err
		}
		w, err := s.waUser(ctx, u)
		found = w
		return w, err
	}
	cred, err := wa.ValidateDiscoverableLogin(handler, c.Session, parsed)
	if err != nil || cred.Authenticator.CloneWarning {
		return TokenPair{}, ErrPasskeyRejected
	}
	u := found.u
	if u.Status != sdk.UserActive {
		return TokenPair{}, ErrPasskeyRejected
	}
	if enforced, err := s.ssoEnforced(ctx, u.Email); err != nil {
		return TokenPair{}, err
	} else if enforced && (tenantRef != "" || len(u.Roles) == 0) {
		return TokenPair{}, ErrSSORequired
	}
	now := s.now()
	if creds, err := s.store.GetCredentials(ctx, u.ID); err == nil && creds.LockedUntil != nil && now.Before(*creds.LockedUntil) {
		return TokenPair{}, ErrAccountLocked
	}
	// Persist the new signature counter (clone detection) and last use.
	if sc, err := s.store.GetWebAuthnCredential(ctx, credID(cred.ID)); err == nil {
		if data, err := json.Marshal(cred); err == nil {
			sc.Data, sc.LastUsedAt = data, &now
			_ = s.store.PutWebAuthnCredential(ctx, sc)
		}
	}
	tenantID, roles, err := s.sessionScope(ctx, u, tenantRef)
	if err != nil {
		return TokenPair{}, err
	}
	if err := s.store.RecordLoginSuccess(ctx, u.ID, now); err != nil {
		return TokenPair{}, err
	}
	refresh, hash := identity.NewToken()
	if err := s.store.CreateRefreshToken(ctx, store.RefreshToken{
		Hash: hash, UserID: u.ID, TenantID: tenantID, Family: uuid.NewString(),
		ExpiresAt: now.Add(s.userOpts.RefreshTTL), CreatedAt: now,
	}); err != nil {
		return TokenPair{}, err
	}
	return s.issue(ctx, u, tenantID, roles, refresh)
}
