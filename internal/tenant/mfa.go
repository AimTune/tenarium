package tenant

import (
	"context"
	"errors"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
)

// MFA event types.
const (
	EventUserMFAEnabled  = "user.mfa_enabled"
	EventUserMFADisabled = "user.mfa_disabled"
)

// recoveryCodeCount is how many recovery codes a user gets.
const recoveryCodeCount = 10

var (
	// ErrMFARequired means the password was right but the user must also
	// give a one-time code (TOTP or recovery code).
	ErrMFARequired = errors.New("a one-time code is required")
	// ErrInvalidOTP means the one-time code was wrong or already used.
	ErrInvalidOTP = errors.New("invalid or already used one-time code")
)

// MFAStatus describes a user's second factor.
type MFAStatus struct {
	Enabled bool `json:"enabled"`
	// Pending is true between enrollment and confirmation.
	Pending           bool `json:"pending"`
	RecoveryCodesLeft int  `json:"recovery_codes_left"`
}

// TOTPEnrollment is what an authenticator app needs.
type TOTPEnrollment struct {
	Secret string `json:"secret"`
	URL    string `json:"otpauth_url"`
}

func (s *Service) MFAStatus(ctx context.Context, userID string) (MFAStatus, error) {
	m, err := s.store.GetMFA(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return MFAStatus{}, nil
	}
	if err != nil {
		return MFAStatus{}, err
	}
	return MFAStatus{Enabled: m.Enabled, Pending: !m.Enabled, RecoveryCodesLeft: len(m.RecoveryHashes)}, nil
}

// BeginTOTP starts enrollment with a new secret. It replaces an earlier
// unconfirmed enrollment but not an enabled second factor.
func (s *Service) BeginTOTP(ctx context.Context, userID string) (TOTPEnrollment, error) {
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	if st, err := s.MFAStatus(ctx, u.ID); err != nil {
		return TOTPEnrollment{}, err
	} else if st.Enabled {
		return TOTPEnrollment{}, stateErr("two-factor authentication is already enabled; disable it first")
	}
	secret := identity.NewTOTPSecret()
	if err := s.store.PutMFA(ctx, store.MFA{UserID: u.ID, TOTPSecret: secret, UpdatedAt: s.now()}); err != nil {
		return TOTPEnrollment{}, err
	}
	return TOTPEnrollment{Secret: secret, URL: identity.OTPAuthURL(s.userOpts.ProductName, u.Email, secret)}, nil
}

// ConfirmTOTP enables the pending second factor once the user proves the
// app works, and returns the recovery codes (shown only now).
func (s *Service) ConfirmTOTP(ctx context.Context, userID, code string) ([]string, error) {
	m, err := s.store.GetMFA(ctx, userID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && m.Enabled) {
		return nil, stateErr("no two-factor enrollment is pending")
	}
	if err != nil {
		return nil, err
	}
	step, ok := identity.VerifyTOTP(m.TOTPSecret, code, s.now(), m.LastStep)
	if !ok {
		return nil, ErrInvalidOTP
	}
	codes, hashes := identity.NewRecoveryCodes(recoveryCodeCount)
	m.Enabled, m.LastStep, m.RecoveryHashes, m.UpdatedAt = true, step, hashes, s.now()
	if err := s.store.PutMFA(ctx, m); err != nil {
		return nil, err
	}
	return codes, s.mfaEvent(ctx, userID, EventUserMFAEnabled)
}

// DisableMFA removes the user's second factor after checking a code.
func (s *Service) DisableMFA(ctx context.Context, userID, code string) error {
	if err := s.checkOTP(ctx, userID, code); err != nil {
		return err
	}
	if err := s.store.DeleteMFA(ctx, userID); err != nil {
		return err
	}
	return s.mfaEvent(ctx, userID, EventUserMFADisabled)
}

// RegenerateRecoveryCodes replaces the recovery codes after checking a
// code.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, userID, code string) ([]string, error) {
	if err := s.checkOTP(ctx, userID, code); err != nil {
		return nil, err
	}
	m, err := s.store.GetMFA(ctx, userID)
	if err != nil {
		return nil, err
	}
	codes, hashes := identity.NewRecoveryCodes(recoveryCodeCount)
	m.RecoveryHashes, m.UpdatedAt = hashes, s.now()
	return codes, s.store.PutMFA(ctx, m)
}

// ResetMFA removes a user's second factor without a code, for admins
// helping a user who lost their device.
func (s *Service) ResetMFA(ctx context.Context, idOrEmail string) error {
	u, err := s.GetUser(ctx, idOrEmail)
	if err != nil {
		return err
	}
	if err := s.store.DeleteMFA(ctx, u.ID); err != nil {
		return err
	}
	return s.mfaEvent(ctx, u.ID, EventUserMFADisabled)
}

// checkOTP verifies an enabled second factor's TOTP or recovery code and
// consumes it.
func (s *Service) checkOTP(ctx context.Context, userID, code string) error {
	m, err := s.store.GetMFA(ctx, userID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !m.Enabled) {
		return stateErr("two-factor authentication is not enabled")
	}
	if err != nil {
		return err
	}
	if code == "" {
		return ErrMFARequired
	}
	if step, ok := identity.VerifyTOTP(m.TOTPSecret, code, s.now(), m.LastStep); ok {
		// The conditional update makes concurrent uses of one code fail.
		if used, err := s.store.UseTOTPStep(ctx, userID, step); err != nil || used {
			return err
		}
		return ErrInvalidOTP
	}
	used, err := s.store.UseRecoveryCode(ctx, userID, identity.HashRecoveryCode(code))
	if err != nil {
		return err
	}
	if !used {
		return ErrInvalidOTP
	}
	return nil
}

// mfaEnabled reports whether login needs a second factor.
func (s *Service) mfaEnabled(ctx context.Context, userID string) (bool, error) {
	st, err := s.MFAStatus(ctx, userID)
	return st.Enabled, err
}

func (s *Service) mfaEvent(ctx context.Context, userID, typ string) error {
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error { return s.appendUserEvent(ctx, tx, typ, u, nil) })
	if err == nil {
		s.notify()
	}
	return err
}
