package postgres

import (
	"context"
	"errors"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Store) GetMFA(ctx context.Context, userID string) (store.MFA, error) {
	if !isUUID(userID) {
		return store.MFA{}, store.ErrNotFound
	}
	var m store.MFA
	err := s.pool.QueryRow(ctx, `SELECT user_id::text, totp_secret, enabled, last_step, recovery_hashes, updated_at
		FROM user_mfa WHERE user_id = $1`, userID).
		Scan(&m.UserID, &m.TOTPSecret, &m.Enabled, &m.LastStep, &m.RecoveryHashes, &m.UpdatedAt)
	m.UpdatedAt = m.UpdatedAt.UTC()
	return m, mapErr(err)
}

func (s *Store) PutMFA(ctx context.Context, m store.MFA) error {
	if m.RecoveryHashes == nil {
		m.RecoveryHashes = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO user_mfa (user_id, totp_secret, enabled, last_step, recovery_hashes, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id) DO UPDATE SET totp_secret = $2, enabled = $3, last_step = $4, recovery_hashes = $5, updated_at = $6`,
		m.UserID, m.TOTPSecret, m.Enabled, m.LastStep, m.RecoveryHashes, m.UpdatedAt)
	if isFKViolation(err) {
		return store.ErrNotFound
	}
	return mapErr(err)
}

func (s *Store) DeleteMFA(ctx context.Context, userID string) error {
	if !isUUID(userID) {
		return store.ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM user_mfa WHERE user_id = $1`, userID)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) UseTOTPStep(ctx context.Context, userID string, step int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE user_mfa SET last_step = $2 WHERE user_id = $1 AND last_step < $2`, userID, step)
	return err == nil && tag.RowsAffected() == 1, err
}

func (s *Store) UseRecoveryCode(ctx context.Context, userID, hash string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE user_mfa SET recovery_hashes = array_remove(recovery_hashes, $2)
		WHERE user_id = $1 AND $2 = ANY(recovery_hashes)`, userID, hash)
	return err == nil && tag.RowsAffected() == 1, err
}

func isFKViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}
