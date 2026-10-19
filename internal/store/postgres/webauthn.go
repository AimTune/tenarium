package postgres

import (
	"context"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/jackc/pgx/v5"
)

const passkeyCols = `id, user_id::text, name, data, created_at, last_used_at` //nolint:gosec // G101: column names, not credentials

func scanPasskey(row pgx.Row) (store.WebAuthnCredential, error) {
	var c store.WebAuthnCredential
	if err := row.Scan(&c.ID, &c.UserID, &c.Name, &c.Data, &c.CreatedAt, &c.LastUsedAt); err != nil {
		return store.WebAuthnCredential{}, mapErr(err)
	}
	c.CreatedAt, c.LastUsedAt = c.CreatedAt.UTC(), utcPtr(c.LastUsedAt)
	return c, nil
}

func (s *Store) ListWebAuthnCredentials(ctx context.Context, userID string) ([]store.WebAuthnCredential, error) {
	if !isUUID(userID) {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+passkeyCols+` FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.WebAuthnCredential
	for rows.Next() {
		c, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetWebAuthnCredential(ctx context.Context, id string) (store.WebAuthnCredential, error) {
	return scanPasskey(s.pool.QueryRow(ctx, `SELECT `+passkeyCols+` FROM webauthn_credentials WHERE id = $1`, id))
}

func (s *Store) PutWebAuthnCredential(ctx context.Context, c store.WebAuthnCredential) error {
	if !isUUID(c.UserID) {
		return store.ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO webauthn_credentials (id, user_id, name, data, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET name = $3, data = $4, last_used_at = $6 WHERE webauthn_credentials.user_id = $2`,
		c.ID, c.UserID, c.Name, c.Data, c.CreatedAt, c.LastUsedAt)
	if isFKViolation(err) {
		return store.ErrNotFound
	}
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrAlreadyExists // the ID belongs to another user
	}
	return nil
}

func (s *Store) DeleteWebAuthnCredential(ctx context.Context, userID, id string) error {
	if !isUUID(userID) {
		return store.ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM webauthn_credentials WHERE user_id = $1 AND id = $2`, userID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}
