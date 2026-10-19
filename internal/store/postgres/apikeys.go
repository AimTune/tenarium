package postgres

import (
	"context"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/jackc/pgx/v5"
)

//nolint:gosec // column names, not credentials
const apiKeyCols = `id::text, tenant_id, name, prefix, hash, roles, created_by, created_at, expires_at, last_used_at, revoked_at`

func scanAPIKey(row pgx.Row) (store.APIKey, error) {
	var (
		k     store.APIKey
		roles []byte
	)
	err := row.Scan(&k.ID, &k.TenantID, &k.Name, &k.Prefix, &k.Hash, &roles, &k.CreatedBy, &k.CreatedAt,
		&k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt)
	if err != nil {
		return store.APIKey{}, mapErr(err)
	}
	k.CreatedAt = k.CreatedAt.UTC()
	for _, t := range []*time.Time{k.ExpiresAt, k.LastUsedAt, k.RevokedAt} {
		if t != nil {
			*t = t.UTC()
		}
	}
	return k, unjs(roles, &k.Roles)
}

func (s *Store) GetAPIKeyByHash(ctx context.Context, hash string) (store.APIKey, error) {
	return scanAPIKey(s.pool.QueryRow(ctx, `SELECT `+apiKeyCols+` FROM api_keys WHERE hash = $1`, hash))
}

func (s *Store) ListAPIKeys(ctx context.Context, tenantID string) ([]store.APIKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+apiKeyCols+` FROM api_keys WHERE tenant_id = $1 ORDER BY id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) TouchAPIKey(ctx context.Context, id string, at time.Time) error {
	if !isUUID(id) {
		return store.ErrNotFound
	}
	_, err := s.pool.Exec(ctx, `UPDATE api_keys SET last_used_at = $2 WHERE id = $1`, id, at)
	return err
}

func (t *tx) CreateAPIKey(ctx context.Context, k store.APIKey) error {
	_, err := t.q.Exec(ctx, `INSERT INTO api_keys (id, tenant_id, name, prefix, hash, roles, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)`,
		k.ID, k.TenantID, k.Name, k.Prefix, k.Hash, jsList(k.Roles), k.CreatedBy, k.CreatedAt, k.ExpiresAt)
	return mapErr(err)
}

func (t *tx) RevokeAPIKey(ctx context.Context, tenantID, id string, at time.Time) (store.APIKey, error) {
	if !isUUID(id) {
		return store.APIKey{}, store.ErrNotFound
	}
	return scanAPIKey(t.q.QueryRow(ctx, `UPDATE api_keys SET revoked_at = $3
		WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL RETURNING `+apiKeyCols, id, tenantID, at))
}
