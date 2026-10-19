package postgres

import (
	"context"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/jackc/pgx/v5"
)

const clientCols = `id, name, secret_hash, redirect_uris, post_logout_redirect_uris, tenant_id, scopes, first_party, created_at, updated_at`

func scanClient(row pgx.Row) (store.OAuthClient, error) {
	var c store.OAuthClient
	if err := row.Scan(&c.ID, &c.Name, &c.SecretHash, &c.RedirectURIs, &c.PostLogoutRedirectURIs, &c.TenantID, &c.Scopes,
		&c.FirstParty, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return store.OAuthClient{}, mapErr(err)
	}
	c.CreatedAt, c.UpdatedAt = c.CreatedAt.UTC(), c.UpdatedAt.UTC()
	return c, nil
}

func (s *Store) GetOAuthClient(ctx context.Context, id string) (store.OAuthClient, error) {
	return scanClient(s.pool.QueryRow(ctx, `SELECT `+clientCols+` FROM oauth_clients WHERE id = $1`, id))
}

func (s *Store) ListOAuthClients(ctx context.Context) ([]store.OAuthClient, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+clientCols+` FROM oauth_clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.OAuthClient
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) PutOAuthClient(ctx context.Context, c store.OAuthClient) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO oauth_clients (`+clientCols+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET name = $2, secret_hash = $3, redirect_uris = $4, post_logout_redirect_uris = $5,
			tenant_id = $6, scopes = $7, first_party = $8, updated_at = $10`,
		c.ID, c.Name, c.SecretHash, nonNilStrings(c.RedirectURIs), nonNilStrings(c.PostLogoutRedirectURIs), c.TenantID,
		nonNilStrings(c.Scopes), c.FirstParty, c.CreatedAt, c.UpdatedAt)
	return mapErr(err)
}

func (s *Store) DeleteOAuthClient(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM oauth_clients WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) GetOAuthConsent(ctx context.Context, userID, clientID string) (store.OAuthConsent, error) {
	if !isUUID(userID) {
		return store.OAuthConsent{}, store.ErrNotFound
	}
	var c store.OAuthConsent
	err := s.pool.QueryRow(ctx, `SELECT user_id::text, client_id, scopes, created_at FROM oauth_consents WHERE user_id = $1 AND client_id = $2`,
		userID, clientID).Scan(&c.UserID, &c.ClientID, &c.Scopes, &c.CreatedAt)
	c.CreatedAt = c.CreatedAt.UTC()
	return c, mapErr(err)
}

func (s *Store) PutOAuthConsent(ctx context.Context, c store.OAuthConsent) error {
	if !isUUID(c.UserID) {
		return store.ErrNotFound
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO oauth_consents (user_id, client_id, scopes, created_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = $3, created_at = $4`,
		c.UserID, c.ClientID, nonNilStrings(c.Scopes), c.CreatedAt)
	if isFKViolation(err) {
		return store.ErrNotFound
	}
	return mapErr(err)
}
