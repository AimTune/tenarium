package postgres

import (
	"cmp"
	"context"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/jackc/pgx/v5"
)

const ssoQuery = `SELECT c.tenant_id::text, c.issuer, c.client_id, c.client_secret, c.enforce, c.auto_provision,
	c.default_role, c.enabled, c.created_at, c.updated_at, c.protocol, c.saml_metadata, c.saml_metadata_url,
	c.saml_email_attribute, c.saml_name_attribute,
	COALESCE((SELECT array_agg(d.domain ORDER BY d.domain) FROM sso_domains d WHERE d.tenant_id = c.tenant_id), '{}')
	FROM sso_connections c`

func scanSSO(row pgx.Row) (store.SSOConnection, error) {
	var c store.SSOConnection
	if err := row.Scan(&c.TenantID, &c.Issuer, &c.ClientID, &c.ClientSecret, &c.Enforce, &c.AutoProvision,
		&c.DefaultRole, &c.Enabled, &c.CreatedAt, &c.UpdatedAt, &c.Protocol, &c.SAMLMetadata, &c.SAMLMetadataURL,
		&c.SAMLEmailAttribute, &c.SAMLNameAttribute, &c.Domains); err != nil {
		return store.SSOConnection{}, mapErr(err)
	}
	c.CreatedAt, c.UpdatedAt = c.CreatedAt.UTC(), c.UpdatedAt.UTC()
	return c, nil
}

func (s *Store) GetSSOConnection(ctx context.Context, tenantID string) (store.SSOConnection, error) {
	if !isUUID(tenantID) {
		return store.SSOConnection{}, store.ErrNotFound
	}
	return scanSSO(s.pool.QueryRow(ctx, ssoQuery+` WHERE c.tenant_id = $1`, tenantID))
}

func (s *Store) FindSSOConnection(ctx context.Context, domain string) (store.SSOConnection, error) {
	return scanSSO(s.pool.QueryRow(ctx, ssoQuery+` WHERE c.tenant_id = (SELECT tenant_id FROM sso_domains WHERE domain = $1)`, domain))
}

func (s *Store) PutSSOConnection(ctx context.Context, c store.SSOConnection) error {
	if !isUUID(c.TenantID) {
		return store.ErrNotFound
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sso_connections
			(tenant_id, issuer, client_id, client_secret, enforce, auto_provision, default_role, enabled, created_at, updated_at,
			 protocol, saml_metadata, saml_metadata_url, saml_email_attribute, saml_name_attribute)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
			ON CONFLICT (tenant_id) DO UPDATE SET issuer = $2, client_id = $3, client_secret = $4, enforce = $5,
				auto_provision = $6, default_role = $7, enabled = $8, updated_at = $10, protocol = $11, saml_metadata = $12,
				saml_metadata_url = $13, saml_email_attribute = $14, saml_name_attribute = $15`,
			c.TenantID, c.Issuer, c.ClientID, c.ClientSecret, c.Enforce, c.AutoProvision, c.DefaultRole, c.Enabled, c.CreatedAt, c.UpdatedAt,
			cmp.Or(c.Protocol, "oidc"), c.SAMLMetadata, c.SAMLMetadataURL, c.SAMLEmailAttribute, c.SAMLNameAttribute)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM sso_domains WHERE tenant_id = $1`, c.TenantID); err != nil {
			return err
		}
		for _, d := range c.Domains {
			if _, err := tx.Exec(ctx, `INSERT INTO sso_domains (domain, tenant_id) VALUES ($1, $2)`, d, c.TenantID); err != nil {
				return err
			}
		}
		return nil
	})
	if isFKViolation(err) {
		return store.ErrNotFound
	}
	return mapErr(err)
}

func (s *Store) DeleteSSOConnection(ctx context.Context, tenantID string) error {
	if !isUUID(tenantID) {
		return store.ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM sso_connections WHERE tenant_id = $1`, tenantID)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}
