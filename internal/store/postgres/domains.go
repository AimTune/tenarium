package postgres

import (
	"context"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/jackc/pgx/v5"
)

const domainCols = `hostname, tenant_id::text, verified, token, created_at, verified_at`

func scanDomain(row pgx.Row) (store.Domain, error) {
	var d store.Domain
	if err := row.Scan(&d.Hostname, &d.TenantID, &d.Verified, &d.Token, &d.CreatedAt, &d.VerifiedAt); err != nil {
		return store.Domain{}, mapErr(err)
	}
	d.CreatedAt = d.CreatedAt.UTC()
	if d.VerifiedAt != nil {
		v := d.VerifiedAt.UTC()
		d.VerifiedAt = &v
	}
	return d, nil
}

func (s *Store) GetDomain(ctx context.Context, hostname string) (store.Domain, error) {
	return scanDomain(s.pool.QueryRow(ctx, `SELECT `+domainCols+` FROM domains WHERE hostname = $1`, hostname))
}

func (s *Store) ListDomains(ctx context.Context, tenantID string) ([]store.Domain, error) {
	if !isUUID(tenantID) {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+domainCols+` FROM domains WHERE tenant_id = $1 ORDER BY hostname`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (t *tx) CreateDomain(ctx context.Context, d store.Domain) error {
	_, err := t.q.Exec(ctx, `INSERT INTO domains (hostname, tenant_id, verified, token, created_at) VALUES ($1, $2, false, $3, $4)`,
		d.Hostname, d.TenantID, d.Token, d.CreatedAt)
	return mapErr(err)
}

func (t *tx) MarkDomainVerified(ctx context.Context, hostname string, at time.Time) error {
	tag, err := t.q.Exec(ctx, `UPDATE domains SET verified = true, verified_at = $2 WHERE hostname = $1`, hostname, at)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (t *tx) DeleteDomain(ctx context.Context, hostname string) error {
	tag, err := t.q.Exec(ctx, `DELETE FROM domains WHERE hostname = $1`, hostname)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}
