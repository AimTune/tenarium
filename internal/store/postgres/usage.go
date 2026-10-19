package postgres

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/jackc/pgx/v5"
)

const usageCols = `tenant_id::text, metric, period, value, period_end, closed_at, updated_at`

func (s *Store) queryUsage(ctx context.Context, q string, args ...any) ([]store.Usage, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Usage
	for rows.Next() {
		var u store.Usage
		if err := rows.Scan(&u.TenantID, &u.Metric, &u.Period, &u.Value, &u.PeriodEnd, &u.ClosedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		u.UpdatedAt, u.PeriodEnd, u.ClosedAt = u.UpdatedAt.UTC(), utcPtr(u.PeriodEnd), utcPtr(u.ClosedAt)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) ListUsage(ctx context.Context, q store.UsageQuery) ([]store.Usage, error) {
	var (
		where []string
		args  []any
	)
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if q.TenantID != "" {
		if !isUUID(q.TenantID) {
			return nil, nil
		}
		where = append(where, "tenant_id = "+arg(q.TenantID))
	}
	if q.Metric != "" {
		where = append(where, "metric = "+arg(q.Metric))
	}
	if len(q.Periods) > 0 {
		where = append(where, "period = ANY("+arg(q.Periods)+")")
	}
	sql := `SELECT ` + usageCols + ` FROM usage`
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY tenant_id, metric, period DESC"
	if q.Limit > 0 {
		sql += " LIMIT " + arg(q.Limit)
	}
	return s.queryUsage(ctx, sql, args...)
}

func (s *Store) EndedUsage(ctx context.Context, now time.Time, limit int) ([]store.Usage, error) {
	return s.queryUsage(ctx, `SELECT `+usageCols+` FROM usage
		WHERE period_end IS NOT NULL AND period_end <= $1 AND closed_at IS NULL ORDER BY period_end LIMIT $2`, now, limit)
}

func (s *Store) IncrementUsage(ctx context.Context, key store.UsageKey, delta int64, limit *int64) (int64, error) {
	var value int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Upsert-and-lock the row so concurrent increments serialise.
		_, err := tx.Exec(ctx, `INSERT INTO usage (tenant_id, metric, period, period_end, value, updated_at)
			VALUES ($1, $2, $3, $4, 0, now()) ON CONFLICT DO NOTHING`, key.TenantID, key.Metric, key.Period, key.PeriodEnd)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT value FROM usage WHERE tenant_id = $1 AND metric = $2 AND period = $3 FOR UPDATE`,
			key.TenantID, key.Metric, key.Period).Scan(&value); err != nil {
			return err
		}
		if limit != nil && delta > 0 && value+delta > *limit {
			return store.ErrQuotaExceeded
		}
		value = max(value+delta, 0)
		_, err = tx.Exec(ctx, `UPDATE usage SET value = $4, updated_at = now() WHERE tenant_id = $1 AND metric = $2 AND period = $3`,
			key.TenantID, key.Metric, key.Period, value)
		return err
	})
	return value, err
}

func (t *tx) CloseUsage(ctx context.Context, tenantID, metric, period string, at time.Time) error {
	tag, err := t.q.Exec(ctx, `UPDATE usage SET closed_at = $4 WHERE tenant_id = $1 AND metric = $2 AND period = $3 AND closed_at IS NULL`,
		tenantID, metric, period, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var n int
	if err := t.q.QueryRow(ctx, `SELECT count(*) FROM usage WHERE tenant_id = $1 AND metric = $2 AND period = $3`, tenantID, metric, period).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return store.ErrConflict
}
