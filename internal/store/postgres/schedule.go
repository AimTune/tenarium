package postgres

import (
	"context"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/jackc/pgx/v5"
)

const scheduleCols = `id::text, tenant_id::text, action, plan, reason, run_at, status, error, created_by, created_at, claimed_at, done_at`

func scanScheduled(row pgx.Row) (store.ScheduledAction, error) {
	var a store.ScheduledAction
	if err := row.Scan(&a.ID, &a.TenantID, &a.Action, &a.Plan, &a.Reason, &a.RunAt, &a.Status, &a.Error,
		&a.CreatedBy, &a.CreatedAt, &a.ClaimedAt, &a.DoneAt); err != nil {
		return store.ScheduledAction{}, mapErr(err)
	}
	a.RunAt, a.CreatedAt = a.RunAt.UTC(), a.CreatedAt.UTC()
	a.ClaimedAt, a.DoneAt = utcPtr(a.ClaimedAt), utcPtr(a.DoneAt)
	return a, nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func (s *Store) GetScheduledAction(ctx context.Context, id string) (store.ScheduledAction, error) {
	if !isUUID(id) {
		return store.ScheduledAction{}, store.ErrNotFound
	}
	return scanScheduled(s.pool.QueryRow(ctx, `SELECT `+scheduleCols+` FROM scheduled_actions WHERE id = $1`, id))
}

func (s *Store) ListScheduledActions(ctx context.Context, tenantID string) ([]store.ScheduledAction, error) {
	if !isUUID(tenantID) {
		return nil, nil
	}
	return s.querySchedule(ctx, `SELECT `+scheduleCols+` FROM scheduled_actions WHERE tenant_id = $1 ORDER BY run_at, id`, tenantID)
}

func (s *Store) DueScheduledActions(ctx context.Context, now, staleBefore time.Time, limit int) ([]store.ScheduledAction, error) {
	return s.querySchedule(ctx, `SELECT `+scheduleCols+` FROM scheduled_actions
		WHERE (status = 'pending' AND run_at <= $1) OR (status = 'running' AND claimed_at < $2)
		ORDER BY run_at, id LIMIT $3`, now, staleBefore, limit)
}

func (s *Store) querySchedule(ctx context.Context, q string, args ...any) ([]store.ScheduledAction, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.ScheduledAction
	for rows.Next() {
		a, err := scanScheduled(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (t *tx) CreateScheduledAction(ctx context.Context, a store.ScheduledAction) error {
	_, err := t.q.Exec(ctx, `INSERT INTO scheduled_actions
		(id, tenant_id, action, plan, reason, run_at, status, error, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		a.ID, a.TenantID, a.Action, a.Plan, a.Reason, a.RunAt, a.Status, a.Error, a.CreatedBy, a.CreatedAt)
	return mapErr(err)
}

func (t *tx) ClaimScheduledAction(ctx context.Context, id string, at, staleBefore time.Time) error {
	tag, err := t.q.Exec(ctx, `UPDATE scheduled_actions SET status = 'running', claimed_at = $2
		WHERE id = $1 AND ((status = 'pending' AND run_at <= $2) OR (status = 'running' AND claimed_at < $3))`,
		id, at, staleBefore)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return t.scheduleMiss(ctx, id)
	}
	return nil
}

func (t *tx) FinishScheduledAction(ctx context.Context, id, status, errMsg string, at time.Time) error {
	tag, err := t.q.Exec(ctx, `UPDATE scheduled_actions SET status = $2, error = $3, done_at = $4
		WHERE id = $1 AND status IN ('pending', 'running')`, id, status, errMsg, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return t.scheduleMiss(ctx, id)
	}
	return nil
}

// scheduleMiss tells a missing action (ErrNotFound) from one in the wrong
// state (ErrConflict).
func (t *tx) scheduleMiss(ctx context.Context, id string) error {
	var n int
	if err := t.q.QueryRow(ctx, `SELECT count(*) FROM scheduled_actions WHERE id = $1`, id).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return store.ErrConflict
}
