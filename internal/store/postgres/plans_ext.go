package postgres

import (
	"context"
	"encoding/json"

	"github.com/AimTune/tenarium/internal/store"
)

func (s *Store) ListPlanRevisions(ctx context.Context, planID string) ([]store.PlanRevision, error) {
	rows, err := s.pool.Query(ctx, `SELECT plan_id, revision, features, limits, created_at FROM plan_revisions
		WHERE plan_id = $1 ORDER BY revision DESC`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.PlanRevision
	for rows.Next() {
		var (
			r        store.PlanRevision
			fs, lims []byte
		)
		if err := rows.Scan(&r.PlanID, &r.Revision, &fs, &lims, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.CreatedAt = r.CreatedAt.UTC()
		if err := unjs(fs, &r.Features); err != nil {
			return nil, err
		}
		if err := unjs(lims, &r.Limits); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetPlanRevision(ctx context.Context, planID string, revision int64) (store.PlanRevision, error) {
	var (
		r        store.PlanRevision
		fs, lims []byte
	)
	err := s.pool.QueryRow(ctx, `SELECT plan_id, revision, features, limits, created_at FROM plan_revisions
		WHERE plan_id = $1 AND revision = $2`, planID, revision).Scan(&r.PlanID, &r.Revision, &fs, &lims, &r.CreatedAt)
	if err != nil {
		return r, mapErr(err)
	}
	r.CreatedAt = r.CreatedAt.UTC()
	if err := unjs(fs, &r.Features); err != nil {
		return r, err
	}
	return r, unjs(lims, &r.Limits)
}

func (t *tx) PutPlanRevision(ctx context.Context, r store.PlanRevision) error {
	_, err := t.q.Exec(ctx, `INSERT INTO plan_revisions (plan_id, revision, features, limits, created_at)
		VALUES ($1, $2, $3::jsonb, $4::jsonb, $5) ON CONFLICT (plan_id, revision) DO NOTHING`,
		r.PlanID, r.Revision, js(r.Features), js(r.Limits), r.CreatedAt)
	return err
}

func (s *Store) ListRollouts(ctx context.Context) ([]store.Rollout, error) {
	rows, err := s.pool.Query(ctx, `SELECT data FROM rollouts ORDER BY feature`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Rollout
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		var r store.Rollout
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRollout(ctx context.Context, feature string) (store.Rollout, error) {
	var b []byte
	if err := s.pool.QueryRow(ctx, `SELECT data FROM rollouts WHERE feature = $1`, feature).Scan(&b); err != nil {
		return store.Rollout{}, mapErr(err)
	}
	var r store.Rollout
	return r, json.Unmarshal(b, &r)
}

func (s *Store) PutRollout(ctx context.Context, r store.Rollout) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO rollouts (feature, data, updated_at) VALUES ($1, $2, $3)
		ON CONFLICT (feature) DO UPDATE SET data = $2, updated_at = $3`, r.Feature, b, r.UpdatedAt)
	return err
}

func (s *Store) DeleteRollout(ctx context.Context, feature string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM rollouts WHERE feature = $1`, feature)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}
