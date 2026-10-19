package postgres

import (
	"context"
	"encoding/json"

	"github.com/AimTune/tenarium/internal/store"
)

func (s *Store) ListTenantTemplates(ctx context.Context) ([]store.TenantTemplate, error) {
	rows, err := s.pool.Query(ctx, `SELECT data FROM tenant_templates ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.TenantTemplate
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		var t store.TenantTemplate
		if err := json.Unmarshal(b, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetTenantTemplate(ctx context.Context, id string) (store.TenantTemplate, error) {
	var b []byte
	if err := s.pool.QueryRow(ctx, `SELECT data FROM tenant_templates WHERE id = $1`, id).Scan(&b); err != nil {
		return store.TenantTemplate{}, mapErr(err)
	}
	var t store.TenantTemplate
	return t, json.Unmarshal(b, &t)
}

func (s *Store) PutTenantTemplate(ctx context.Context, t store.TenantTemplate) error {
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO tenant_templates (id, data, updated_at) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET data = $2, updated_at = $3`, t.ID, b, t.UpdatedAt)
	return err
}

func (s *Store) DeleteTenantTemplate(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM tenant_templates WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}
