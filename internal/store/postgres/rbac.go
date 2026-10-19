package postgres

import (
	"context"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/jackc/pgx/v5"
)

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

const roleCols = `tenant_id::text, name, description, actions, created_at, updated_at`

func scanRole(row pgx.Row) (store.TenantRole, error) {
	var r store.TenantRole
	if err := row.Scan(&r.TenantID, &r.Name, &r.Description, &r.Actions, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return store.TenantRole{}, mapErr(err)
	}
	r.CreatedAt, r.UpdatedAt = r.CreatedAt.UTC(), r.UpdatedAt.UTC()
	return r, nil
}

func (s *Store) GetTenantRole(ctx context.Context, tenantID, name string) (store.TenantRole, error) {
	if !isUUID(tenantID) {
		return store.TenantRole{}, store.ErrNotFound
	}
	return scanRole(s.pool.QueryRow(ctx, `SELECT `+roleCols+` FROM tenant_roles WHERE tenant_id = $1 AND name = $2`, tenantID, name))
}

func (s *Store) ListTenantRoles(ctx context.Context, tenantID string) ([]store.TenantRole, error) {
	if !isUUID(tenantID) {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+roleCols+` FROM tenant_roles WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.TenantRole
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

const groupCols = `id::text, tenant_id::text, name, description, roles, members, created_at, updated_at`

func scanGroup(row pgx.Row) (store.Group, error) {
	var g store.Group
	if err := row.Scan(&g.ID, &g.TenantID, &g.Name, &g.Description, &g.Roles, &g.Members, &g.CreatedAt, &g.UpdatedAt); err != nil {
		return store.Group{}, mapErr(err)
	}
	g.CreatedAt, g.UpdatedAt = g.CreatedAt.UTC(), g.UpdatedAt.UTC()
	return g, nil
}

func (s *Store) GetGroup(ctx context.Context, tenantID, id string) (store.Group, error) {
	if !isUUID(tenantID) || !isUUID(id) {
		return store.Group{}, store.ErrNotFound
	}
	return scanGroup(s.pool.QueryRow(ctx, `SELECT `+groupCols+` FROM tenant_groups WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *Store) ListGroups(ctx context.Context, tenantID string) ([]store.Group, error) {
	if !isUUID(tenantID) {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+groupCols+` FROM tenant_groups WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (t *tx) PutTenantRole(ctx context.Context, r store.TenantRole) error {
	_, err := t.q.Exec(ctx, `INSERT INTO tenant_roles (tenant_id, name, description, actions, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, name) DO UPDATE SET description = $3, actions = $4, updated_at = $6`,
		r.TenantID, r.Name, r.Description, nonNilStrings(r.Actions), r.CreatedAt, r.UpdatedAt)
	return mapErr(err)
}

func (t *tx) DeleteTenantRole(ctx context.Context, tenantID, name string) error {
	if !isUUID(tenantID) {
		return store.ErrNotFound
	}
	tag, err := t.q.Exec(ctx, `DELETE FROM tenant_roles WHERE tenant_id = $1 AND name = $2`, tenantID, name)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (t *tx) CreateGroup(ctx context.Context, g store.Group) error {
	_, err := t.q.Exec(ctx, `INSERT INTO tenant_groups (id, tenant_id, name, description, roles, members, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		g.ID, g.TenantID, g.Name, g.Description, nonNilStrings(g.Roles), nonNilStrings(g.Members), g.CreatedAt, g.UpdatedAt)
	return mapErr(err)
}

func (t *tx) UpdateGroup(ctx context.Context, g store.Group) error {
	if !isUUID(g.ID) {
		return store.ErrNotFound
	}
	tag, err := t.q.Exec(ctx, `UPDATE tenant_groups SET name = $3, description = $4, roles = $5, members = $6, updated_at = $7
		WHERE tenant_id = $1 AND id = $2`,
		g.TenantID, g.ID, g.Name, g.Description, nonNilStrings(g.Roles), nonNilStrings(g.Members), g.UpdatedAt)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (t *tx) DeleteGroup(ctx context.Context, tenantID, id string) error {
	if !isUUID(tenantID) || !isUUID(id) {
		return store.ErrNotFound
	}
	tag, err := t.q.Exec(ctx, `DELETE FROM tenant_groups WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}
