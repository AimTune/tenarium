package memory

import (
	"cmp"
	"context"
	"slices"

	"github.com/AimTune/tenarium/internal/store"
)

func roleKey(tenantID, name string) string { return tenantID + "\x00" + name }

func cloneRole(r store.TenantRole) store.TenantRole {
	r.Actions = slices.Clone(r.Actions)
	return r
}

func cloneGroup(g store.Group) store.Group {
	g.Roles, g.Members = slices.Clone(g.Roles), slices.Clone(g.Members)
	return g
}

func (s *Store) GetTenantRole(_ context.Context, tenantID, name string) (store.TenantRole, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[roleKey(tenantID, name)]
	if !ok {
		return store.TenantRole{}, store.ErrNotFound
	}
	return cloneRole(r), nil
}

func (s *Store) ListTenantRoles(_ context.Context, tenantID string) ([]store.TenantRole, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.TenantRole
	for _, r := range s.roles {
		if r.TenantID == tenantID {
			out = append(out, cloneRole(r))
		}
	}
	slices.SortFunc(out, func(a, b store.TenantRole) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}

func (s *Store) GetGroup(_ context.Context, tenantID, id string) (store.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[id]
	if !ok || g.TenantID != tenantID {
		return store.Group{}, store.ErrNotFound
	}
	return cloneGroup(g), nil
}

func (s *Store) ListGroups(_ context.Context, tenantID string) ([]store.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.Group
	for _, g := range s.groups {
		if g.TenantID == tenantID {
			out = append(out, cloneGroup(g))
		}
	}
	slices.SortFunc(out, func(a, b store.Group) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}

func (t *tx) PutTenantRole(_ context.Context, r store.TenantRole) error {
	t.roles[roleKey(r.TenantID, r.Name)] = cloneRole(r)
	return nil
}

func (t *tx) DeleteTenantRole(_ context.Context, tenantID, name string) error {
	k := roleKey(tenantID, name)
	if _, ok := t.roles[k]; !ok {
		return store.ErrNotFound
	}
	delete(t.roles, k)
	return nil
}

func (t *tx) CreateGroup(_ context.Context, g store.Group) error {
	for _, o := range t.groups {
		if o.ID == g.ID || (o.TenantID == g.TenantID && o.Name == g.Name) {
			return store.ErrAlreadyExists
		}
	}
	t.groups[g.ID] = cloneGroup(g)
	return nil
}

func (t *tx) UpdateGroup(_ context.Context, g store.Group) error {
	old, ok := t.groups[g.ID]
	if !ok || old.TenantID != g.TenantID {
		return store.ErrNotFound
	}
	for _, o := range t.groups {
		if o.ID != g.ID && o.TenantID == g.TenantID && o.Name == g.Name {
			return store.ErrAlreadyExists
		}
	}
	t.groups[g.ID] = cloneGroup(g)
	return nil
}

func (t *tx) DeleteGroup(_ context.Context, tenantID, id string) error {
	g, ok := t.groups[id]
	if !ok || g.TenantID != tenantID {
		return store.ErrNotFound
	}
	delete(t.groups, id)
	return nil
}
