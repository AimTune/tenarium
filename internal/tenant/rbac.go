package tenant

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// Role and group event types.
const (
	EventRoleUpdated  = "role.updated"
	EventRoleDeleted  = "role.deleted"
	EventGroupCreated = "group.created"
	EventGroupUpdated = "group.updated"
	EventGroupDeleted = "group.deleted"
)

// TenantRoleNames lists the roles usable in a tenant: the built-in member
// roles followed by the tenant's custom roles.
func (s *Service) TenantRoleNames(ctx context.Context, tenantID string) ([]string, error) {
	names := slices.Clone(s.memberRoles)
	custom, err := s.store.ListTenantRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, r := range custom {
		names = append(names, r.Name)
	}
	return names, nil
}

// checkRole validates that role exists in the tenant.
func (s *Service) checkRole(ctx context.Context, tenantID, field, role string) error {
	if s.roleAllowed(role) {
		return nil
	}
	if _, err := s.store.GetTenantRole(ctx, tenantID, role); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	names, _ := s.TenantRoleNames(ctx, tenantID)
	return invalid(field, "must be one of %v", names)
}

// RoleActions returns the action patterns of a tenant's custom role.
func (s *Service) RoleActions(ctx context.Context, tenantID, role string) ([]string, bool) {
	r, err := s.store.GetTenantRole(ctx, tenantID, role)
	if err != nil {
		return nil, false
	}
	return r.Actions, true
}

// ExpandActions returns the built-in actions matched by patterns, or an
// error naming a pattern that matches none.
func ExpandActions(patterns []string) ([]sdk.Action, error) {
	var out []sdk.Action
	for _, p := range patterns {
		matched := false
		for _, a := range sdk.Actions() {
			if ok, err := path.Match(p, string(a)); err != nil {
				return nil, invalid("actions", "invalid pattern %q", p)
			} else if ok {
				matched = true
				if !slices.Contains(out, a) {
					out = append(out, a)
				}
			}
		}
		if !matched {
			return nil, invalid("actions", "%q matches no action", p)
		}
	}
	return out, nil
}

// RoleInput defines a custom role.
type RoleInput struct {
	Description string   `json:"description,omitempty"`
	Actions     []string `json:"actions"`
}

// PutRole creates or replaces a custom role. The caller must already have
// checked that it may grant every action the role covers.
func (s *Service) PutRole(ctx context.Context, tenantRef, name string, in RoleInput) (store.TenantRole, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return store.TenantRole{}, err
	}
	switch {
	case !keyRe.MatchString(name):
		return store.TenantRole{}, invalid("name", "must be a lowercase identifier")
	case s.roleAllowed(name):
		return store.TenantRole{}, invalid("name", "%q is a built-in role", name)
	case len(in.Actions) == 0 || len(in.Actions) > 100:
		return store.TenantRole{}, invalid("actions", "between 1 and 100 patterns are required")
	case len(in.Description) > 500:
		return store.TenantRole{}, invalid("description", "too long")
	}
	if _, err := ExpandActions(in.Actions); err != nil {
		return store.TenantRole{}, err
	}
	now := s.now()
	r := store.TenantRole{TenantID: t.ID, Name: name, Description: in.Description, Actions: slices.Clone(in.Actions), CreatedAt: now, UpdatedAt: now}
	if prev, err := s.store.GetTenantRole(ctx, t.ID, name); err == nil {
		r.CreatedAt = prev.CreatedAt
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.PutTenantRole(ctx, r); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, EventRoleUpdated, t.ID, "tenants/"+t.ID+"/roles/"+name, r)
	})
	if err != nil {
		return store.TenantRole{}, err
	}
	s.notify()
	return r, nil
}

func (s *Service) ListRoles(ctx context.Context, tenantRef string) ([]store.TenantRole, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return nil, err
	}
	return s.store.ListTenantRoles(ctx, t.ID)
}

func (s *Service) GetRole(ctx context.Context, tenantRef, name string) (store.TenantRole, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return store.TenantRole{}, err
	}
	return s.store.GetTenantRole(ctx, t.ID, name)
}

// DeleteRole removes a custom role that no member, group or API key uses.
func (s *Service) DeleteRole(ctx context.Context, tenantRef, name string) error {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return err
	}
	r, err := s.store.GetTenantRole(ctx, t.ID, name)
	if err != nil {
		return err
	}
	if use, err := s.roleInUse(ctx, t.ID, name); err != nil {
		return err
	} else if use != "" {
		return stateErr("role %s is still used by %s", name, use)
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.DeleteTenantRole(ctx, t.ID, name); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, EventRoleDeleted, t.ID, "tenants/"+t.ID+"/roles/"+name, r)
	})
	if err != nil {
		return err
	}
	s.notify()
	return nil
}

func (s *Service) roleInUse(ctx context.Context, tenantID, role string) (string, error) {
	ms, err := s.store.ListMembers(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if i := slices.IndexFunc(ms, func(m sdk.Member) bool { return m.Role == role }); i >= 0 {
		return "member " + ms[i].Email, nil
	}
	gs, err := s.store.ListGroups(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if i := slices.IndexFunc(gs, func(g store.Group) bool { return slices.Contains(g.Roles, role) }); i >= 0 {
		return "group " + gs[i].Name, nil
	}
	keys, err := s.store.ListAPIKeys(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if i := slices.IndexFunc(keys, func(k store.APIKey) bool { return k.RevokedAt == nil && slices.Contains(k.Roles, role) }); i >= 0 {
		return "API key " + keys[i].Name, nil
	}
	return "", nil
}

// GroupInput creates or updates a group; nil fields are unchanged.
type GroupInput struct {
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	Roles       *[]string `json:"roles,omitempty"`
}

func (s *Service) applyGroup(ctx context.Context, g *store.Group, in GroupInput) error {
	if in.Name != nil {
		g.Name = strings.TrimSpace(*in.Name)
	}
	if in.Description != nil {
		g.Description = *in.Description
	}
	if in.Roles != nil {
		g.Roles = nil
		for _, r := range *in.Roles {
			if err := s.checkRole(ctx, g.TenantID, "roles", r); err != nil {
				return err
			}
			if !slices.Contains(g.Roles, r) {
				g.Roles = append(g.Roles, r)
			}
		}
	}
	switch {
	case g.Name == "" || len(g.Name) > 200:
		return invalid("name", "must be 1-200 characters")
	case len(g.Description) > 500:
		return invalid("description", "too long")
	}
	return nil
}

func (s *Service) CreateGroup(ctx context.Context, tenantRef string, in GroupInput) (store.Group, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return store.Group{}, err
	}
	if !t.IsLive() {
		return store.Group{}, transitionErr("add groups to", t.Status)
	}
	now := s.now()
	g := store.Group{ID: uuid.Must(uuid.NewV7()).String(), TenantID: t.ID, CreatedAt: now, UpdatedAt: now}
	if err := s.applyGroup(ctx, &g, in); err != nil {
		return store.Group{}, err
	}
	return g, s.writeGroup(ctx, EventGroupCreated, g, func(tx store.Tx) error { return tx.CreateGroup(ctx, g) })
}

func (s *Service) writeGroup(ctx context.Context, typ string, g store.Group, fn func(tx store.Tx) error) error {
	err := s.store.InTx(ctx, func(tx store.Tx) error {
		if err := fn(tx); err != nil {
			if errors.Is(err, store.ErrAlreadyExists) {
				return fmt.Errorf("group %q: %w", g.Name, err)
			}
			return err
		}
		return s.appendEvent(ctx, tx, typ, g.TenantID, "tenants/"+g.TenantID+"/groups/"+g.ID, g)
	})
	if err == nil {
		s.notify()
	}
	return err
}

func (s *Service) ListGroups(ctx context.Context, tenantRef string) ([]store.Group, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return nil, err
	}
	return s.store.ListGroups(ctx, t.ID)
}

// FindGroup returns a tenant's group by ID or name.
func (s *Service) FindGroup(ctx context.Context, tenantRef, idOrName string) (store.Group, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return store.Group{}, err
	}
	if g, err := s.store.GetGroup(ctx, t.ID, idOrName); err == nil {
		return g, nil
	}
	gs, err := s.store.ListGroups(ctx, t.ID)
	if err != nil {
		return store.Group{}, err
	}
	if i := slices.IndexFunc(gs, func(g store.Group) bool { return strings.EqualFold(g.Name, idOrName) }); i >= 0 {
		return gs[i], nil
	}
	return store.Group{}, store.ErrNotFound
}

func (s *Service) UpdateGroup(ctx context.Context, tenantRef, id string, in GroupInput) (store.Group, error) {
	g, err := s.FindGroup(ctx, tenantRef, id)
	if err != nil {
		return g, err
	}
	if err := s.applyGroup(ctx, &g, in); err != nil {
		return store.Group{}, err
	}
	g.UpdatedAt = s.now()
	return g, s.writeGroup(ctx, EventGroupUpdated, g, func(tx store.Tx) error { return tx.UpdateGroup(ctx, g) })
}

func (s *Service) DeleteGroup(ctx context.Context, tenantRef, id string) error {
	g, err := s.FindGroup(ctx, tenantRef, id)
	if err != nil {
		return err
	}
	return s.writeGroup(ctx, EventGroupDeleted, g, func(tx store.Tx) error { return tx.DeleteGroup(ctx, g.TenantID, g.ID) })
}

// SetGroupMembership adds (in=true) or removes a member from a group.
func (s *Service) SetGroupMembership(ctx context.Context, tenantRef, groupID, memberID string, in bool) (store.Group, error) {
	g, err := s.FindGroup(ctx, tenantRef, groupID)
	if err != nil {
		return g, err
	}
	if _, err := s.store.GetMember(ctx, g.TenantID, memberID); err != nil {
		return g, err
	}
	has := slices.Contains(g.Members, memberID)
	switch {
	case in && !has:
		g.Members = append(g.Members, memberID)
	case !in && has:
		g.Members = slices.DeleteFunc(g.Members, func(id string) bool { return id == memberID })
	default:
		return g, nil
	}
	g.UpdatedAt = s.now()
	return g, s.writeGroup(ctx, EventGroupUpdated, g, func(tx store.Tx) error { return tx.UpdateGroup(ctx, g) })
}

// SetGroupMembers replaces a group's members.
func (s *Service) SetGroupMembers(ctx context.Context, tenantRef, groupID string, memberIDs []string) (store.Group, error) {
	g, err := s.FindGroup(ctx, tenantRef, groupID)
	if err != nil {
		return g, err
	}
	var ids []string
	for _, id := range memberIDs {
		if _, err := s.store.GetMember(ctx, g.TenantID, id); err != nil {
			return g, invalid("members", "unknown member %s", id)
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	g.Members, g.UpdatedAt = ids, s.now()
	return g, s.writeGroup(ctx, EventGroupUpdated, g, func(tx store.Tx) error { return tx.UpdateGroup(ctx, g) })
}

// EffectiveRoles are a member's role plus the roles of its groups.
func (s *Service) EffectiveRoles(ctx context.Context, m sdk.Member) []string {
	roles := []string{m.Role}
	gs, err := s.store.ListGroups(ctx, m.TenantID)
	if err != nil {
		return roles
	}
	for _, g := range gs {
		if slices.Contains(g.Members, m.ID) {
			for _, r := range g.Roles {
				if !slices.Contains(roles, r) {
					roles = append(roles, r)
				}
			}
		}
	}
	return roles
}

// removeFromGroups drops a removed member from its groups, inside tx. The
// groups are read before the transaction (store reads inside one would
// deadlock the memory store).
func (s *Service) removeFromGroups(ctx context.Context, tx store.Tx, m sdk.Member, gs []store.Group) error {
	for _, g := range gs {
		if !slices.Contains(g.Members, m.ID) {
			continue
		}
		g.Members = slices.DeleteFunc(g.Members, func(id string) bool { return id == m.ID })
		g.UpdatedAt = s.now()
		if err := tx.UpdateGroup(ctx, g); err != nil {
			return err
		}
	}
	return nil
}
