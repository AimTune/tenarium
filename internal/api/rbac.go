package api

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func (s *Server) listActions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": sdk.Actions()})
}

// roleView describes a built-in or custom role.
type roleView struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Actions     []string `json:"actions"`
	BuiltIn     bool     `json:"built_in"`
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionRolesRead)
	if !ok {
		return
	}
	var out []roleView
	table := s.Authz.TenantRoleTable()
	for _, name := range s.Tenants.MemberRoles() {
		out = append(out, roleView{Name: name, Actions: table[name], BuiltIn: true})
	}
	custom, err := s.Tenants.ListRoles(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	for _, c := range custom {
		out = append(out, roleView{Name: c.Name, Description: c.Description, Actions: c.Actions})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) getRole(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionRolesRead)
	if !ok {
		return
	}
	name := r.PathValue("role")
	if slices.Contains(s.Tenants.MemberRoles(), name) {
		writeJSON(w, http.StatusOK, roleView{Name: name, Actions: s.Authz.TenantRoleTable()[name], BuiltIn: true})
		return
	}
	role, err := s.Tenants.GetRole(r.Context(), t.ID, name)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, roleView{Name: role.Name, Description: role.Description, Actions: role.Actions})
}

// canGrant checks that the caller holds every action the patterns cover on
// the tenant, so nobody can create a role (or group) more powerful than
// themselves.
func (s *Server) canGrant(w http.ResponseWriter, r *http.Request, t sdk.Tenant, patterns []string) bool {
	actions, err := tenant.ExpandActions(patterns)
	if err != nil {
		s.writeErr(w, r, err)
		return false
	}
	p, _ := sdk.PrincipalFrom(r.Context())
	for _, a := range actions {
		if err := s.Authz.Authorize(r.Context(), p, a, tenantResource(t)); err != nil {
			writeError(w, http.StatusForbidden, "forbidden", fmt.Sprintf("cannot grant %s: the caller does not hold it", a), "actions")
			return false
		}
	}
	return true
}

// rolePatterns returns the patterns of built-in or custom roles.
func (s *Server) rolePatterns(r *http.Request, t sdk.Tenant, roles []string) []string {
	var out []string
	table := s.Authz.TenantRoleTable()
	for _, name := range roles {
		if p, ok := table[name]; ok {
			out = append(out, p...)
		} else if p, ok := s.Tenants.RoleActions(r.Context(), t.ID, name); ok {
			out = append(out, p...)
		}
	}
	return out
}

func (s *Server) putRole(w http.ResponseWriter, r *http.Request) {
	var in tenant.RoleInput
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionRolesWrite)
	if !ok || !s.canGrant(w, r, t, in.Actions) {
		return
	}
	role, err := s.Tenants.PutRole(r.Context(), t.ID, r.PathValue("role"), in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, roleView{Name: role.Name, Description: role.Description, Actions: role.Actions})
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionRolesWrite)
	if !ok {
		return
	}
	if err := s.Tenants.DeleteRole(r.Context(), t.ID, r.PathValue("role")); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionGroupsRead)
	if !ok {
		return
	}
	gs, err := s.Tenants.ListGroups(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(gs)})
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var in tenant.GroupInput
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionGroupsWrite)
	if !ok {
		return
	}
	if in.Roles != nil && !s.canGrant(w, r, t, s.rolePatterns(r, t, *in.Roles)) {
		return
	}
	g, err := s.Tenants.CreateGroup(r.Context(), t.ID, in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionGroupsRead)
	if !ok {
		return
	}
	g, err := s.Tenants.FindGroup(r.Context(), t.ID, r.PathValue("group"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	var in tenant.GroupInput
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionGroupsWrite)
	if !ok {
		return
	}
	if in.Roles != nil && !s.canGrant(w, r, t, s.rolePatterns(r, t, *in.Roles)) {
		return
	}
	g, err := s.Tenants.UpdateGroup(r.Context(), t.ID, r.PathValue("group"), in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionGroupsWrite)
	if !ok {
		return
	}
	if err := s.Tenants.DeleteGroup(r.Context(), t.ID, r.PathValue("group")); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// groupMember adds (PUT) or removes (DELETE) a member. Adding someone to a
// group grants its roles, so the caller must hold them too.
func (s *Server) groupMember(in bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, ok := s.loadTenant(w, r, sdk.ActionGroupsWrite)
		if !ok {
			return
		}
		if in {
			g, err := s.Tenants.FindGroup(r.Context(), t.ID, r.PathValue("group"))
			if err != nil {
				s.writeErr(w, r, err)
				return
			}
			if !s.canGrant(w, r, t, s.rolePatterns(r, t, g.Roles)) {
				return
			}
		}
		g, err := s.Tenants.SetGroupMembership(r.Context(), t.ID, r.PathValue("group"), r.PathValue("member"), in)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, g)
	}
}

func (s *Server) tenantRoleNames(r *http.Request, tenantID string) []string {
	names, err := s.Tenants.TenantRoleNames(r.Context(), tenantID)
	if err != nil {
		return s.Tenants.MemberRoles()
	}
	return names
}
