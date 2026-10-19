package scim

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// A SCIM Group is either a member role (built-in or custom: its members
// hold the role; removing someone returns them to the default role) or,
// for any other name, a tenant group (team) whose roles its members get.

// target is the Tenarium object behind a SCIM group.
type target struct {
	role  string
	group *store.Group
}

func (g target) id() string {
	if g.group != nil {
		return g.group.ID
	}
	return g.role
}

func (g target) name() string {
	if g.group != nil {
		return g.group.Name
	}
	return g.role
}

func (h *Handler) roleNamed(r *http.Request, t sdk.Tenant, name string) string {
	names, _ := h.Tenants.TenantRoleNames(r.Context(), t.ID)
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return n
		}
	}
	return ""
}

// resolve finds the group for a path ID (role name or group ID).
func (h *Handler) resolve(r *http.Request, t sdk.Tenant, id string) (target, error) {
	if role := h.roleNamed(r, t, id); role != "" {
		return target{role: role}, nil
	}
	g, err := h.Tenants.FindGroup(r.Context(), t.ID, id)
	if err != nil {
		return target{}, &Error{Status: http.StatusNotFound, Detail: "no such group"}
	}
	return target{group: &g}, nil
}

func (h *Handler) groupResource(r *http.Request, t sdk.Tenant, g target, ms []sdk.Member) map[string]any {
	members := []map[string]string{}
	for _, m := range ms {
		in := m.Role == g.role
		if g.group != nil {
			in = slices.Contains(g.group.Members, m.ID)
		}
		if in {
			members = append(members, map[string]string{"value": m.ID, "display": m.Email, "$ref": base(r, t) + "/Users/" + m.ID})
		}
	}
	return map[string]any{
		"schemas": []string{schemaGroup}, "id": g.id(), "displayName": g.name(), "members": members,
		"meta": map[string]string{"resourceType": "Group", "location": base(r, t) + "/Groups/" + g.id()},
	}
}

func (h *Handler) targets(r *http.Request, t sdk.Tenant) ([]target, error) {
	names, err := h.Tenants.TenantRoleNames(r.Context(), t.ID)
	if err != nil {
		return nil, err
	}
	var out []target
	for _, n := range names {
		out = append(out, target{role: n})
	}
	gs, err := h.Tenants.ListGroups(r.Context(), t.ID)
	if err != nil {
		return nil, err
	}
	for i := range gs {
		out = append(out, target{group: &gs[i]})
	}
	return out, nil
}

func (h *Handler) ListGroups(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	attr, value, err := filter(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	all, err := h.targets(r, t)
	if err != nil {
		WriteError(w, err)
		return
	}
	switch attr {
	case "":
	case "displayname":
		all = slices.DeleteFunc(all, func(g target) bool { return !strings.EqualFold(g.name(), value) })
	case "id":
		all = slices.DeleteFunc(all, func(g target) bool { return g.id() != value })
	case "externalid":
		all = nil
	default:
		WriteError(w, badRequest("invalidFilter", "cannot filter groups by %s", attr))
		return
	}
	ms, err := h.Tenants.ListMembers(r.Context(), t.ID)
	if err != nil {
		WriteError(w, err)
		return
	}
	pg, start, err := page(r, all)
	if err != nil {
		WriteError(w, err)
		return
	}
	items := make([]any, len(pg))
	for i, g := range pg {
		res := h.groupResource(r, t, g, ms)
		if strings.Contains(r.URL.Query().Get("excludedAttributes"), "members") {
			delete(res, "members")
		}
		items[i] = res
	}
	write(w, http.StatusOK, listResponse(items, start, len(all)))
}

func (h *Handler) GetGroup(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	g, err := h.resolve(r, t, r.PathValue("group"))
	if err != nil {
		WriteError(w, err)
		return
	}
	h.writeGroup(w, r, t, g, http.StatusOK)
}

func (h *Handler) writeGroup(w http.ResponseWriter, r *http.Request, t sdk.Tenant, g target, status int) {
	if g.group != nil { // reload after changes
		fresh, err := h.Tenants.FindGroup(r.Context(), t.ID, g.group.ID)
		if err != nil {
			WriteError(w, err)
			return
		}
		g.group = &fresh
	}
	ms, err := h.Tenants.ListMembers(r.Context(), t.ID)
	if err != nil {
		WriteError(w, err)
		return
	}
	write(w, status, h.groupResource(r, t, g, ms))
}

type groupIn struct {
	DisplayName string    `json:"displayName"`
	Members     []valueIn `json:"members"`
}

func ids(vs []valueIn) map[string]bool {
	out := map[string]bool{}
	for _, v := range vs {
		out[v.Value] = true
	}
	return out
}

// CreateGroup pushes a group: a role name, or a tenant group (created if
// missing). Listed members join it.
func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	var in groupIn
	if err := decode(r, &in); err != nil {
		WriteError(w, err)
		return
	}
	if strings.TrimSpace(in.DisplayName) == "" {
		WriteError(w, badRequest("invalidValue", "displayName is required"))
		return
	}
	g, err := h.resolve(r, t, in.DisplayName)
	if err != nil {
		created, cerr := h.Tenants.CreateGroup(r.Context(), t.ID, tenant.GroupInput{Name: &in.DisplayName})
		if cerr != nil {
			WriteError(w, cerr)
			return
		}
		g = target{group: &created}
	}
	for id := range ids(in.Members) {
		if err := h.add(r, t, g, id); err != nil {
			WriteError(w, err)
			return
		}
	}
	w.Header().Set("Location", base(r, t)+"/Groups/"+g.id())
	h.writeGroup(w, r, t, g, http.StatusCreated)
}

// ReplaceGroup makes exactly the listed members belong to the group.
func (h *Handler) ReplaceGroup(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	var in groupIn
	if err := decode(r, &in); err != nil {
		WriteError(w, err)
		return
	}
	g, err := h.resolve(r, t, r.PathValue("group"))
	if err != nil {
		WriteError(w, err)
		return
	}
	if err := h.sync(r, t, g, ids(in.Members)); err != nil {
		WriteError(w, err)
		return
	}
	h.writeGroup(w, r, t, g, http.StatusOK)
}

func (h *Handler) PatchGroup(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	var req patchRequest
	if err := decode(r, &req); err != nil {
		WriteError(w, err)
		return
	}
	g, err := h.resolve(r, t, r.PathValue("group"))
	if err != nil {
		WriteError(w, err)
		return
	}
	for _, op := range req.Operations {
		if err := h.patchGroup(r, t, g, op); err != nil {
			WriteError(w, err)
			return
		}
	}
	h.writeGroup(w, r, t, g, http.StatusOK)
}

func (h *Handler) patchGroup(r *http.Request, t sdk.Tenant, g target, op patchOp) error {
	path := strings.ToLower(op.Path)
	var members []valueIn
	switch {
	case path == "members":
		if len(op.Value) > 0 {
			if err := json.Unmarshal(op.Value, &members); err != nil {
				return badRequest("invalidValue", "members must be a list")
			}
		}
	case path == "" && strings.EqualFold(op.Op, "add"):
		var v groupIn
		_ = json.Unmarshal(op.Value, &v)
		members = v.Members
	case strings.HasPrefix(path, "members[value eq "):
		id := strings.TrimSuffix(strings.TrimPrefix(op.Path[len("members[value eq "):], `"`), `"]`)
		members = []valueIn{{Value: id}}
	case path == "displayname" || path == "externalid" || path == "":
		return nil // renames are not synced; the name identifies the role or group
	default:
		return badRequest("invalidPath", "unsupported path %q", op.Path)
	}
	switch strings.ToLower(op.Op) {
	case "add":
		for id := range ids(members) {
			if err := h.add(r, t, g, id); err != nil {
				return err
			}
		}
	case "remove":
		if len(members) == 0 && path == "members" {
			return h.sync(r, t, g, map[string]bool{})
		}
		for id := range ids(members) {
			if err := h.remove(r, t, g, id); err != nil {
				return err
			}
		}
	case "replace":
		return h.sync(r, t, g, ids(members))
	default:
		return badRequest("invalidSyntax", "unknown op %q", op.Op)
	}
	return nil
}

// DeleteGroup removes a tenant group, or returns every holder of a role to
// the default role.
func (h *Handler) DeleteGroup(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	g, err := h.resolve(r, t, r.PathValue("group"))
	if err != nil {
		WriteError(w, err)
		return
	}
	if g.group != nil {
		err = h.Tenants.DeleteGroup(r.Context(), t.ID, g.group.ID)
	} else {
		err = h.sync(r, t, g, map[string]bool{})
	}
	if err != nil {
		WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// sync makes exactly want belong to the group.
func (h *Handler) sync(r *http.Request, t sdk.Tenant, g target, want map[string]bool) error {
	ms, err := h.Tenants.ListMembers(r.Context(), t.ID)
	if err != nil {
		return err
	}
	for id := range want {
		if !slices.ContainsFunc(ms, func(m sdk.Member) bool { return m.ID == id }) {
			return badRequest("invalidValue", "unknown member %s", id)
		}
	}
	if g.group != nil {
		var list []string
		for id := range want {
			list = append(list, id)
		}
		slices.Sort(list)
		_, err := h.Tenants.SetGroupMembers(r.Context(), t.ID, g.group.ID, list)
		return err
	}
	for _, m := range ms {
		switch {
		case want[m.ID] && m.Role != g.role:
			err = h.add(r, t, g, m.ID)
		case !want[m.ID] && m.Role == g.role:
			err = h.remove(r, t, g, m.ID)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) add(r *http.Request, t sdk.Tenant, g target, memberID string) error {
	if g.group != nil {
		_, err := h.Tenants.SetGroupMembership(r.Context(), t.ID, g.group.ID, memberID, true)
		return memberErr(err, memberID)
	}
	role := g.role
	_, err := h.Tenants.UpdateMember(r.Context(), t.ID, memberID, tenant.MemberUpdate{Role: &role})
	return memberErr(err, memberID)
}

func (h *Handler) remove(r *http.Request, t sdk.Tenant, g target, memberID string) error {
	if g.group != nil {
		_, err := h.Tenants.SetGroupMembership(r.Context(), t.ID, g.group.ID, memberID, false)
		return memberErr(err, memberID)
	}
	m, err := h.Tenants.GetMember(r.Context(), t.ID, memberID)
	if err != nil || m.Role != g.role {
		return memberErr(err, memberID)
	}
	def := h.Tenants.DefaultMemberRole()
	if def == g.role {
		return nil // already the default; nothing lower to fall back to
	}
	_, err = h.Tenants.UpdateMember(r.Context(), t.ID, memberID, tenant.MemberUpdate{Role: &def})
	return err
}

func memberErr(err error, id string) error {
	if errors.Is(err, store.ErrNotFound) {
		return badRequest("invalidValue", "unknown member %s", id)
	}
	return err
}
