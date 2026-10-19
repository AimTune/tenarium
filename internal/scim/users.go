package scim

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// userIn is the subset of the SCIM User schema Tenarium uses.
type userIn struct {
	UserName    string    `json:"userName"`
	DisplayName string    `json:"displayName"`
	Name        *nameIn   `json:"name"`
	Emails      []emailIn `json:"emails"`
	Active      *bool     `json:"active"`
	Roles       []valueIn `json:"roles"`
}

type nameIn struct {
	Formatted  string `json:"formatted"`
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

type emailIn struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

type valueIn struct {
	Value string `json:"value"`
}

func (u userIn) email() string {
	for _, e := range u.Emails {
		if e.Primary && e.Value != "" {
			return e.Value
		}
	}
	if strings.Contains(u.UserName, "@") || len(u.Emails) == 0 {
		return u.UserName
	}
	return u.Emails[0].Value
}

func (u userIn) fullName() string {
	if u.Name != nil {
		if u.Name.Formatted != "" {
			return u.Name.Formatted
		}
		if n := strings.TrimSpace(u.Name.GivenName + " " + u.Name.FamilyName); n != "" {
			return n
		}
	}
	return u.DisplayName
}

func (u userIn) role() string {
	if len(u.Roles) > 0 {
		return u.Roles[0].Value
	}
	return ""
}

func (h *Handler) userResource(r *http.Request, t sdk.Tenant, m sdk.Member) map[string]any {
	u := h.Tenants.MemberUser(r.Context(), m)
	res := map[string]any{
		"schemas":  []string{schemaUser},
		"id":       m.ID,
		"userName": m.Email,
		"active":   m.Status != sdk.MemberSuspended,
		"emails":   []map[string]any{{"value": m.Email, "primary": true, "type": "work"}},
		"roles":    []map[string]any{{"value": m.Role, "primary": true}},
		"meta":     meta("User", base(r, t)+"/Users/"+m.ID, m.CreatedAt, m.UpdatedAt, m.Version),
	}
	if u.Name != "" {
		res["displayName"] = u.Name
		res["name"] = map[string]string{"formatted": u.Name}
	}
	return res
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	attr, value, err := filter(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	ms, err := h.Tenants.ListMembers(r.Context(), t.ID)
	if err != nil {
		WriteError(w, err)
		return
	}
	switch attr {
	case "":
	case "username", "emails.value", "emails":
		ms = slices.DeleteFunc(ms, func(m sdk.Member) bool { return !strings.EqualFold(m.Email, value) })
	case "id":
		ms = slices.DeleteFunc(ms, func(m sdk.Member) bool { return m.ID != value })
	case "externalid":
		ms = nil // not stored; identity providers then match by userName
	default:
		WriteError(w, badRequest("invalidFilter", "cannot filter users by %s", attr))
		return
	}
	pg, start, err := page(r, ms)
	if err != nil {
		WriteError(w, err)
		return
	}
	items := make([]any, len(pg))
	for i, m := range pg {
		items[i] = h.userResource(r, t, m)
	}
	write(w, http.StatusOK, listResponse(items, start, len(ms)))
}

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	m, err := h.Tenants.GetMember(r.Context(), t.ID, r.PathValue("user"))
	if err != nil {
		WriteError(w, err)
		return
	}
	write(w, http.StatusOK, h.userResource(r, t, m))
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	var in userIn
	if err := decode(r, &in); err != nil {
		WriteError(w, err)
		return
	}
	email := in.email()
	if email == "" {
		WriteError(w, badRequest("invalidValue", "userName or emails is required"))
		return
	}
	role := in.role()
	if role == "" {
		role = h.Tenants.DefaultMemberRole()
	}
	m, err := h.Tenants.AddMember(r.Context(), t.ID, tenant.MemberInput{Email: email, Name: in.fullName(), Role: role})
	if err != nil {
		WriteError(w, err)
		return
	}
	if m, err = h.apply(r, t, m, in, false); err != nil {
		WriteError(w, err)
		return
	}
	w.Header().Set("Location", base(r, t)+"/Users/"+m.ID)
	write(w, http.StatusCreated, h.userResource(r, t, m))
}

// apply sets the mutable attributes (role, active, name) from in. With
// replace (PUT), an absent active means active. Renaming users of domains
// the tenant does not own is skipped: their profile is not the tenant's.
func (h *Handler) apply(r *http.Request, t sdk.Tenant, m sdk.Member, in userIn, replace bool) (sdk.Member, error) {
	var upd tenant.MemberUpdate
	if role := in.role(); role != "" && role != m.Role {
		upd.Role = &role
	}
	active := in.Active
	if active == nil && replace {
		yes := true
		active = &yes
	}
	if active != nil && *active != (m.Status != sdk.MemberSuspended) {
		upd.Active = active
	}
	if upd.Role != nil || upd.Active != nil {
		var err error
		if m, err = h.Tenants.UpdateMember(r.Context(), t.ID, m.ID, upd); err != nil {
			return m, err
		}
	}
	if name := in.fullName(); name != "" {
		err := h.Tenants.SetMemberName(r.Context(), t.ID, m.ID, name)
		if err != nil && !errors.Is(err, tenant.ErrForeignIdentity) {
			return m, err
		}
	}
	return m, nil
}

func (h *Handler) ReplaceUser(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	var in userIn
	if err := decode(r, &in); err != nil {
		WriteError(w, err)
		return
	}
	m, err := h.Tenants.GetMember(r.Context(), t.ID, r.PathValue("user"))
	if err != nil {
		WriteError(w, err)
		return
	}
	if e := in.email(); e != "" && !strings.EqualFold(e, m.Email) {
		WriteError(w, badRequest("mutability", "userName cannot be changed; delete and recreate the user"))
		return
	}
	if m, err = h.apply(r, t, m, in, true); err != nil {
		WriteError(w, err)
		return
	}
	write(w, http.StatusOK, h.userResource(r, t, m))
}

// patchOp is one PatchOp operation.
type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

type patchRequest struct {
	Operations []patchOp `json:"Operations"`
}

func (h *Handler) PatchUser(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	var req patchRequest
	if err := decode(r, &req); err != nil {
		WriteError(w, err)
		return
	}
	m, err := h.Tenants.GetMember(r.Context(), t.ID, r.PathValue("user"))
	if err != nil {
		WriteError(w, err)
		return
	}
	var in userIn
	for _, op := range req.Operations {
		if err := patchUser(&in, op); err != nil {
			WriteError(w, err)
			return
		}
	}
	if m, err = h.apply(r, t, m, in, false); err != nil {
		WriteError(w, err)
		return
	}
	write(w, http.StatusOK, h.userResource(r, t, m))
}

// patchUser folds one operation into in. Identity providers send either a
// path ("active", "displayName", "roles") or a value object without path.
func patchUser(in *userIn, op patchOp) error {
	switch strings.ToLower(op.Op) {
	case "add", "replace":
	case "remove":
		return nil // nothing removable is stored; roles are managed by groups
	default:
		return badRequest("invalidSyntax", "unknown op %q", op.Op)
	}
	var v userIn
	switch path := strings.ToLower(op.Path); path {
	case "":
		if err := json.Unmarshal(op.Value, &v); err != nil {
			// e.g. {"active": "False"} from Entra ID
			if v = (userIn{Active: looseBool(op.Value)}); v.Active == nil {
				return badRequest("invalidValue", "invalid value: %v", err)
			}
		}
	case "active":
		if v.Active = parseBool(op.Value); v.Active == nil {
			return badRequest("invalidValue", "active must be a boolean")
		}
	case "displayname", "name.formatted":
		_ = json.Unmarshal(op.Value, &v.DisplayName)
	case "roles":
		if err := json.Unmarshal(op.Value, &v.Roles); err != nil {
			return badRequest("invalidValue", "roles must be a list")
		}
	default:
		return nil // other attributes are not stored (RFC 7644 lets us ignore them)
	}
	merge(in, v)
	return nil
}

// parseBool accepts true/false and Entra ID's "True"/"False" strings.
func parseBool(raw json.RawMessage) *bool {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return &b
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && (strings.EqualFold(s, "true") || strings.EqualFold(s, "false")) {
		b = strings.EqualFold(s, "true")
		return &b
	}
	return nil
}

// looseBool reads {"active": "False"} value objects that fail strict
// decoding into *bool.
func looseBool(raw json.RawMessage) *bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	if v, ok := m["active"]; ok {
		return parseBool(v)
	}
	return nil
}

func merge(dst *userIn, v userIn) {
	if v.Active != nil {
		dst.Active = v.Active
	}
	if v.DisplayName != "" || v.Name != nil {
		dst.DisplayName, dst.Name = v.DisplayName, v.Name
	}
	if len(v.Roles) > 0 {
		dst.Roles = v.Roles
	}
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	if err := h.Tenants.RemoveMember(r.Context(), t.ID, r.PathValue("user")); err != nil {
		WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
