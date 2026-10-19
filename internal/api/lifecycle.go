package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// checkMaintenance refuses changes by tenant-scoped callers to a tenant in
// a maintenance window; platform callers (who run the maintenance) pass.
func (s *Server) checkMaintenance(w http.ResponseWriter, r *http.Request, p *sdk.Principal, action sdk.Action, res sdk.Resource) bool {
	if p == nil || p.TenantID == "" || res.TenantID == "" || strings.HasSuffix(string(action), ":read") {
		return true
	}
	if err := s.Tenants.CheckWritable(r.Context(), res.TenantID); err != nil {
		w.Header().Set("Retry-After", "300")
		writeError(w, http.StatusServiceUnavailable, "maintenance", err.Error(), "")
		return false
	}
	return true
}

func (s *Server) startMaintenance(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Message string     `json:"message"`
		Until   *time.Time `json:"until"`
	}
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionTenantsSuspend)
	if !ok {
		return
	}
	t, err := s.Tenants.StartMaintenance(r.Context(), t.ID, in.Message, in.Until)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeVersioned(w, http.StatusOK, t.Version, t)
}

func (s *Server) endMaintenance(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionTenantsResume)
	if !ok {
		return
	}
	t, err := s.Tenants.EndMaintenance(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeVersioned(w, http.StatusOK, t.Version, t)
}

func (s *Server) tenantHealth(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionTenantsRead)
	if !ok {
		return
	}
	h, err := s.Tenants.TenantHealth(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

// publicBranding serves sign-in pages: ?tenant=<id or slug> or
// ?host=<custom domain>.
func (s *Server) publicBranding(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("tenant") == "" && q.Get("host") == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "tenant or host is required", "tenant")
		return
	}
	b, err := s.Tenants.BrandingFor(r.Context(), q.Get("tenant"), q.Get("host"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) cloneTenant(w http.ResponseWriter, r *http.Request) {
	var in tenant.CloneInput
	if !decode(w, r, &in) {
		return
	}
	src, ok := s.loadTenant(w, r, sdk.ActionTenantsRead)
	if !ok {
		return
	}
	res := sdk.Resource{Type: "tenant"}
	if in.ParentID != "" {
		parent, err := s.Tenants.Get(r.Context(), in.ParentID)
		if err != nil {
			s.writeErr(w, r, &tenant.ValidationError{Field: "parent_id", Message: "parent tenant not found"})
			return
		}
		in.ParentID, res.TenantID = parent.ID, parent.ID
	}
	if !s.authorize(w, r, sdk.ActionTenantsCreate, res) {
		return
	}
	// Copying a plan, add-ons, features or limits is as commercial as
	// choosing them.
	if src.Plan != "" || len(src.Features) > 0 || len(src.Limits) > 0 || len(src.AddOns) > 0 {
		if !s.authorize(w, r, sdk.ActionPlansWrite, res) {
			return
		}
	}
	roles, err := s.Tenants.CloneRoles(r.Context(), src.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if !s.canGrantRoles(w, r, sdk.Tenant{ID: res.TenantID}, roles) {
		return
	}
	if in.Members && !s.authorize(w, r, sdk.ActionMembersRead, tenantResource(src)) {
		return
	}
	t, err := s.Tenants.CloneTenant(r.Context(), src.ID, in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/tenants/"+t.ID)
	writeVersioned(w, http.StatusCreated, t.Version, t)
}

// authorizeTemplate checks a create request's template: commercial values
// need plans:write and its roles must be grantable.
func (s *Server) authorizeTemplate(w http.ResponseWriter, r *http.Request, id string, res sdk.Resource) bool {
	if id == "" {
		return true
	}
	tpl, err := s.Tenants.GetTemplate(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.writeErr(w, r, &tenant.ValidationError{Field: "template", Message: "unknown template"})
		return false
	} else if err != nil {
		s.writeErr(w, r, err)
		return false
	}
	if tpl.Plan != "" || len(tpl.Features) > 0 || len(tpl.Limits) > 0 || len(tpl.AddOns) > 0 {
		if !s.authorize(w, r, sdk.ActionPlansWrite, res) {
			return false
		}
	}
	return s.canGrantRoles(w, r, sdk.Tenant{ID: res.TenantID}, tpl.Roles)
}

func (s *Server) canGrantRoles(w http.ResponseWriter, r *http.Request, t sdk.Tenant, roles []store.TemplateRole) bool {
	var patterns []string
	for _, ro := range roles {
		patterns = append(patterns, ro.Actions...)
	}
	return len(patterns) == 0 || s.canGrant(w, r, t, patterns)
}

func templateResource(id string) sdk.Resource { return sdk.Resource{Type: "tenant-template", ID: id} }

func (s *Server) listTemplates(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionPlansRead, templateResource("")) {
		return
	}
	ts, err := s.Tenants.ListTemplates(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(ts)})
}

func (s *Server) getTemplate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("template")
	if !s.authorize(w, r, sdk.ActionPlansRead, templateResource(id)) {
		return
	}
	t, err := s.Tenants.GetTemplate(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) putTemplate(w http.ResponseWriter, r *http.Request) {
	var in store.TenantTemplate
	if !decode(w, r, &in) {
		return
	}
	in.ID = r.PathValue("template")
	if !s.authorize(w, r, sdk.ActionPlansWrite, templateResource(in.ID)) {
		return
	}
	t, err := s.Tenants.PutTemplate(r.Context(), in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("template")
	if !s.authorize(w, r, sdk.ActionPlansWrite, templateResource(id)) {
		return
	}
	if err := s.Tenants.DeleteTemplate(r.Context(), id); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
