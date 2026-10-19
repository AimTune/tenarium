package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var in tenant.CreateInput
	if !decode(w, r, &in) {
		return
	}
	// Creating a child is authorized against the parent, so tenant-scoped
	// admins can create workspaces under their organization.
	res := sdk.Resource{Type: "tenant"}
	if in.ParentID != "" {
		parent, err := s.Tenants.Get(r.Context(), in.ParentID)
		if err != nil {
			s.writeErr(w, r, &tenant.ValidationError{Field: "parent_id", Message: "parent tenant not found"})
			return
		}
		in.ParentID = parent.ID
		res.TenantID = parent.ID
	}
	if !s.authorize(w, r, sdk.ActionTenantsCreate, res) {
		return
	}
	// Choosing a plan, features or limits is a commercial decision, as in
	// updateTenant.
	if in.Plan != "" || len(in.Features) > 0 || len(in.Limits) > 0 || len(in.AddOns) > 0 {
		if !s.authorize(w, r, sdk.ActionPlansWrite, res) {
			return
		}
	}
	if !s.authorizeTemplate(w, r, in.Template, res) {
		return
	}
	for _, sc := range in.Schedule {
		if !s.authorizeSchedule(w, r, sc.Action, res) {
			return
		}
	}
	t, err := s.Tenants.Create(r.Context(), in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/tenants/"+t.ID)
	writeVersioned(w, http.StatusCreated, t.Version, t)
}

func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) {
	if t, ok := s.loadTenant(w, r, sdk.ActionTenantsRead); ok {
		writeVersioned(w, http.StatusOK, t.Version, t)
	}
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := store.ListTenantsQuery{
		Status:         sdk.TenantStatus(q.Get("status")),
		Plan:           q.Get("plan"),
		After:          q.Get("after"),
		IncludeDeleted: q.Get("include_deleted") == "true",
	}
	limit, err := queryLimit(r, 50, 500)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	query.Limit = limit
	for _, sel := range q["label"] {
		k, v, ok := strings.Cut(sel, "=")
		if !ok {
			s.writeErr(w, r, &tenant.ValidationError{Field: "label", Message: "must be key=value"})
			return
		}
		if query.Labels == nil {
			query.Labels = map[string]string{}
		}
		query.Labels[k] = v
	}

	res := sdk.Resource{Type: "tenant"}
	if pid := q.Get("parent_id"); pid != "" {
		parent, err := s.Tenants.Get(r.Context(), pid)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		query.ParentID, res.TenantID = parent.ID, parent.ID
	}
	p, _ := sdk.PrincipalFrom(r.Context())
	if p != nil && p.TenantID != "" && query.ParentID == "" {
		// Tenant-scoped callers listing without a parent see only their own
		// tenant; they list descendants via parent_id.
		query.IDs = []string{p.TenantID}
		res.TenantID = p.TenantID
	}
	if !s.authorize(w, r, sdk.ActionTenantsRead, res) {
		return
	}
	s.writeTenantPage(w, r, query)
}

func (s *Server) listChildren(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionTenantsRead)
	if !ok {
		return
	}
	limit, err := queryLimit(r, 50, 500)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.writeTenantPage(w, r, store.ListTenantsQuery{ParentID: t.ID, After: r.URL.Query().Get("after"), Limit: limit})
}

func (s *Server) writeTenantPage(w http.ResponseWriter, r *http.Request, q store.ListTenantsQuery) {
	items, err := s.Tenants.List(r.Context(), q)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	resp := map[string]any{"items": nonNil(items)}
	if len(items) == q.Limit {
		resp["next"] = items[len(items)-1].ID
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) updateTenant(w http.ResponseWriter, r *http.Request) {
	var in tenant.UpdateInput
	if !decode(w, r, &in) {
		return
	}
	expected, err := ifMatch(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionTenantsUpdate)
	if !ok {
		return
	}
	// Plan, feature and limit changes are commercial decisions; they need
	// plans:write in addition to tenants:update.
	if in.Plan != nil || in.Features != nil || in.Limits != nil || in.AddOns != nil || in.BillingAnchor != nil || in.ClearBillingAnchor {
		if !s.authorize(w, r, sdk.ActionPlansWrite, tenantResource(t)) {
			return
		}
	}
	t, err = s.Tenants.Update(r.Context(), t.ID, in, expected)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeVersioned(w, http.StatusOK, t.Version, t)
}

func (s *Server) suspendTenant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength != 0 && !decode(w, r, &in) {
		return
	}
	s.transition(w, r, sdk.ActionTenantsSuspend, http.StatusOK, func(ctx context.Context, id string) (sdk.Tenant, error) {
		return s.Tenants.Suspend(ctx, id, in.Reason)
	})
}

func (s *Server) resumeTenant(w http.ResponseWriter, r *http.Request) {
	s.transition(w, r, sdk.ActionTenantsResume, http.StatusOK, s.Tenants.Resume)
}

func (s *Server) retryProvisioning(w http.ResponseWriter, r *http.Request) {
	s.transition(w, r, sdk.ActionTenantsProvision, http.StatusAccepted, s.Tenants.RetryProvisioning)
}

func (s *Server) transition(w http.ResponseWriter, r *http.Request, action sdk.Action, status int,
	fn func(ctx context.Context, id string) (sdk.Tenant, error),
) {
	t, ok := s.loadTenant(w, r, action)
	if !ok {
		return
	}
	t, err := fn(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeVersioned(w, status, t.Version, t)
}

func (s *Server) getEntitlements(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionTenantsRead)
	if !ok {
		return
	}
	e, err := s.Tenants.Entitlements(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}
