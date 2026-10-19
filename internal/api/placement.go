package api

import (
	"net/http"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func (s *Server) listPlanRevisions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.authorize(w, r, sdk.ActionPlansRead, planResource(id)) {
		return
	}
	revs, err := s.Tenants.ListPlanRevisions(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(revs)})
}

func (s *Server) setPlanRevision(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Revision int64 `json:"revision"`
	}
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionTenantsUpdate)
	if !ok {
		return
	}
	if !s.authorize(w, r, sdk.ActionPlansWrite, tenantResource(t)) {
		return
	}
	t, err := s.Tenants.SetPlanRevision(r.Context(), t.ID, in.Revision)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeVersioned(w, http.StatusOK, t.Version, t)
}

func (s *Server) moveRegion(w http.ResponseWriter, r *http.Request) {
	var in tenant.MoveInput
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionTenantsMove)
	if !ok {
		return
	}
	t, err := s.Tenants.MoveRegion(r.Context(), t.ID, in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeVersioned(w, http.StatusOK, t.Version, t)
}

func (s *Server) listRegions(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionPlansRead, sdk.Resource{Type: "region"}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(s.Tenants.Regions())})
}

// Rollouts name tenant IDs (include/exclude lists), so even reading them
// is platform-only (plans:write).
func rolloutResource(feature string) sdk.Resource { return sdk.Resource{Type: "rollout", ID: feature} }

func (s *Server) listRollouts(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionPlansWrite, rolloutResource("")) {
		return
	}
	rs, err := s.Tenants.ListRollouts(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(rs)})
}

func (s *Server) getRollout(w http.ResponseWriter, r *http.Request) {
	f := r.PathValue("feature")
	if !s.authorize(w, r, sdk.ActionPlansWrite, rolloutResource(f)) {
		return
	}
	ro, err := s.Tenants.GetRollout(r.Context(), f)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, ro)
}

func (s *Server) putRollout(w http.ResponseWriter, r *http.Request) {
	var in store.Rollout
	if !decode(w, r, &in) {
		return
	}
	in.Feature = r.PathValue("feature")
	if !s.authorize(w, r, sdk.ActionPlansWrite, rolloutResource(in.Feature)) {
		return
	}
	ro, err := s.Tenants.PutRollout(r.Context(), in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, ro)
}

func (s *Server) deleteRollout(w http.ResponseWriter, r *http.Request) {
	f := r.PathValue("feature")
	if !s.authorize(w, r, sdk.ActionPlansWrite, rolloutResource(f)) {
		return
	}
	if err := s.Tenants.DeleteRollout(r.Context(), f); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
