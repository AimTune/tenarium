package api

import (
	"net/http"

	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func planResource(id string) sdk.Resource { return sdk.Resource{Type: "plan", ID: id} }

func (s *Server) listPlans(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionPlansRead, planResource("")) {
		return
	}
	plans, err := s.Tenants.ListPlans(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(plans)})
}

func (s *Server) createPlan(w http.ResponseWriter, r *http.Request) {
	var in tenant.PlanInput
	if !decode(w, r, &in) {
		return
	}
	if !s.authorize(w, r, sdk.ActionPlansWrite, planResource(in.ID)) {
		return
	}
	p, err := s.Tenants.CreatePlan(r.Context(), in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/plans/"+p.ID)
	writeVersioned(w, http.StatusCreated, p.Version, p)
}

func (s *Server) getPlan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.authorize(w, r, sdk.ActionPlansRead, planResource(id)) {
		return
	}
	p, err := s.Tenants.GetPlan(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeVersioned(w, http.StatusOK, p.Version, p)
}

func (s *Server) updatePlan(w http.ResponseWriter, r *http.Request) {
	var in tenant.PlanUpdate
	if !decode(w, r, &in) {
		return
	}
	expected, err := ifMatch(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	id := r.PathValue("id")
	if !s.authorize(w, r, sdk.ActionPlansWrite, planResource(id)) {
		return
	}
	p, err := s.Tenants.UpdatePlan(r.Context(), id, in, expected)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeVersioned(w, http.StatusOK, p.Version, p)
}

func (s *Server) deletePlan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.authorize(w, r, sdk.ActionPlansWrite, planResource(id)) {
		return
	}
	if err := s.Tenants.DeletePlan(r.Context(), id); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
