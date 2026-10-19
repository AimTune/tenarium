package api

import (
	"net/http"
	"time"

	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// scheduleActions are the permissions needed to schedule (or cancel) an
// action: the same as performing it directly.
func scheduleActions(action string) []sdk.Action {
	switch action {
	case tenant.ScheduleSuspend:
		return []sdk.Action{sdk.ActionTenantsSuspend}
	case tenant.ScheduleResume:
		return []sdk.Action{sdk.ActionTenantsResume}
	case tenant.ScheduleDelete:
		return []sdk.Action{sdk.ActionTenantsDelete}
	case tenant.ScheduleSetPlan:
		return []sdk.Action{sdk.ActionTenantsUpdate, sdk.ActionPlansWrite}
	}
	// Unknown actions fail validation in the service.
	return nil
}

func (s *Server) authorizeSchedule(w http.ResponseWriter, r *http.Request, action string, res sdk.Resource) bool {
	for _, a := range scheduleActions(action) {
		if !s.authorize(w, r, a, res) {
			return false
		}
	}
	return true
}

func (s *Server) listSchedule(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionTenantsRead)
	if !ok {
		return
	}
	items, err := s.Tenants.ListSchedule(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(items)})
}

func (s *Server) createScheduled(w http.ResponseWriter, r *http.Request) {
	var in tenant.ScheduleInput
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionTenantsRead)
	if !ok || !s.authorizeSchedule(w, r, in.Action, tenantResource(t)) {
		return
	}
	a, err := s.Tenants.Schedule(r.Context(), t.ID, in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) cancelScheduled(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionTenantsRead)
	if !ok {
		return
	}
	a, err := s.Tenants.GetScheduled(r.Context(), t.ID, r.PathValue("action"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if !s.authorizeSchedule(w, r, a.Action, tenantResource(t)) {
		return
	}
	a, err = s.Tenants.CancelScheduled(r.Context(), t.ID, a.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) deleteTenant(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionTenantsDelete)
	if !ok {
		return
	}
	force := r.URL.Query().Get("force") == "true"
	if force && !s.authorize(w, r, sdk.ActionTenantsPurge, tenantResource(t)) {
		return
	}
	t, scheduled, err := s.Tenants.RequestDeletion(r.Context(), t.ID, force)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if scheduled != nil {
		w.Header().Set("Tenarium-Deletion-At", scheduled.RunAt.Format(time.RFC3339))
	}
	writeVersioned(w, http.StatusAccepted, t.Version, t)
}

func (s *Server) restoreTenant(w http.ResponseWriter, r *http.Request) {
	s.transition(w, r, sdk.ActionTenantsDelete, http.StatusOK, s.Tenants.Restore)
}
