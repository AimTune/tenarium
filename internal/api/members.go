package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionMembersRead)
	if !ok {
		return
	}
	ms, err := s.Tenants.ListMembers(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(ms), "roles": s.tenantRoleNames(r, t.ID)})
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request) {
	var in tenant.MemberInput
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionMembersWrite)
	if !ok {
		return
	}
	// A role grants its actions: the caller must hold them all.
	if !s.canGrant(w, r, t, s.rolePatterns(r, t, []string{in.Role})) {
		return
	}
	m, err := s.Tenants.AddMember(r.Context(), t.ID, in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/tenants/"+t.ID+"/members/"+m.ID)
	writeVersioned(w, http.StatusCreated, m.Version, m)
}

func (s *Server) getMember(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionMembersRead)
	if !ok {
		return
	}
	m, err := s.Tenants.GetMember(r.Context(), t.ID, r.PathValue("member"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeVersioned(w, http.StatusOK, m.Version, m)
}

func (s *Server) updateMember(w http.ResponseWriter, r *http.Request) {
	var in tenant.MemberUpdate
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionMembersWrite)
	if !ok {
		return
	}
	if in.Role != nil && !s.canGrant(w, r, t, s.rolePatterns(r, t, []string{*in.Role})) {
		return
	}
	m, err := s.Tenants.UpdateMember(r.Context(), t.ID, r.PathValue("member"), in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeVersioned(w, http.StatusOK, m.Version, m)
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionMembersWrite)
	if !ok {
		return
	}
	if err := s.Tenants.RemoveMember(r.Context(), t.ID, r.PathValue("member")); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getUsage(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionUsageRead)
	if !ok {
		return
	}
	items, err := s.Tenants.Usage(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(items)})
}

func (s *Server) recordUsage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Delta int64 `json:"delta"`
	}
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionUsageWrite)
	if !ok {
		return
	}
	item, err := s.Tenants.RecordUsage(r.Context(), t.ID, r.PathValue("metric"), in.Delta)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) usageHistory(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionUsageRead)
	if !ok {
		return
	}
	limit, err := queryLimit(r, 12, 366)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	items, err := s.Tenants.UsageHistory(r.Context(), t.ID, r.PathValue("metric"), limit)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(items)})
}

// reserveUsage hands a share of a limit to a regional cell.
func (s *Server) reserveUsage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Amount     int64  `json:"amount"`
		TTLSeconds int64  `json:"ttl_seconds"`
		Holder     string `json:"holder"`
	}
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionUsageWrite)
	if !ok {
		return
	}
	g, err := s.Tenants.ReserveUsage(r.Context(), t.ID, r.PathValue("metric"), tenant.GrantInput{
		Amount: in.Amount, TTL: time.Duration(in.TTLSeconds) * time.Second, Holder: in.Holder})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

// releaseUsage closes a grant and gives back what was not used.
func (s *Server) releaseUsage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Used int64 `json:"used"`
	}
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionUsageWrite)
	if !ok {
		return
	}
	g, err := s.Tenants.ReleaseUsage(r.Context(), t.ID, r.PathValue("grant"), in.Used)
	if errors.Is(err, tenant.ErrGrantGone) {
		writeError(w, http.StatusGone, "grant_gone", err.Error(), "")
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}
