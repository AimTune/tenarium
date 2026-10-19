package api

import (
	"net/http"

	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func (s *Server) getSSO(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionSSORead)
	if !ok {
		return
	}
	c, err := s.Tenants.GetSSO(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) putSSO(w http.ResponseWriter, r *http.Request) {
	var in tenant.SSOInput
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionSSOWrite)
	if !ok {
		return
	}
	c, err := s.Tenants.PutSSO(r.Context(), t.ID, in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) deleteSSO(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionSSOWrite)
	if !ok {
		return
	}
	if err := s.Tenants.DeleteSSO(r.Context(), t.ID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ssoAvailable answers 404 when SSO is off (Tenarium tokens disabled).
func (s *Server) ssoAvailable(w http.ResponseWriter) bool {
	if s.SSO == nil {
		writeError(w, http.StatusNotFound, "not_found", "single sign-on is not available", "")
		return false
	}
	return true
}

func (s *Server) ssoStart(w http.ResponseWriter, r *http.Request) {
	if s.ssoAvailable(w) {
		s.SSO.Start(w, r)
	}
}

func (s *Server) ssoCallback(w http.ResponseWriter, r *http.Request) {
	if s.ssoAvailable(w) {
		s.SSO.Callback(w, r)
	}
}

func (s *Server) ssoDiscover(w http.ResponseWriter, r *http.Request) {
	if s.ssoAvailable(w) {
		s.SSO.Discover(w, r)
	}
}

func (s *Server) samlMetadata(w http.ResponseWriter, r *http.Request) {
	if s.ssoAvailable(w) {
		s.SSO.SAMLMetadata(w, r)
	}
}

func (s *Server) samlACS(w http.ResponseWriter, r *http.Request) {
	if s.ssoAvailable(w) {
		s.SSO.SAMLACS(w, r)
	}
}
