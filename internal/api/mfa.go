package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// Impersonated sessions may not manage the user's own credentials or data.
func selfID(w http.ResponseWriter, r *http.Request) (string, bool) {
	if impersonated(r) {
		writeError(w, http.StatusForbidden, "forbidden", "not allowed while impersonating", "")
		return "", false
	}
	id := callerUserID(r)
	if id == "" {
		writeError(w, http.StatusBadRequest, "not_a_user", "the caller is not a Tenarium user", "")
	}
	return id, id != ""
}

func impersonated(r *http.Request) bool {
	p, ok := sdk.PrincipalFrom(r.Context())
	if !ok {
		return false
	}
	_, imp := p.Claims[tenant.ImpersonationClaim]
	return imp
}

type otpBody struct {
	Code string `json:"code"`
}

func (s *Server) myMFA(w http.ResponseWriter, r *http.Request) {
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	st, err := s.Tenants.MFAStatus(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) beginTOTP(w http.ResponseWriter, r *http.Request) {
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	e, err := s.Tenants.BeginTOTP(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	var in otpBody
	if !decode(w, r, &in) {
		return
	}
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	codes, err := s.Tenants.ConfirmTOTP(r.Context(), id, in.Code)
	if err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (s *Server) regenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	var in otpBody
	if !decode(w, r, &in) {
		return
	}
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	codes, err := s.Tenants.RegenerateRecoveryCodes(r.Context(), id, in.Code)
	if err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (s *Server) disableMyMFA(w http.ResponseWriter, r *http.Request) {
	var in otpBody
	if !decode(w, r, &in) {
		return
	}
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	if err := s.Tenants.DisableMFA(r.Context(), id, in.Code); err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) resetUserMFA(w http.ResponseWriter, r *http.Request) {
	u, ok := s.loadUser(w, r, sdk.ActionUsersWrite)
	if !ok {
		return
	}
	if err := s.Tenants.ResetMFA(r.Context(), u.ID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) grantImpersonationConsent(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TTL string `json:"ttl"`
	}
	if r.ContentLength != 0 && !decode(w, r, &in) {
		return
	}
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	var ttl time.Duration
	if in.TTL != "" {
		d, err := time.ParseDuration(in.TTL)
		if err != nil {
			s.writeErr(w, r, &tenant.ValidationError{Field: "ttl", Message: "must be a duration such as 1h"})
			return
		}
		ttl = d
	}
	code, exp, err := s.Tenants.GrantImpersonationConsent(r.Context(), id, ttl)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"code": code, "expires_at": exp})
}

func (s *Server) impersonateUser(w http.ResponseWriter, r *http.Request) {
	var in tenant.ImpersonationInput
	if !decode(w, r, &in) {
		return
	}
	u, ok := s.loadUser(w, r, sdk.ActionUsersImpersonate)
	if !ok {
		return
	}
	pair, err := s.Tenants.Impersonate(r.Context(), u.ID, in)
	if err != nil {
		if errors.Is(err, tenant.ErrConsentRequired) {
			writeError(w, http.StatusForbidden, "consent_required", err.Error(), "consent_code")
			return
		}
		s.writeAuthErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, pair)
}
