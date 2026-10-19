package api

import (
	"encoding/json"
	"net/http"
)

func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) {
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	items, err := s.Tenants.ListPasskeys(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(items)})
}

func (s *Server) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	opts, ceremony, err := s.Tenants.BeginPasskeyRegistration(r.Context(), id)
	if err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"options": opts, "ceremony": ceremony})
}

func (s *Server) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ceremony   string          `json:"ceremony"`
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &in) {
		return
	}
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	c, err := s.Tenants.FinishPasskeyRegistration(r.Context(), id, in.Ceremony, in.Name, in.Credential)
	if err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request) {
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	if err := s.Tenants.DeletePasskey(r.Context(), id, r.PathValue("passkey")); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// beginPasskeyLogin and finishPasskeyLogin are public (rate-limited) sign-in
// endpoints.
func (s *Server) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if r.ContentLength != 0 && !decode(w, r, &in) {
		return
	}
	opts, ceremony, err := s.Tenants.BeginPasskeyLogin(r.Context(), in.Email)
	if err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"options": opts, "ceremony": ceremony})
}

func (s *Server) finishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ceremony   string          `json:"ceremony"`
		Credential json.RawMessage `json:"credential"`
		Tenant     string          `json:"tenant"`
	}
	if !decode(w, r, &in) {
		return
	}
	pair, err := s.Tenants.FinishPasskeyLogin(r.Context(), in.Ceremony, in.Credential, in.Tenant)
	if err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, pair)
}
