package api

import (
	"net/http"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// Signing key event types.
const (
	EventSigningKeyRotated = "signing_key.rotated"
	EventSigningKeyRetired = "signing_key.retired"
)

var signingKeysResource = sdk.Resource{Type: "signing_key"}

// issuerEnabled answers 404 when Tenarium tokens are disabled.
func (s *Server) issuerEnabled(w http.ResponseWriter, r *http.Request, action sdk.Action) bool {
	if !s.authorize(w, r, action, signingKeysResource) {
		return false
	}
	if s.Issuer == nil {
		writeError(w, http.StatusNotFound, "not_found", "Tenarium tokens are disabled", "")
		return false
	}
	return true
}

func (s *Server) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	if !s.issuerEnabled(w, r, sdk.ActionSigningKeysRead) {
		return
	}
	keys, err := s.Issuer.Keys(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": keys})
}

func (s *Server) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	if !s.issuerEnabled(w, r, sdk.ActionSigningKeysWrite) {
		return
	}
	if err := s.Issuer.Rotate(r.Context()); err != nil {
		s.writeErr(w, r, err)
		return
	}
	keys, err := s.Issuer.Keys(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	active := keys[len(keys)-1]
	if err := s.Tenants.RecordEvent(r.Context(), EventSigningKeyRotated, "", "signing-keys/"+active.ID, active); err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, active)
}

func (s *Server) retireSigningKey(w http.ResponseWriter, r *http.Request) {
	if !s.issuerEnabled(w, r, sdk.ActionSigningKeysWrite) {
		return
	}
	kid := r.PathValue("kid")
	if err := s.Issuer.Retire(r.Context(), kid); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err := s.Tenants.RecordEvent(r.Context(), EventSigningKeyRetired, "", "signing-keys/"+kid, map[string]string{"kid": kid}); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
