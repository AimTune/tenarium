package api

import (
	"net/http"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// writeExport sends a data export as a JSON download.
func writeExport(w http.ResponseWriter, name string, v any) {
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) exportTenant(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionDataExport)
	if !ok {
		return
	}
	x, err := s.Tenants.ExportTenant(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeExport(w, "tenant-"+t.Slug, x)
}

func (s *Server) exportUser(w http.ResponseWriter, r *http.Request) {
	u, ok := s.loadUser(w, r, sdk.ActionUsersRead)
	if !ok {
		return
	}
	s.writeUserExport(w, r, u.ID)
}

func (s *Server) exportMe(w http.ResponseWriter, r *http.Request) {
	if id, ok := selfID(w, r); ok {
		s.writeUserExport(w, r, id)
	}
}

func (s *Server) writeUserExport(w http.ResponseWriter, r *http.Request, id string) {
	x, err := s.Tenants.ExportUser(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeExport(w, "user-"+id, x)
}

func (s *Server) eraseUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RedactEvents bool `json:"redact_events"`
	}
	if r.ContentLength != 0 && !decode(w, r, &in) {
		return
	}
	u, ok := s.loadUser(w, r, sdk.ActionDataErase)
	if !ok {
		return
	}
	n, err := s.Tenants.EraseUser(r.Context(), u.ID, in.RedactEvents)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_id": u.ID, "erased": true, "redacted_events": n})
}
