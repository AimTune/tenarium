package api

import (
	"net/http"

	"github.com/AimTune/tenarium/internal/eventschema"
)

// Event schemas describe public contracts; any authenticated caller may
// read them.

func (s *Server) listEventSchemas(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": eventschema.All(), "envelope": eventschema.EnvelopeSchema()})
}

func (s *Server) getEventSchema(w http.ResponseWriter, r *http.Request) {
	e, ok := eventschema.Get(r.PathValue("type"))
	if v := r.PathValue("version"); v != "" {
		e, ok = eventschema.GetVersion(r.PathValue("type"), v)
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "unknown event type or version", "")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, e)
}
