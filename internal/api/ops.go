package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/AimTune/tenarium/internal/events"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// listEvents pages through the event log. Optional filters (tenant_id, type
// glob) are applied to each page, so a page may hold fewer than limit items;
// follow "next" until it is absent.
func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tenantID := q.Get("tenant_id")
	res := sdk.Resource{Type: "event", TenantID: tenantID}
	if !s.authorize(w, r, sdk.ActionEventsRead, res) {
		return
	}
	after, err := strconv.ParseInt(q.Get("after"), 10, 64)
	if err != nil && q.Get("after") != "" {
		s.writeErr(w, r, &tenant.ValidationError{Field: "after", Message: "must be an event sequence number"})
		return
	}
	limit, err := queryLimit(r, 100, 1000)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	evts, err := s.Store.ReadEvents(r.Context(), after, limit)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	filter := sdk.EventFilter{}
	if t := q.Get("type"); t != "" {
		filter.Types = []string{t}
	}
	items := make([]sdk.Event, 0, len(evts))
	for _, e := range evts {
		if (tenantID == "" || e.TenantID == tenantID) && filter.Match(e) {
			items = append(items, e)
		}
	}
	resp := map[string]any{"items": items}
	if len(evts) == limit {
		resp["next"] = strconv.FormatInt(evts[len(evts)-1].Seq, 10)
	}
	writeJSON(w, http.StatusOK, resp)
}

func dlResource(id string) sdk.Resource { return sdk.Resource{Type: "deadletter", ID: id} }

func (s *Server) listDeadLetters(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionDeadLettersRead, dlResource("")) {
		return
	}
	dls, err := s.Store.ListDeadLetters(r.Context(), r.URL.Query().Get("subscription"), 500)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(dls), "subscriptions": s.Dispatcher.Subscriptions()})
}

func (s *Server) getDeadLetter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.authorize(w, r, sdk.ActionDeadLettersRead, dlResource(id)) {
		return
	}
	dl, err := s.Store.GetDeadLetter(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, dl)
}

func (s *Server) replayDeadLetter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.authorize(w, r, sdk.ActionDeadLettersReplay, dlResource(id)) {
		return
	}
	if err := s.Dispatcher.Replay(r.Context(), id); err != nil {
		if _, getErr := s.Store.GetDeadLetter(r.Context(), id); getErr != nil {
			s.writeErr(w, r, getErr)
			return
		}
		writeError(w, http.StatusBadGateway, "replay_failed", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "delivered"})
}

func (s *Server) deleteDeadLetter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.authorize(w, r, sdk.ActionDeadLettersReplay, dlResource(id)) {
		return
	}
	if err := s.Store.DeleteDeadLetter(r.Context(), id); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listPlugins(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionPluginsRead, sdk.Resource{Type: "plugin"}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":     nonNil(s.Plugins.Infos()),
		"available": sdk.Registered(),
	})
}

// replayEvents redelivers the stored events of a time range to one
// subscription (names may contain "/", hence the body field).
func (s *Server) replayEvents(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Subscription string    `json:"subscription"`
		Since        time.Time `json:"since"`
		Until        time.Time `json:"until"`
		Types        []string  `json:"types"`
		TenantIDs    []string  `json:"tenant_ids"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.authorize(w, r, sdk.ActionDeadLettersReplay, sdk.Resource{Type: "subscription", ID: in.Subscription}) {
		return
	}
	res, err := s.Dispatcher.ReplayRange(r.Context(), in.Subscription, events.RangeQuery{
		Since: in.Since, Until: in.Until, Types: in.Types, TenantIDs: in.TenantIDs})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// reloadConfig applies a changed configuration file (like SIGHUP).
func (s *Server) reloadConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionConfigReload, sdk.Resource{Type: "config"}) {
		return
	}
	if s.Reload == nil {
		writeError(w, http.StatusNotFound, "not_found", "the server was started without a configuration file", "")
		return
	}
	res, err := s.Reload(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, "reload_failed", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, res)
}
