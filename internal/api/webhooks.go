package api

import (
	"net/http"

	"github.com/AimTune/tenarium/internal/webhooks"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// webhookTenant authorizes action on the path's tenant and answers 404
// when tenant webhooks are disabled.
func (s *Server) webhookTenant(w http.ResponseWriter, r *http.Request, action sdk.Action) (string, bool) {
	t, ok := s.loadTenant(w, r, action)
	if !ok {
		return "", false
	}
	if s.Webhooks == nil {
		writeError(w, http.StatusNotFound, "not_found", "tenant webhooks are disabled", "")
		return "", false
	}
	return t.ID, true
}

func (s *Server) listWebhooks(w http.ResponseWriter, r *http.Request) {
	tid, ok := s.webhookTenant(w, r, sdk.ActionWebhooksRead)
	if !ok {
		return
	}
	items, err := s.Webhooks.List(r.Context(), tid)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(items)})
}

func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) {
	var in webhooks.Input
	if !decode(w, r, &in) {
		return
	}
	tid, ok := s.webhookTenant(w, r, sdk.ActionWebhooksWrite)
	if !ok {
		return
	}
	hook, secret, err := s.Webhooks.Create(r.Context(), tid, in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"webhook": hook, "secret": secret})
}

func (s *Server) getWebhook(w http.ResponseWriter, r *http.Request) {
	tid, ok := s.webhookTenant(w, r, sdk.ActionWebhooksRead)
	if !ok {
		return
	}
	hook, err := s.Webhooks.Get(r.Context(), tid, r.PathValue("webhook"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, hook)
}

func (s *Server) updateWebhook(w http.ResponseWriter, r *http.Request) {
	var in webhooks.Input
	if !decode(w, r, &in) {
		return
	}
	tid, ok := s.webhookTenant(w, r, sdk.ActionWebhooksWrite)
	if !ok {
		return
	}
	hook, err := s.Webhooks.Update(r.Context(), tid, r.PathValue("webhook"), in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, hook)
}

func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	tid, ok := s.webhookTenant(w, r, sdk.ActionWebhooksWrite)
	if !ok {
		return
	}
	if err := s.Webhooks.Delete(r.Context(), tid, r.PathValue("webhook")); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotateWebhookSecret(w http.ResponseWriter, r *http.Request) {
	tid, ok := s.webhookTenant(w, r, sdk.ActionWebhooksWrite)
	if !ok {
		return
	}
	secret, err := s.Webhooks.RotateSecret(r.Context(), tid, r.PathValue("webhook"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret})
}

func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) {
	tid, ok := s.webhookTenant(w, r, sdk.ActionWebhooksWrite)
	if !ok {
		return
	}
	d, err := s.Webhooks.Test(r.Context(), tid, r.PathValue("webhook"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) listWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	tid, ok := s.webhookTenant(w, r, sdk.ActionWebhooksRead)
	if !ok {
		return
	}
	limit, err := queryLimit(r, 50, 200)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	items, err := s.Webhooks.Deliveries(r.Context(), tid, r.PathValue("webhook"), r.URL.Query().Get("before"), limit)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	resp := map[string]any{"items": nonNil(items)}
	if len(items) == limit {
		resp["next"] = items[len(items)-1].ID
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) redeliverWebhook(w http.ResponseWriter, r *http.Request) {
	tid, ok := s.webhookTenant(w, r, sdk.ActionWebhooksWrite)
	if !ok {
		return
	}
	d, err := s.Webhooks.Redeliver(r.Context(), tid, r.PathValue("webhook"), r.PathValue("delivery"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}
