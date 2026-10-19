package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/AimTune/tenarium/internal/events"
	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/internal/webhooks"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// writeErr maps domain errors to HTTP responses:
//
//	400 validation_failed   409 already_exists / invalid_transition
//	403 forbidden           412 version_conflict
//	404 not_found           422 rejected (plugin hook)
//	429 quota_exceeded      500 internal
func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var (
		ve *tenant.ValidationError
		qe *tenant.QuotaError
		we *webhooks.ValidationError
	)
	switch {
	case errors.As(err, &ve):
		writeError(w, http.StatusBadRequest, "validation_failed", ve.Message, ve.Field)
	case errors.As(err, &we):
		writeError(w, http.StatusBadRequest, "validation_failed", we.Message, we.Field)
	case errors.As(err, &qe):
		w.Header().Set("X-Quota-Limit", strconv.FormatInt(qe.Limit, 10))
		writeError(w, http.StatusTooManyRequests, "quota_exceeded", qe.Error(), qe.Metric)
	case errors.Is(err, sdk.ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden", err.Error(), "")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "resource not found", "")
	case errors.Is(err, store.ErrAlreadyExists):
		writeError(w, http.StatusConflict, "already_exists", err.Error(), "")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusPreconditionFailed, "version_conflict", "resource was modified concurrently; re-read and retry", "")
	case errors.Is(err, tenant.ErrInvalidTransition):
		writeError(w, http.StatusConflict, "invalid_transition", err.Error(), "")
	case errors.Is(err, identity.ErrActiveKey):
		writeError(w, http.StatusConflict, "active_key", err.Error(), "")
	case errors.Is(err, tenant.ErrVerificationFailed):
		writeError(w, http.StatusUnprocessableEntity, "verification_failed", err.Error(), "hostname")
	case errors.Is(err, events.ErrInvalidRange):
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), "since")
	case errors.Is(err, events.ErrUnknownSubscription):
		writeError(w, http.StatusConflict, "unknown_subscription", err.Error(), "")
	default:
		if re, ok := sdk.IsReject(err); ok {
			writeError(w, http.StatusUnprocessableEntity, "rejected", re.Reason, "")
			return
		}
		s.Log.Error("request failed", "method", r.Method, "path", r.URL.Path,
			"request_id", r.Header.Get("X-Request-ID"), "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error", "")
	}
}

func writeError(w http.ResponseWriter, status int, code, msg, field string) {
	body := map[string]string{"code": code, "message": msg}
	if field != "" {
		body["field"] = field
	}
	writeJSON(w, status, map[string]any{"error": body})
}
