package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// auditQuery parses the filters shared by the audit endpoints.
func auditQuery(r *http.Request) (store.EventQuery, error) {
	q := r.URL.Query()
	eq := store.EventQuery{Actor: q.Get("actor"), Types: q["type"]}
	for _, f := range []struct {
		name string
		dst  *time.Time
	}{{"since", &eq.Since}, {"until", &eq.Until}} {
		if v := q.Get(f.name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return eq, &tenant.ValidationError{Field: f.name, Message: "must be an RFC 3339 time"}
			}
			*f.dst = t
		}
	}
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return eq, &tenant.ValidationError{Field: "before", Message: "must be an event sequence number"}
		}
		eq.Before = n
	}
	limit, err := queryLimit(r, 100, 1000)
	eq.Limit = limit
	return eq, err
}

// listAudit is the platform-wide audit trail: every change, newest first,
// filterable by tenant, actor, event type and time.
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	eq, err := auditQuery(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	res := sdk.Resource{Type: "event"}
	if ref := r.URL.Query().Get("tenant_id"); ref != "" {
		t, err := s.Tenants.Get(r.Context(), ref)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		res.TenantID = t.ID
	} else if p, ok := sdk.PrincipalFrom(r.Context()); ok && p.TenantID != "" {
		// Tenant-scoped callers see their own tenant's trail.
		res.TenantID = p.TenantID
	}
	if !s.authorize(w, r, sdk.ActionEventsRead, res) {
		return
	}
	if res.TenantID != "" {
		eq.TenantIDs = []string{res.TenantID}
	}
	s.writeAudit(w, r, eq)
}

func (s *Server) listTenantAudit(w http.ResponseWriter, r *http.Request) {
	eq, err := auditQuery(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionEventsRead)
	if !ok {
		return
	}
	eq.TenantIDs = []string{t.ID}
	s.writeAudit(w, r, eq)
}

func (s *Server) writeAudit(w http.ResponseWriter, r *http.Request, eq store.EventQuery) {
	items, err := s.Store.QueryEvents(r.Context(), eq)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	resp := map[string]any{"items": nonNil(items)}
	if len(items) == eq.Limit {
		resp["next"] = strconv.FormatInt(items[len(items)-1].Seq, 10)
	}
	writeJSON(w, http.StatusOK, resp)
}
