package api

import (
	"errors"
	"net/http"
	"slices"

	"github.com/AimTune/tenarium/internal/certs"
	"github.com/AimTune/tenarium/internal/store"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionDomainsRead)
	if !ok {
		return
	}
	ds, err := s.Tenants.ListDomains(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(ds)})
}

func (s *Server) addDomain(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hostname string `json:"hostname"`
	}
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionDomainsWrite)
	if !ok {
		return
	}
	d, err := s.Tenants.AddDomain(r.Context(), t.ID, in.Hostname)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"domain": d,
		"instructions": map[string]string{
			"type": "TXT", "name": "_tenarium-challenge." + d.Hostname, "value": d.Token,
		},
	})
}

func (s *Server) verifyDomain(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionDomainsWrite)
	if !ok {
		return
	}
	d, err := s.Tenants.VerifyDomain(r.Context(), t.ID, r.PathValue("hostname"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) removeDomain(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionDomainsWrite)
	if !ok {
		return
	}
	if err := s.Tenants.RemoveDomain(r.Context(), t.ID, r.PathValue("hostname")); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// resolveDomain maps a hostname to its tenant, for application gateways and
// middleware. Platform-level callers only.
func (s *Server) resolveDomain(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionDomainsRead, sdk.Resource{Type: "domain"}) {
		return
	}
	host := r.URL.Query().Get("host")
	t, err := s.Tenants.ResolveDomain(r.Context(), host)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	resp := map[string]string{"tenant_id": t.ID, "slug": t.Slug, "hostname": host}
	if t.Region != "" {
		resp["region"] = t.Region
	}
	writeJSON(w, http.StatusOK, resp)
}

// checkDomain answers Caddy's on-demand TLS "ask": 200 if a certificate may
// be issued for the domain (verified and its tenant live), 404 otherwise.
// It is unauthenticated and reveals nothing else.
func (s *Server) checkDomain(w http.ResponseWriter, r *http.Request) {
	if _, err := s.Tenants.ResolveDomain(r.Context(), r.URL.Query().Get("domain")); err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// domainCertificate reports the managed certificate of a tenant's domain.
func (s *Server) domainCertificate(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionDomainsRead)
	if !ok {
		return
	}
	if s.Certs == nil {
		writeError(w, http.StatusNotFound, "not_found", "managed certificates are not enabled", "")
		return
	}
	ds, err := s.Tenants.ListDomains(r.Context(), t.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	host := r.PathValue("hostname")
	if !slices.ContainsFunc(ds, func(d store.Domain) bool { return d.Hostname == host }) {
		s.writeErr(w, r, store.ErrNotFound)
		return
	}
	st, err := s.Certs.Status(r.Context(), host)
	if errors.Is(err, certs.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"hostname": host, "issued": false})
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hostname": host, "issued": true, "certificate": st})
}
