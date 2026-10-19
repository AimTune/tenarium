package api

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// keyAuthenticator accepts database-backed API keys ("tnr_...").
type keyAuthenticator struct{ tenants *tenant.Service }

func (a *keyAuthenticator) Name() string { return "key" }

func (a *keyAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*sdk.Principal, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !strings.HasPrefix(raw, tenant.APIKeyPrefix) {
		return nil, sdk.ErrNoCredentials
	}
	return a.tenants.APIKeyPrincipal(ctx, raw)
}

func apiKeyResource(tenantID string) sdk.Resource {
	return sdk.Resource{Type: "apikey", TenantID: tenantID}
}

// tenantKeys handles /v1/tenants/{id}/api-keys; platform handles /v1/api-keys.
func (s *Server) listTenantAPIKeys(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionAPIKeysRead)
	if ok {
		s.writeKeys(w, r, t.ID)
	}
}

func (s *Server) listPlatformAPIKeys(w http.ResponseWriter, r *http.Request) {
	if s.authorize(w, r, sdk.ActionAPIKeysRead, apiKeyResource("")) {
		s.writeKeys(w, r, "")
	}
}

func (s *Server) writeKeys(w http.ResponseWriter, r *http.Request, tenantRef string) {
	keys, err := s.Tenants.ListAPIKeys(r.Context(), tenantRef)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(keys)})
}

func (s *Server) createTenantAPIKey(w http.ResponseWriter, r *http.Request) {
	var in tenant.APIKeyInput
	if !decode(w, r, &in) {
		return
	}
	t, ok := s.loadTenant(w, r, sdk.ActionAPIKeysWrite)
	if !ok {
		return
	}
	// Custom roles may be granted only by callers holding all their actions.
	var custom []string
	for _, role := range in.Roles {
		if !slices.Contains(s.Tenants.MemberRoles(), role) {
			custom = append(custom, role)
		}
	}
	if len(custom) > 0 && !s.canGrant(w, r, t, s.rolePatterns(r, t, custom)) {
		return
	}
	s.createKey(w, r, t.ID, in)
}

func (s *Server) createPlatformAPIKey(w http.ResponseWriter, r *http.Request) {
	var in tenant.APIKeyInput
	if !decode(w, r, &in) {
		return
	}
	if s.authorize(w, r, sdk.ActionAPIKeysWrite, apiKeyResource("")) {
		s.createKey(w, r, "", in)
	}
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request, tenantRef string, in tenant.APIKeyInput) {
	k, err := s.Tenants.CreateAPIKey(r.Context(), tenantRef, in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, k)
}

func (s *Server) revokeTenantAPIKey(w http.ResponseWriter, r *http.Request) {
	t, ok := s.loadTenant(w, r, sdk.ActionAPIKeysWrite)
	if ok {
		s.revokeKey(w, r, t.ID)
	}
}

func (s *Server) revokePlatformAPIKey(w http.ResponseWriter, r *http.Request) {
	if s.authorize(w, r, sdk.ActionAPIKeysWrite, apiKeyResource("")) {
		s.revokeKey(w, r, "")
	}
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request, tenantRef string) {
	if err := s.Tenants.RevokeAPIKey(r.Context(), tenantRef, r.PathValue("key")); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
