package api

import (
	"net/http"

	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

var oauthClientResource = sdk.Resource{Type: "oauth_client"}

func (s *Server) listOAuthClients(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionOAuthClientsRead, oauthClientResource) {
		return
	}
	cs, err := s.Tenants.ListOAuthClients(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(cs)})
}

func (s *Server) createOAuthClient(w http.ResponseWriter, r *http.Request) {
	var in tenant.OAuthClientInput
	if !decode(w, r, &in) {
		return
	}
	if !s.authorize(w, r, sdk.ActionOAuthClientsWrite, oauthClientResource) {
		return
	}
	c, secret, err := s.Tenants.CreateOAuthClient(r.Context(), in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	out := map[string]any{"client": c}
	if secret != "" {
		out["client_secret"] = secret
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getOAuthClient(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionOAuthClientsRead, oauthClientResource) {
		return
	}
	c, err := s.Tenants.GetOAuthClient(r.Context(), r.PathValue("client"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) updateOAuthClient(w http.ResponseWriter, r *http.Request) {
	var in tenant.OAuthClientInput
	if !decode(w, r, &in) {
		return
	}
	if !s.authorize(w, r, sdk.ActionOAuthClientsWrite, oauthClientResource) {
		return
	}
	c, err := s.Tenants.UpdateOAuthClient(r.Context(), r.PathValue("client"), in)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) deleteOAuthClient(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionOAuthClientsWrite, oauthClientResource) {
		return
	}
	if err := s.Tenants.DeleteOAuthClient(r.Context(), r.PathValue("client")); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotateOAuthClientSecret(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, sdk.ActionOAuthClientsWrite, oauthClientResource) {
		return
	}
	secret, err := s.Tenants.RotateOAuthClientSecret(r.Context(), r.PathValue("client"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"client_secret": secret})
}

// mountOIDCProvider serves the OpenID provider's browser and token
// endpoints at /oauth (no API authentication; login and token requests are
// rate limited like /v1/auth).
func (s *Server) mountOIDCProvider(root *http.ServeMux, limiter *rateLimiter) {
	if s.OIDC == nil {
		return
	}
	p := s.OIDC
	root.HandleFunc("GET /oauth/authorize", routed("GET /oauth/authorize", p.Authorize))
	root.Handle("POST /oauth/login", limiter.wrap(routed("POST /oauth/login", p.Login)))
	root.HandleFunc("POST /oauth/consent", routed("POST /oauth/consent", p.Consent))
	root.Handle("POST /oauth/token", limiter.wrap(routed("POST /oauth/token", p.Token)))
	root.HandleFunc("GET /oauth/userinfo", routed("GET /oauth/userinfo", p.UserInfo))
	root.HandleFunc("POST /oauth/userinfo", routed("POST /oauth/userinfo", p.UserInfo))
	root.HandleFunc("GET /oauth/logout", routed("GET /oauth/logout", p.Logout))
}
