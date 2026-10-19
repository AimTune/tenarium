package api

import (
	"net/http"

	"github.com/AimTune/tenarium/internal/scim"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// scimRoute authorizes a SCIM request against the path's tenant: reads need
// members:read, writes members:write (a tenant API key with the admin role
// is the usual credential configured in the identity provider).
func (s *Server) scimRoute(action sdk.Action, fn func(*scim.Handler, http.ResponseWriter, *http.Request, sdk.Tenant)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, ok := s.loadTenant(w, r, action)
		if !ok {
			return
		}
		fn(&scim.Handler{Tenants: s.Tenants}, w, r, t)
	}
}

func (s *Server) mountSCIM(h func(pattern string, fn http.HandlerFunc)) {
	read, write := sdk.ActionMembersRead, sdk.ActionMembersWrite
	h("GET /v1/tenants/{id}/scim/v2/ServiceProviderConfig", s.scimRoute(read, (*scim.Handler).ServiceProviderConfig))
	h("GET /v1/tenants/{id}/scim/v2/ResourceTypes", s.scimRoute(read, (*scim.Handler).ResourceTypes))
	h("GET /v1/tenants/{id}/scim/v2/Schemas", s.scimRoute(read, (*scim.Handler).Schemas))
	h("GET /v1/tenants/{id}/scim/v2/Users", s.scimRoute(read, (*scim.Handler).ListUsers))
	h("POST /v1/tenants/{id}/scim/v2/Users", s.scimRoute(write, (*scim.Handler).CreateUser))
	h("GET /v1/tenants/{id}/scim/v2/Users/{user}", s.scimRoute(read, (*scim.Handler).GetUser))
	h("PUT /v1/tenants/{id}/scim/v2/Users/{user}", s.scimRoute(write, (*scim.Handler).ReplaceUser))
	h("PATCH /v1/tenants/{id}/scim/v2/Users/{user}", s.scimRoute(write, (*scim.Handler).PatchUser))
	h("DELETE /v1/tenants/{id}/scim/v2/Users/{user}", s.scimRoute(write, (*scim.Handler).DeleteUser))
	h("GET /v1/tenants/{id}/scim/v2/Groups", s.scimRoute(read, (*scim.Handler).ListGroups))
	h("POST /v1/tenants/{id}/scim/v2/Groups", s.scimRoute(write, (*scim.Handler).CreateGroup))
	h("GET /v1/tenants/{id}/scim/v2/Groups/{group}", s.scimRoute(read, (*scim.Handler).GetGroup))
	h("PUT /v1/tenants/{id}/scim/v2/Groups/{group}", s.scimRoute(write, (*scim.Handler).ReplaceGroup))
	h("PATCH /v1/tenants/{id}/scim/v2/Groups/{group}", s.scimRoute(write, (*scim.Handler).PatchGroup))
	h("DELETE /v1/tenants/{id}/scim/v2/Groups/{group}", s.scimRoute(write, (*scim.Handler).DeleteGroup))
}
