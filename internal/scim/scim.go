// Package scim implements a SCIM 2.0 service provider (RFC 7643/7644) per
// tenant, so a customer's identity provider (Okta, Entra ID, ...) can push
// its people into the tenant. A SCIM User is a membership of the tenant; a
// SCIM Group is a tenant role, so group membership in the identity provider
// decides the member's role.
package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

const (
	schemaUser     = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup    = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaList     = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError    = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaPatch    = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaSPConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	maxBody        = 1 << 20
)

// Handler serves SCIM for the tenant given by the caller; authentication
// and authorization happen before (members:read / members:write).
type Handler struct {
	Tenants *tenant.Service
}

// Error is a SCIM error response.
type Error struct {
	Status   int
	ScimType string
	Detail   string
}

func (e *Error) Error() string { return e.Detail }

func badRequest(scimType, format string, args ...any) *Error {
	return &Error{Status: http.StatusBadRequest, ScimType: scimType, Detail: fmt.Sprintf(format, args...)}
}

// WriteError answers err in SCIM format, mapping domain errors.
func WriteError(w http.ResponseWriter, err error) {
	var (
		se *Error
		ve *tenant.ValidationError
		qe *tenant.QuotaError
	)
	switch {
	case errors.As(err, &se):
	case errors.As(err, &ve):
		se = badRequest("invalidValue", "%s: %s", ve.Field, ve.Message)
	case errors.As(err, &qe):
		se = &Error{Status: http.StatusForbidden, Detail: qe.Error()}
	case errors.Is(err, store.ErrNotFound):
		se = &Error{Status: http.StatusNotFound, Detail: "resource not found"}
	case errors.Is(err, store.ErrAlreadyExists):
		se = &Error{Status: http.StatusConflict, ScimType: "uniqueness", Detail: err.Error()}
	case errors.Is(err, tenant.ErrForeignIdentity), errors.Is(err, sdk.ErrForbidden):
		se = &Error{Status: http.StatusForbidden, Detail: err.Error()}
	case errors.Is(err, tenant.ErrInvalidTransition):
		se = &Error{Status: http.StatusConflict, Detail: err.Error()}
	default:
		if re, ok := sdk.IsReject(err); ok {
			se = &Error{Status: http.StatusForbidden, Detail: re.Reason}
		} else {
			se = &Error{Status: http.StatusInternalServerError, Detail: "internal error"}
		}
	}
	body := map[string]any{"schemas": []string{schemaError}, "status": strconv.Itoa(se.Status), "detail": se.Detail}
	if se.ScimType != "" {
		body["scimType"] = se.ScimType
	}
	write(w, se.Status, body)
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBody))
	if err := dec.Decode(v); err != nil {
		return badRequest("invalidSyntax", "invalid JSON: %v", err)
	}
	return nil
}

func base(r *http.Request, t sdk.Tenant) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/v1/tenants/" + t.ID + "/scim/v2"
}

// --- discovery -------------------------------------------------------------

func (h *Handler) ServiceProviderConfig(w http.ResponseWriter, _ *http.Request, _ sdk.Tenant) {
	write(w, http.StatusOK, map[string]any{
		"schemas":        []string{schemaSPConfig},
		"patch":          map[string]bool{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": 200},
		"changePassword": map[string]bool{"supported": false},
		"sort":           map[string]bool{"supported": false},
		"etag":           map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "Bearer token",
			"description": "A tenant API key (tnr_...) with members:read and members:write.",
		}},
	})
}

func (h *Handler) ResourceTypes(w http.ResponseWriter, r *http.Request, t sdk.Tenant) {
	b := base(r, t)
	write(w, http.StatusOK, listResponse([]any{
		map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User",
			"endpoint": "/Users", "schema": schemaUser, "meta": map[string]string{"resourceType": "ResourceType", "location": b + "/ResourceTypes/User"}},
		map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group",
			"endpoint": "/Groups", "schema": schemaGroup, "meta": map[string]string{"resourceType": "ResourceType", "location": b + "/ResourceTypes/Group"}},
	}, 1, 2))
}

func (h *Handler) Schemas(w http.ResponseWriter, _ *http.Request, _ sdk.Tenant) {
	attr := func(name, typ string, multi, required bool) map[string]any {
		return map[string]any{"name": name, "type": typ, "multiValued": multi, "required": required,
			"mutability": "readWrite", "returned": "default", "uniqueness": "none", "caseExact": false}
	}
	write(w, http.StatusOK, listResponse([]any{
		map[string]any{"id": schemaUser, "name": "User", "attributes": []any{
			attr("userName", "string", false, true), attr("name", "complex", false, false), attr("displayName", "string", false, false),
			attr("emails", "complex", true, false), attr("active", "boolean", false, false), attr("roles", "complex", true, false),
		}},
		map[string]any{"id": schemaGroup, "name": "Group", "attributes": []any{
			attr("displayName", "string", false, true), attr("members", "complex", true, false),
		}},
	}, 1, 2))
}

func listResponse(items []any, start, total int) map[string]any {
	return map[string]any{"schemas": []string{schemaList}, "totalResults": total, "startIndex": start,
		"itemsPerPage": len(items), "Resources": items}
}

// page applies SCIM's 1-based startIndex and count.
func page[T any](r *http.Request, all []T) ([]T, int, error) {
	q := r.URL.Query()
	start, count := 1, 100
	if v := q.Get("startIndex"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, 0, badRequest("invalidValue", "startIndex must be a number")
		}
		start = max(n, 1)
	}
	if v := q.Get("count"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, 0, badRequest("invalidValue", "count must be a number")
		}
		count = min(max(n, 0), 200)
	}
	if start > len(all) {
		return nil, start, nil
	}
	return all[start-1 : min(start-1+count, len(all))], start, nil
}

// filter parses the simple filters identity providers send:
// `attr eq "value"`. Anything else is refused.
func filter(r *http.Request) (attr, value string, err error) {
	f := strings.TrimSpace(r.URL.Query().Get("filter"))
	if f == "" {
		return "", "", nil
	}
	parts := strings.SplitN(f, " ", 3)
	if len(parts) != 3 || !strings.EqualFold(parts[1], "eq") {
		return "", "", badRequest("invalidFilter", "only `attribute eq \"value\"` filters are supported")
	}
	v, uerr := strconv.Unquote(parts[2])
	if uerr != nil {
		return "", "", badRequest("invalidFilter", "the value must be a quoted string")
	}
	return strings.ToLower(parts[0]), v, nil
}

func meta(resourceType, location string, created, modified time.Time, version int64) map[string]any {
	m := map[string]any{"resourceType": resourceType, "location": location,
		"created": created.UTC().Format(time.RFC3339), "lastModified": modified.UTC().Format(time.RFC3339)}
	if version > 0 {
		m["version"] = fmt.Sprintf(`W/"%d"`, version)
	}
	return m
}
