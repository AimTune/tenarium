package vault

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// TenantInfo is the response of GET /tenants/{tenant}. It carries no
// secrets: an AppRole role_id alone does not authenticate.
type TenantInfo struct {
	Address   string       `json:"address"`
	Namespace string       `json:"namespace,omitempty"`
	KVMount   string       `json:"kv_mount"`
	KVPath    string       `json:"kv_path"`
	Policy    string       `json:"policy"`
	AppRole   *AppRoleInfo `json:"approle,omitempty"`
	Transit   *TransitInfo `json:"transit,omitempty"`
	// Provisioned is false when the KV path is not marked for the tenant.
	Provisioned bool `json:"provisioned"`
}

type AppRoleInfo struct {
	Mount string `json:"mount"`
	Role  string `json:"role"`
	// RoleID is set once the role exists.
	RoleID string `json:"role_id,omitempty"`
}

type TransitInfo struct {
	Mount string `json:"mount"`
	Key   string `json:"key"`
}

// SecretIDResponse is the response of POST /tenants/{tenant}/secret-id.
type SecretIDResponse struct {
	RoleID           string `json:"role_id"`
	SecretID         string `json:"secret_id"`
	SecretIDAccessor string `json:"secret_id_accessor"`
	// SecretIDTTL is in seconds; 0 means it does not expire.
	SecretIDTTL int64 `json:"secret_id_ttl"`
}

// authorizedTenant resolves {tenant} and checks read access, answering 404
// rather than 403 so callers cannot probe other tenants' slugs. It returns
// false after writing an error response.
func (p *Plugin) authorizedTenant(w http.ResponseWriter, r *http.Request) (sdk.Tenant, bool) {
	t, err := p.host.GetTenant(r.Context(), r.PathValue("tenant"))
	if errors.Is(err, sdk.ErrNotFound) {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return t, false
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return t, false
	}
	res := sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
	if err := p.host.Authorize(r.Context(), sdk.ActionTenantsRead, res); err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return t, false
	}
	return t, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (p *Plugin) serveTenant(w http.ResponseWriter, r *http.Request) {
	t, ok := p.authorizedTenant(w, r)
	if !ok {
		return
	}
	tg, err := p.target(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info := TenantInfo{
		Address: p.cfg.Address, Namespace: p.cfg.Namespace,
		KVMount: p.cfg.KV.Mount, KVPath: tg.Prefix, Policy: tg.Policy,
	}
	m, err := p.ownedMarker(r.Context(), t, tg)
	if err != nil && !errors.Is(err, errNotProvisioned) {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	info.Provisioned = err == nil
	if tg.Role != "" {
		info.AppRole = &AppRoleInfo{Mount: p.cfg.AppRole.Mount, Role: tg.Role}
		// Only read the role_id of a role recorded for this tenant.
		if m != nil && m.Role == p.roleRef(tg) {
			id, err := p.roleID(r, tg)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			info.AppRole.RoleID = id
		}
	}
	if tg.Key != "" {
		info.Transit = &TransitInfo{Mount: p.cfg.Transit.Mount, Key: tg.Key}
	}
	writeJSON(w, info)
}

// roleID returns the role's role_id, or "" if the role does not exist.
func (p *Plugin) roleID(r *http.Request, tg target) (string, error) {
	var out struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	if _, err := p.exists(r.Context(), p.rolePath(p.roleRef(tg))+"/role-id", &out); err != nil {
		return "", err
	}
	return out.Data.RoleID, nil
}

// serveSecretID issues a new AppRole secret_id for the tenant's role. It
// requires tenants:update; the response must not be cached.
func (p *Plugin) serveSecretID(w http.ResponseWriter, r *http.Request) {
	t, ok := p.authorizedTenant(w, r)
	if !ok {
		return
	}
	res := sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
	if err := p.host.Authorize(r.Context(), sdk.ActionTenantsUpdate, res); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	tg, err := p.target(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Never issue credentials for a role that is not recorded as this
	// tenant's, even if one with the same name exists.
	m, err := p.ownedMarker(r.Context(), t, tg)
	if err == nil && m.Role != p.roleRef(tg) {
		err = errNotProvisioned
	}
	if errors.Is(err, errNotProvisioned) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	roleID, err := p.roleID(r, tg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if roleID == "" {
		http.Error(w, errNotProvisioned.Error(), http.StatusConflict)
		return
	}
	meta := map[string]string{metaSecretIDTenantID: t.ID}
	if pr, ok := sdk.PrincipalFrom(r.Context()); ok {
		meta[metaSecretIDIssuedBy] = pr.Authenticator + ":" + pr.Subject
	}
	metaJSON, _ := json.Marshal(meta)
	var out struct {
		Data struct {
			SecretID         string `json:"secret_id"`
			SecretIDAccessor string `json:"secret_id_accessor"`
			SecretIDTTL      int64  `json:"secret_id_ttl"`
		} `json:"data"`
	}
	err = p.client.do(r.Context(), http.MethodPost, p.rolePath(p.roleRef(tg))+"/secret-id", nil,
		map[string]string{"metadata": string(metaJSON)}, &out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, SecretIDResponse{
		RoleID: roleID, SecretID: out.Data.SecretID,
		SecretIDAccessor: out.Data.SecretIDAccessor, SecretIDTTL: out.Data.SecretIDTTL,
	})
}
