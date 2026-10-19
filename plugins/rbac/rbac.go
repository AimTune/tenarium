// Package rbac is a role-based sdk.Authorizer. Roles come from the
// principal (set by authenticators such as oidc or ldap) or from explicit
// subject bindings in configuration, and grant action patterns:
//
//	roles:
//	  admin:    ["*"]
//	  operator: ["tenants:*", "members:*", "usage:*", "plans:read", "events:read"]
//	  viewer:   ["*:read"]
//
// Patterns use path.Match syntax against actions like "tenants:update".
package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("rbac", func() sdk.Plugin { return &Plugin{} })
}

type Config struct {
	// Roles maps a role name to the action patterns it grants.
	Roles map[string][]string `json:"roles"`
	// Bindings grant roles to specific subjects, keyed by
	// "{authenticator}:{subject}" (e.g. "core/api-key:api-key-0").
	Bindings map[string][]string `json:"bindings"`
	// TenantRoles grant extra roles to tenant-scoped principals, whose
	// reach is already limited to their own tenant subtree.
	TenantRoles []string `json:"tenant_roles"`
	// DefaultRoles apply to every authenticated principal.
	DefaultRoles []string `json:"default_roles"`
	// DenyUnknown makes the authorizer deny instead of abstain when no role
	// grants the action. Use it when rbac must be the final word even if
	// other authorizers are configured.
	DenyUnknown bool `json:"deny_unknown"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "roles": {"type": "object", "additionalProperties": {"type": "array", "items": {"type": "string"}}},
    "bindings": {"type": "object", "additionalProperties": {"type": "array", "items": {"type": "string"}}},
    "tenant_roles": {"type": "array", "items": {"type": "string"}},
    "default_roles": {"type": "array", "items": {"type": "string"}},
    "deny_unknown": {"type": "boolean"}
  },
  "required": ["roles"],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg Config
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "rbac",
		Name:         "Role-Based Access Control",
		Version:      "0.1.0",
		Description:  "Grants API actions to roles from authenticators or static bindings.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	for role, patterns := range p.cfg.Roles {
		for _, pat := range patterns {
			if _, err := path.Match(pat, ""); err != nil {
				return fmt.Errorf("role %q: bad pattern %q: %w", role, pat, err)
			}
		}
	}
	all := slices.Concat(p.cfg.TenantRoles, p.cfg.DefaultRoles)
	for _, roles := range p.cfg.Bindings {
		all = append(all, roles...)
	}
	for _, role := range all {
		if _, ok := p.cfg.Roles[role]; !ok {
			return fmt.Errorf("role %q is referenced but not defined", role)
		}
	}
	r.Authorizer(p)
	return nil
}

func (p *Plugin) Name() string { return "roles" }

func (p *Plugin) Authorize(_ context.Context, pr *sdk.Principal, action sdk.Action, _ sdk.Resource) (sdk.Decision, error) {
	for _, role := range p.rolesOf(pr) {
		for _, pat := range p.cfg.Roles[role] {
			if ok, _ := path.Match(pat, string(action)); ok {
				return sdk.Allow, nil
			}
		}
	}
	if p.cfg.DenyUnknown {
		return sdk.Deny, nil
	}
	return sdk.Abstain, nil
}

func (p *Plugin) rolesOf(pr *sdk.Principal) []string {
	roles := slices.Concat(pr.Roles, p.cfg.DefaultRoles, p.cfg.Bindings[pr.Authenticator+":"+pr.Subject])
	if pr.TenantID != "" {
		roles = append(roles, p.cfg.TenantRoles...)
	}
	return roles
}
