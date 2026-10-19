// Package authz combines the built-in tenant-scope rule with plugin
// authorizers into a single decision.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"

	"github.com/AimTune/tenarium/internal/plugin"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// ParentFunc returns a tenant's parent ID ("" for roots).
type ParentFunc func(ctx context.Context, tenantID string) (string, error)

// maxDepth bounds ancestor walks so a corrupt hierarchy can't loop forever.
const maxDepth = 32

// UserTokenAuthenticator names the authenticator of Tenarium-issued user
// tokens.
const UserTokenAuthenticator = "core/token"

// ServiceKeyAuthenticator names the authenticator of database-backed API
// keys; they get the same role tables as user tokens.
const ServiceKeyAuthenticator = "core/key"

// RoleTable maps a role to the action patterns (path.Match globs) it grants.
type RoleTable map[string][]string

// UserRoles are the built-in role tables for users signed in with
// Tenarium tokens: platform roles for tokens without a tenant, tenant roles
// (the membership role) for tenant tokens.
type UserRoles struct {
	Platform RoleTable
	Tenant   RoleTable
}

// DefaultUserRoles grants tenant roles nothing commercial and nothing
// destructive on the tenant itself; platform admins can do everything.
func DefaultUserRoles() UserRoles {
	read := []string{"tenants:read", "members:read", "usage:read", "plans:read", "plugins:route"}
	manage := append(append([]string{}, read...),
		"tenants:update", "tenants:create", "members:write", "events:read", "apikeys:read", "apikeys:write", "domains:read", "domains:write",
		"webhooks:read", "webhooks:write", "sso:read", "sso:write", "roles:read", "roles:write",
		"groups:read", "groups:write", "data:export")
	return UserRoles{
		Platform: RoleTable{"admin": {"*"}, "viewer": {"*:read"}},
		Tenant:   RoleTable{"owner": manage, "admin": manage, "member": read, "viewer": read},
	}
}

func (e *Engine) allows(ctx context.Context, p *sdk.Principal, action sdk.Action) bool {
	table := e.userRoles.Platform
	if p.TenantID != "" {
		table = e.userRoles.Tenant
	}
	for _, role := range p.Roles {
		patterns, ok := table[role]
		if !ok && p.TenantID != "" && e.customRoles != nil {
			// A role the tenant defined itself.
			patterns, _ = e.customRoles(ctx, p.TenantID, role)
		}
		for _, pat := range patterns {
			if ok, _ := path.Match(pat, string(action)); ok {
				return true
			}
		}
	}
	return false
}

// Engine decides whether a principal may perform an action.
type Engine struct {
	authorizers []plugin.AuthorizerRef
	parentOf    ParentFunc
	userRoles   UserRoles
	log         *slog.Logger
	customRoles CustomRoleFunc
}

func New(authorizers []plugin.AuthorizerRef, parentOf ParentFunc, log *slog.Logger) *Engine {
	return &Engine{authorizers: authorizers, parentOf: parentOf, userRoles: DefaultUserRoles(), log: log}
}

// WithUserRoles replaces the built-in role tables.
func (e *Engine) WithUserRoles(r UserRoles) *Engine {
	e.userRoles = r
	return e
}

// globalReadsForScoped are actions a tenant-scoped principal may perform on
// resources that belong to no tenant. Plugin routes are reachable; a route
// returning tenant data must check it with sdk.Host.Authorize.
var globalReadsForScoped = map[sdk.Action]bool{sdk.ActionPlansRead: true, sdk.ActionPluginsRoute: true}

// platformOnly are commercial actions a tenant-scoped principal may never
// perform, even on its own tenant: changing plans, features or limits,
// recording usage (a negative delta would release quota) and purging tenants
// (skipping the deletion grace period), plus managing token signing keys.
var platformOnly = map[sdk.Action]bool{
	sdk.ActionPlansWrite: true, sdk.ActionUsageWrite: true, sdk.ActionTenantsPurge: true,
	sdk.ActionTenantsMove:     true,
	sdk.ActionSigningKeysRead: true, sdk.ActionSigningKeysWrite: true,
	sdk.ActionUsersImpersonate: true, sdk.ActionDataErase: true,
	sdk.ActionOAuthClientsRead: true, sdk.ActionOAuthClientsWrite: true,
	sdk.ActionConfigReload: true,
}

// Authorize returns nil if allowed, or an error wrapping sdk.ErrForbidden.
//
//  1. A tenant-scoped principal may only act on its own tenant and that
//     tenant's descendants (plus reading plans), and never perform
//     platform-only actions. No plugin can lift this.
//  2. With no authorizers registered, everything else is allowed.
//  3. Otherwise any Deny wins, and at least one Allow is required.
func (e *Engine) Authorize(ctx context.Context, p *sdk.Principal, action sdk.Action, res sdk.Resource) error {
	if p == nil {
		return fmt.Errorf("%w: unauthenticated", sdk.ErrForbidden)
	}
	if _, impersonated := p.Claims["impersonator"]; impersonated && impersonationDenied[action] {
		return fmt.Errorf("%w: %s is not allowed while impersonating", sdk.ErrForbidden, action)
	}
	if p.TenantID != "" {
		if platformOnly[action] {
			return fmt.Errorf("%w: %s requires a platform-level caller", sdk.ErrForbidden, action)
		}
		ok, err := e.inScope(ctx, p.TenantID, action, res)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: %s is outside the caller's tenant", sdk.ErrForbidden, action)
		}
	}
	// Users signed in with Tenarium tokens always go through the built-in
	// role tables, so a tenant "viewer" can never delete their tenant even
	// when no authorizer plugin is configured.
	userAllowed := false
	if p.Authenticator == UserTokenAuthenticator || p.Authenticator == ServiceKeyAuthenticator {
		if !e.allows(ctx, p, action) {
			return fmt.Errorf("%w: role %v may not %s", sdk.ErrForbidden, p.Roles, action)
		}
		userAllowed = true
	}
	if len(e.authorizers) == 0 {
		return nil
	}
	allowed := userAllowed
	for _, a := range e.authorizers {
		d, err := e.call(ctx, a, p, action, res)
		if err != nil {
			return fmt.Errorf("authorizer %s: %w", a.Name, err)
		}
		switch d {
		case sdk.Deny:
			return fmt.Errorf("%w: %s denied by %s", sdk.ErrForbidden, action, a.Name)
		case sdk.Allow:
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("%w: no policy allows %s", sdk.ErrForbidden, action)
	}
	return nil
}

func (e *Engine) call(ctx context.Context, a plugin.AuthorizerRef, p *sdk.Principal, action sdk.Action, res sdk.Resource) (d sdk.Decision, err error) {
	defer func() {
		if r := recover(); r != nil {
			d, err = sdk.Deny, fmt.Errorf("panic: %v", r)
		}
	}()
	return a.Authorizer.Authorize(ctx, p, action, res)
}

func (e *Engine) inScope(ctx context.Context, scopeTenant string, action sdk.Action, res sdk.Resource) (bool, error) {
	if res.TenantID == "" {
		return globalReadsForScoped[action], nil
	}
	id := res.TenantID
	for range maxDepth {
		if id == scopeTenant {
			return true, nil
		}
		parent, err := e.parentOf(ctx, id)
		if errors.Is(err, sdk.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if parent == "" {
			return false, nil
		}
		id = parent
	}
	return false, nil
}

// CustomRoleFunc returns the action patterns of a role a tenant defined.
type CustomRoleFunc func(ctx context.Context, tenantID, role string) ([]string, bool)

// WithCustomRoles resolves tenant roles missing from the built-in table.
func (e *Engine) WithCustomRoles(fn CustomRoleFunc) *Engine {
	e.customRoles = fn
	return e
}

// TenantRoleTable returns the built-in tenant roles and their patterns.
func (e *Engine) TenantRoleTable() RoleTable { return e.userRoles.Tenant }

// impersonationDenied are actions support staff may not perform while
// acting as a user: creating credentials, exporting or erasing data,
// changing identity configuration and impersonating further.
var impersonationDenied = map[sdk.Action]bool{
	sdk.ActionAPIKeysWrite: true, sdk.ActionDataExport: true, sdk.ActionDataErase: true,
	sdk.ActionSSOWrite: true, sdk.ActionUsersImpersonate: true, sdk.ActionUsersWrite: true,
	sdk.ActionSigningKeysWrite: true, sdk.ActionWebhooksWrite: true, sdk.ActionRolesWrite: true,
}
