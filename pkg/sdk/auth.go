package sdk

import (
	"context"
	"errors"
	"net/http"
)

// Principal is an authenticated caller of the Tenarium API.
type Principal struct {
	// Subject uniquely identifies the caller within its authenticator,
	// e.g. a Keycloak user ID, an LDAP DN or an API key name.
	Subject string `json:"subject"`
	// Kind is "user" or "service".
	Kind string `json:"kind"`
	// Authenticator is the name of the authenticator that produced this
	// principal; it is set by the core.
	Authenticator string `json:"authenticator"`
	// TenantID scopes the principal to a single tenant (e.g. a tenant admin
	// signing in through that tenant's IdP). Empty means platform-wide.
	TenantID string         `json:"tenant_id,omitempty"`
	Roles    []string       `json:"roles,omitempty"`
	Claims   map[string]any `json:"claims,omitempty"`
}

// ErrNoCredentials is returned by an Authenticator when the request carries
// no credentials it understands, so the next authenticator is tried.
var ErrNoCredentials = errors.New("no credentials")

// Authenticator turns request credentials into a Principal. Typical
// implementations: OIDC/JWT bearer tokens (Keycloak, Auth0, Entra ID), LDAP
// bind via Basic auth, mTLS client certificates, signed API keys.
//
// Authenticators run in registration order. Returning ErrNoCredentials
// passes to the next one; any other error rejects the request with 401.
type Authenticator interface {
	Name() string
	Authenticate(ctx context.Context, r *http.Request) (*Principal, error)
}

// Action names an API operation, "{resource}:{verb}".
type Action string

const (
	ActionTenantsCreate    Action = "tenants:create"
	ActionTenantsRead      Action = "tenants:read"
	ActionTenantsUpdate    Action = "tenants:update"
	ActionTenantsDelete    Action = "tenants:delete"
	ActionTenantsSuspend   Action = "tenants:suspend"
	ActionTenantsResume    Action = "tenants:resume"
	ActionTenantsProvision Action = "tenants:provision"
	// ActionTenantsPurge deletes a tenant immediately, skipping the deletion
	// grace period. Platform-only.
	ActionTenantsPurge Action = "tenants:purge"
	// ActionTenantsMove moves a tenant to another region. Platform-only.
	ActionTenantsMove       Action = "tenants:move"
	ActionMembersRead       Action = "members:read"
	ActionMembersWrite      Action = "members:write"
	ActionUsageRead         Action = "usage:read"
	ActionUsageWrite        Action = "usage:write"
	ActionPlansRead         Action = "plans:read"
	ActionPlansWrite        Action = "plans:write"
	ActionEventsRead        Action = "events:read"
	ActionDeadLettersRead   Action = "deadletters:read"
	ActionDeadLettersReplay Action = "deadletters:replay"
	ActionPluginsRead       Action = "plugins:read"
	// ActionPluginsRoute guards every plugin HTTP route; Resource.ID is the
	// plugin instance name.
	ActionPluginsRoute  Action = "plugins:route"
	ActionUsersRead     Action = "users:read"
	ActionUsersWrite    Action = "users:write"
	ActionAPIKeysRead   Action = "apikeys:read"
	ActionAPIKeysWrite  Action = "apikeys:write"
	ActionDomainsRead   Action = "domains:read"
	ActionDomainsWrite  Action = "domains:write"
	ActionWebhooksRead  Action = "webhooks:read"
	ActionWebhooksWrite Action = "webhooks:write"
	ActionSSORead       Action = "sso:read"
	ActionSSOWrite      Action = "sso:write"
	// Signing keys of Tenarium tokens; platform-only.
	ActionSigningKeysRead  Action = "signingkeys:read"
	ActionSigningKeysWrite Action = "signingkeys:write"
	ActionRolesRead        Action = "roles:read"
	ActionRolesWrite       Action = "roles:write"
	ActionGroupsRead       Action = "groups:read"
	ActionGroupsWrite      Action = "groups:write"
	// ActionUsersImpersonate lets support staff act as a user. Platform-only.
	ActionUsersImpersonate Action = "users:impersonate"
	// ActionDataExport and ActionDataErase cover GDPR exports and erasure.
	ActionDataExport Action = "data:export"
	ActionDataErase  Action = "data:erase"
	// OAuth clients of the OpenID provider; platform-only.
	ActionOAuthClientsRead  Action = "oauthclients:read"
	ActionOAuthClientsWrite Action = "oauthclients:write"
	// ActionConfigReload reloads the server configuration. Platform-only.
	ActionConfigReload Action = "config:reload"
)

// Actions lists every built-in action (custom roles are built from it).
func Actions() []Action {
	return []Action{
		ActionTenantsCreate, ActionTenantsRead, ActionTenantsUpdate, ActionTenantsDelete, ActionTenantsSuspend,
		ActionTenantsResume, ActionTenantsProvision, ActionTenantsPurge, ActionTenantsMove, ActionMembersRead, ActionMembersWrite,
		ActionUsageRead, ActionUsageWrite, ActionPlansRead, ActionPlansWrite, ActionEventsRead,
		ActionDeadLettersRead, ActionDeadLettersReplay, ActionPluginsRead, ActionPluginsRoute,
		ActionUsersRead, ActionUsersWrite, ActionAPIKeysRead, ActionAPIKeysWrite, ActionDomainsRead,
		ActionDomainsWrite, ActionWebhooksRead, ActionWebhooksWrite, ActionSSORead, ActionSSOWrite,
		ActionSigningKeysRead, ActionSigningKeysWrite, ActionRolesRead, ActionRolesWrite,
		ActionGroupsRead, ActionGroupsWrite, ActionUsersImpersonate, ActionDataExport, ActionDataErase,
		ActionOAuthClientsRead, ActionOAuthClientsWrite, ActionConfigReload,
	}
}

// Resource is the object an action targets.
type Resource struct {
	// Type is "tenant", "plan", "member", "event", "deadletter", "plugin"
	// or a plugin-defined type.
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
	// TenantID is the tenant the resource belongs to, if any. For a tenant
	// itself it equals ID.
	TenantID string `json:"tenant_id,omitempty"`
}

// Decision is an authorizer's verdict.
type Decision int

const (
	// Abstain means the authorizer has no opinion.
	Abstain Decision = iota
	Allow
	Deny
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	default:
		return "abstain"
	}
}

// Authorizer decides whether a principal may perform an action.
//
// The core combines all authorizers: any Deny wins, otherwise at least one
// Allow is required. With no authorizers configured every authenticated
// caller is allowed. Independently of authorizers, a tenant-scoped principal
// (Principal.TenantID set) can never touch another tenant's resources.
type Authorizer interface {
	Name() string
	Authorize(ctx context.Context, p *Principal, action Action, res Resource) (Decision, error)
}

// ErrForbidden is returned when authorization denies an action.
var ErrForbidden = errors.New("forbidden")

type principalKey struct{}

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the caller of the current request, if any. It is
// available in hooks, so a plugin can implement authorization rules (RBAC,
// tenant-scoped admins) as a hook that rejects operations.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok && p != nil
}
