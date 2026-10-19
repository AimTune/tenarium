// Package sdk is the stable, public contract between Tenarium and its plugins.
//
// A plugin is any value implementing Plugin. During Init it receives a
// Registrar through which it declares what it wants to take part in:
//
//   - Subscribe: asynchronous, at-least-once delivery of domain events
//     (e.g. publish tenant events to Kafka).
//   - Hook: synchronous interceptors that run before a state change and may
//     mutate or reject it (e.g. enforce slug policies).
//   - Provisioner: steps that create/destroy per-tenant resources
//     (e.g. a database schema, an S3 bucket, a Keycloak realm).
//   - Route: extra HTTP endpoints mounted under /v1/plugins/{instance}/.
//   - Authenticator: ways to authenticate API callers (OIDC, LDAP, ...).
//   - Authorizer: decisions on what an authenticated caller may do (RBAC).
//
// Built-in plugins register themselves with Register from an init function
// and are compiled into the binary (see cmd/tenarium). The same contract is
// bridged to out-of-process plugins (HTTP/JSON, any language) and WASM
// modules, so a plugin written against this package does not care how it
// is hosted.
package sdk

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

// Plugin is implemented by every extension.
type Plugin interface {
	// Manifest describes the plugin. It must be cheap and side-effect free.
	Manifest() Manifest
	// Init is called once, after configuration is loaded and before the
	// server starts accepting traffic. Returning an error aborts startup.
	Init(ctx context.Context, r Registrar) error
}

// Reconfigurer is optionally implemented by plugins that can apply a
// changed configuration without a restart (config hot reload: SIGHUP or
// POST /v1/admin/reload). decode decodes the new configuration exactly
// like Registrar.Config, after the manifest's schema accepted it.
// Returning an error keeps the old configuration. Subscriptions, hooks and
// routes registered in Init cannot change this way; settings read at run
// time (templates, thresholds, credentials, endpoints) can.
type Reconfigurer interface {
	Reconfigure(ctx context.Context, decode func(v any) error) error
}

// Stopper is optionally implemented by plugins holding resources
// (connections, goroutines) that must be released on shutdown.
type Stopper interface {
	Stop(ctx context.Context) error
}

// HealthChecker is optionally implemented by plugins that can report
// whether their dependencies are reachable. It feeds /readyz.
type HealthChecker interface {
	Health(ctx context.Context) error
}

// Manifest is the static description of a plugin.
type Manifest struct {
	// ID is a unique, URL-safe identifier such as "kafka" or "acme-billing".
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	// ConfigSchema is an optional JSON Schema (draft 2020-12) for the
	// plugin's configuration block. When set, configuration is validated
	// against it before Init and errors point at the offending field.
	ConfigSchema json.RawMessage `json:"config_schema,omitempty"`
}

// Registrar is handed to Plugin.Init. Registrations are only valid during
// Init; calling these methods afterwards panics.
type Registrar interface {
	// Config decodes this plugin's configuration block into v.
	Config(v any) error
	// Logger returns a logger scoped to the plugin.
	Logger() *slog.Logger
	// Host exposes read access to Tenarium data.
	Host() Host
	// InstanceName is the configured name of this plugin instance.
	InstanceName() string

	// Subscribe registers an asynchronous event handler. Each subscription
	// has its own durable cursor, retry policy and dead-letter queue, so a
	// slow or failing subscriber never blocks the others.
	Subscribe(name string, filter EventFilter, h EventHandler, opts ...SubscribeOption)
	// Hook registers a synchronous interceptor for the given point.
	Hook(point HookPoint, h HookHandler, opts ...HookOption)
	// Provisioner registers a tenant resource provisioner.
	Provisioner(p Provisioner)
	// Route mounts an HTTP handler under /v1/plugins/{instance}/. The pattern
	// uses net/http ServeMux syntax relative to that prefix, e.g. "GET /stats".
	// Routes sit behind authentication; the caller is in the request context.
	Route(pattern string, h http.Handler)
	// PublicRoute mounts an unauthenticated handler under
	// /v1/plugins/{instance}/public/, for callbacks from third parties
	// (e.g. Stripe webhooks). The plugin must authenticate requests itself,
	// typically by verifying a signature.
	PublicRoute(pattern string, h http.Handler)
	// Authenticator adds a way for API callers to authenticate.
	Authenticator(a Authenticator)
	// Authorizer adds an authorization policy.
	Authorizer(a Authorizer)
	// UserDirectory offers a user directory. It is used when the instance
	// is selected with users.directory in the configuration.
	UserDirectory(d UserDirectory)
	// Mailer offers an email transport. It is used when the instance is
	// selected with users.mailer, or if it is the only one.
	Mailer(m Mailer)
}

// Host is the API a plugin can use to query Tenarium.
type Host interface {
	GetTenant(ctx context.Context, idOrSlug string) (Tenant, error)
	// ListTenants pages through live tenants in creation order. Pass the last
	// ID of the previous page as after.
	ListTenants(ctx context.Context, after string, limit int) ([]Tenant, error)
	GetPlan(ctx context.Context, id string) (Plan, error)
	// Entitlements returns the tenant's effective features and limits.
	Entitlements(ctx context.Context, tenantID string) (Entitlements, error)
	// GetUser returns a user by ID or email.
	GetUser(ctx context.Context, idOrEmail string) (User, error)
	// Authorize checks whether the caller in ctx (see PrincipalFrom) may
	// perform action on res, applying the same rules as the core API:
	// tenant scope and authorizer plugins. Plugin routes that return
	// tenant-specific data must call it. It returns an error wrapping
	// ErrForbidden when denied.
	Authorize(ctx context.Context, action Action, res Resource) error

	// The following operations change state. They run hooks and emit
	// events like API calls do, with the plugin instance as the actor
	// ("plugin:<instance>").

	SuspendTenant(ctx context.Context, idOrSlug, reason string) (Tenant, error)
	ResumeTenant(ctx context.Context, idOrSlug string) (Tenant, error)
	// SetTenantPlan changes a tenant's plan.
	SetTenantPlan(ctx context.Context, idOrSlug, plan string) (Tenant, error)
	// RecordUsage adds delta to a usage metric, enforcing limits.
	RecordUsage(ctx context.Context, idOrSlug, metric string, delta int64) (int64, error)
}
