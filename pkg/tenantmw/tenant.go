// Package tenantmw lets a SaaS application served by Tenarium resolve the
// tenant of each HTTP request and enforce its status, features and limits.
//
// A Resolver finds a tenant reference in the request (subdomain, header,
// path prefix, custom domain or the tid claim of a Tenarium access token).
// A Source loads the tenant's state, from the Redis cache maintained by
// Tenarium's redis plugin (RedisSource) or from the REST API (APISource),
// usually wrapped in a CachingSource. Middleware combines both, rejects
// unknown and inactive tenants and stores the *Tenant in the request
// context:
//
//	resolver := tenantmw.NewResolver(
//		tenantmw.FromToken(verifier),
//		tenantmw.FromSubdomain("app.example.com"),
//	)
//	source := tenantmw.CachingSource(tenantmw.RedisSource(rdb, ""), 30*time.Second)
//	handler := tenantmw.Middleware(resolver, source, tenantmw.Options{})(mux)
//
//	func serve(w http.ResponseWriter, r *http.Request) {
//		t := tenantmw.FromContext(r.Context())
//		if t.HasFeature("sso") { ... }
//	}
package tenantmw

import (
	"context"
	"errors"
)

// Status is a tenant lifecycle status.
type Status string

const (
	StatusProvisioning Status = "provisioning"
	StatusActive       Status = "active"
	StatusSuspended    Status = "suspended"
	StatusFailed       Status = "failed"
	StatusDeleting     Status = "deleting"
	StatusDeleted      Status = "deleted"
)

// Tenant is the state of a tenant as seen by the application. Features and
// Limits are the effective entitlements (plan plus tenant overrides).
// Values handed out by sources may be shared between requests: treat them
// as read-only.
type Tenant struct {
	ID       string            `json:"id"`
	Slug     string            `json:"slug"`
	Name     string            `json:"name,omitempty"`
	Status   Status            `json:"status"`
	Plan     string            `json:"plan,omitempty"`
	ParentID string            `json:"parent_id,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Features map[string]bool   `json:"features,omitempty"`
	Limits   map[string]int64  `json:"limits,omitempty"`
	Version  int64             `json:"version,omitempty"`
}

// HasFeature reports whether feature is enabled for the tenant.
func (t *Tenant) HasFeature(feature string) bool {
	return t != nil && t.Features[feature]
}

// Limit returns the limit for metric and whether one is set. An absent
// limit means unlimited.
func (t *Tenant) Limit(metric string) (int64, bool) {
	if t == nil {
		return 0, false
	}
	v, ok := t.Limits[metric]
	return v, ok
}

// Errors reported by resolvers, sources and the middleware.
var (
	// ErrNoTenant means no resolver source found a tenant in the request.
	ErrNoTenant = errors.New("tenantmw: no tenant in request")
	// ErrNotFound means the tenant does not exist (or is not cached).
	ErrNotFound = errors.New("tenantmw: tenant not found")
	// ErrInactive means the tenant's status is not allowed.
	ErrInactive = errors.New("tenantmw: tenant is not active")
	// ErrTenantMismatch means the access token belongs to another tenant
	// than the one addressed by the request.
	ErrTenantMismatch = errors.New("tenantmw: token tenant does not match request tenant")
	// ErrInvalidToken means a Tenarium access token failed verification.
	ErrInvalidToken = errors.New("tenantmw: invalid access token")
	// ErrFeatureDisabled is reported by RequireFeature.
	ErrFeatureDisabled = errors.New("tenantmw: feature not enabled for tenant")
	// ErrQuotaExceeded means recording usage would exceed the tenant's limit.
	ErrQuotaExceeded = errors.New("tenantmw: quota exceeded")
)

type ctxKey int

const (
	tenantKey ctxKey = iota
	claimsKey
)

// NewContext returns a copy of ctx carrying t.
func NewContext(ctx context.Context, t *Tenant) context.Context {
	return context.WithValue(ctx, tenantKey, t)
}

// FromContext returns the tenant stored by Middleware, or nil.
func FromContext(ctx context.Context) *Tenant {
	t, _ := ctx.Value(tenantKey).(*Tenant)
	return t
}

// ClaimsFromContext returns the verified access token claims stored by
// Middleware when the request carried a Tenarium token, or nil.
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}
