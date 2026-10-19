package sdk

import "context"

// Provisioner creates and destroys resources that belong to a tenant.
//
// When a tenant is created the core runs every provisioner's Provision in
// registration order; if any fails, the tenant moves to StatusFailed and can
// be retried. On deletion Deprovision runs in reverse order. Both methods may
// be called more than once for the same tenant and must be idempotent.
type Provisioner interface {
	// Name is unique within the plugin, e.g. "postgres-schema".
	Name() string
	Provision(ctx context.Context, t Tenant) error
	Deprovision(ctx context.Context, t Tenant) error
}
