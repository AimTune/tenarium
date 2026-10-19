package rls

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolOptions configure ConfigurePool.
type PoolOptions struct {
	// Setting is the configuration parameter (default "app.tenant_id").
	Setting string
	// Tenant returns the tenant for an acquisition's context (default
	// TenantFromContext).
	Tenant func(ctx context.Context) (string, bool)
	// RequireTenant fails acquisitions without a tenant with ErrNoTenant
	// instead of handing out a connection without one (which sees no
	// rows of protected tables).
	RequireTenant bool
	// ResetTimeout bounds the reset on release (default 5s).
	ResetTimeout time.Duration
}

// ConfigurePool is the session-level alternative to WithTenant: every
// connection acquired from the pool gets the context's tenant with
// set_config(setting, tenant, false) in PrepareConn, and the setting is
// cleared in AfterRelease. Plain pool.Query/Exec calls are then scoped to
// the tenant in their context without an explicit transaction. Existing
// PrepareConn and AfterRelease hooks still run first. pgx ignores the
// deprecated BeforeAcquire once PrepareConn is set, so move such a hook to
// PrepareConn before calling ConfigurePool.
//
// Pitfalls, which is why WithTenant is the recommended default:
//
//   - The tenant is bound when a connection is acquired. A connection
//     held across tenants (pool.Acquire, a long transaction, a pgx.Conn
//     outside the pool) keeps the first tenant.
//   - The setting lives in the server session. Behind PgBouncer (or any
//     pooler) in transaction or statement mode, the server connection is
//     shared by other clients between transactions, and they inherit the
//     tenant. Use only with direct connections or session pooling.
//   - It costs a round trip on every acquire and another on release.
//   - Clearing on release is best effort: if it fails, the connection is
//     destroyed rather than returned to the pool.
//   - The context must carry the tenant everywhere a query runs; a
//     background context silently gets no tenant (and no rows), unless
//     RequireTenant is set.
func ConfigurePool(cfg *pgxpool.Config, o PoolOptions) {
	setting := o.Setting
	if setting == "" {
		setting = DefaultSetting
	}
	tenant := o.Tenant
	if tenant == nil {
		tenant = TenantFromContext
	}
	timeout := o.ResetTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	prev := cfg.PrepareConn
	cfg.PrepareConn = func(ctx context.Context, c *pgx.Conn) (bool, error) {
		if prev != nil {
			if ok, err := prev(ctx, c); !ok || err != nil {
				return ok, err
			}
		}
		id, ok := tenant(ctx)
		if !ok && o.RequireTenant {
			// Keep the connection; fail the query.
			return true, ErrNoTenant
		}
		// Always set: a connection must never keep a previous tenant.
		if _, err := c.Exec(ctx, "SELECT set_config($1, $2, false)", setting, id); err != nil {
			return false, err
		}
		return true, nil
	}

	prevRelease := cfg.AfterRelease
	cfg.AfterRelease = func(c *pgx.Conn) bool {
		if prevRelease != nil && !prevRelease(c) {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_, err := c.Exec(ctx, "SELECT set_config($1, '', false)", setting)
		return err == nil
	}
}
