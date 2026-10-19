package rls

import (
	"context"
	"errors"
	"fmt"

	"github.com/AimTune/tenarium/pkg/tenantmw"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrNoTenant is returned when no tenant is given or found in the context.
// The helpers refuse to run instead of running without a tenant, which
// would silently see no rows.
var ErrNoTenant = errors.New("rls: no tenant")

// Beginner starts transactions: *pgxpool.Pool, *pgx.Conn and pgx.Tx
// (nested transactions become savepoints).
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Execer runs a statement: pgx.Tx, *pgx.Conn, *pgxpool.Conn.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Scope configures the runtime helpers. The zero value uses
// DefaultSetting and default transaction options.
type Scope struct {
	// Setting is the configuration parameter the policies read (default
	// "app.tenant_id").
	Setting string
	// TxOptions apply when the database supports BeginTx (pools and
	// connections; not nested transactions).
	TxOptions pgx.TxOptions
}

func (s Scope) setting() string {
	if s.Setting == "" {
		return DefaultSetting
	}
	return s.Setting
}

// WithTenant runs fn in a transaction whose tenant is tenantID. The tenant
// is set with set_config(setting, tenantID, true): transaction-local, so it
// ends with COMMIT or ROLLBACK and the connection returns to the pool
// clean. That makes it safe with pgxpool and with PgBouncer in transaction
// mode. fn's error rolls the transaction back; nil commits it.
func WithTenant(ctx context.Context, db Beginner, tenantID string, fn func(pgx.Tx) error) error {
	return Scope{}.WithTenant(ctx, db, tenantID, fn)
}

// WithTenant is the package level WithTenant with s's settings.
func (s Scope) WithTenant(ctx context.Context, db Beginner, tenantID string, fn func(pgx.Tx) error) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	run := func(tx pgx.Tx) error {
		if err := s.SetTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		return fn(tx)
	}
	if txb, ok := db.(interface {
		BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	}); ok {
		return pgx.BeginTxFunc(ctx, txb, s.TxOptions, run)
	}
	return pgx.BeginFunc(ctx, db, run)
}

// SetTenant sets the tenant for the rest of the current transaction. Call
// it inside a transaction: outside one, the setting ends with the
// statement and has no effect.
func SetTenant(ctx context.Context, tx Execer, tenantID string) error {
	return Scope{}.SetTenant(ctx, tx, tenantID)
}

// SetTenant is the package level SetTenant with s's settings.
func (s Scope) SetTenant(ctx context.Context, tx Execer, tenantID string) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	if _, err := tx.Exec(ctx, "SELECT set_config($1, $2, true)", s.setting(), tenantID); err != nil {
		return fmt.Errorf("rls: set tenant: %w", err)
	}
	return nil
}

// WithRequestTenant is WithTenant for the tenant in ctx: one stored with
// NewContext, else the tenant tenantmw.Middleware resolved for the HTTP
// request. It returns ErrNoTenant when there is none.
func WithRequestTenant(ctx context.Context, db Beginner, fn func(pgx.Tx) error) error {
	return Scope{}.WithRequestTenant(ctx, db, fn)
}

// WithRequestTenant is the package level WithRequestTenant with s's
// settings.
func (s Scope) WithRequestTenant(ctx context.Context, db Beginner, fn func(pgx.Tx) error) error {
	id, ok := TenantFromContext(ctx)
	if !ok {
		return ErrNoTenant
	}
	return s.WithTenant(ctx, db, id, fn)
}

type ctxKey struct{}

// NewContext returns a copy of ctx carrying tenantID for WithRequestTenant
// and the pool hooks. It takes precedence over a tenantmw tenant.
func NewContext(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, ctxKey{}, tenantID)
}

// TenantFromContext returns the tenant ID stored by NewContext, else the ID
// of the tenant stored by tenantmw.Middleware.
func TenantFromContext(ctx context.Context) (string, bool) {
	if id, ok := ctx.Value(ctxKey{}).(string); ok && id != "" {
		return id, true
	}
	if t := tenantmw.FromContext(ctx); t != nil && t.ID != "" {
		return t.ID, true
	}
	return "", false
}
