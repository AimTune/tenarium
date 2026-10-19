package plugin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// AuthorizeFunc is the core authorization decision.
type AuthorizeFunc func(ctx context.Context, p *sdk.Principal, action sdk.Action, res sdk.Resource) error

// StoreHost implements sdk.Host on top of a store. Authz is set once the
// authorization engine exists (it depends on plugins loaded with this host).
type StoreHost struct {
	Store store.Store
	Authz AuthorizeFunc
	// Actions performs state changes; set once the tenant service exists.
	Actions TenantActions
}

var _ sdk.Host = (*StoreHost)(nil)

func (h *StoreHost) GetUser(ctx context.Context, idOrEmail string) (sdk.User, error) {
	if strings.Contains(idOrEmail, "@") {
		return h.Store.GetUserByEmail(ctx, idOrEmail)
	}
	return h.Store.GetUser(ctx, idOrEmail)
}

func (h *StoreHost) Authorize(ctx context.Context, action sdk.Action, res sdk.Resource) error {
	p, ok := sdk.PrincipalFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: no caller in context", sdk.ErrForbidden)
	}
	if h.Authz == nil {
		return fmt.Errorf("%w: authorization not ready", sdk.ErrForbidden)
	}
	return h.Authz(ctx, p, action, res)
}

func (h StoreHost) GetTenant(ctx context.Context, idOrSlug string) (sdk.Tenant, error) {
	if _, err := uuid.Parse(idOrSlug); err == nil {
		return h.Store.GetTenant(ctx, idOrSlug)
	}
	return h.Store.GetTenantBySlug(ctx, idOrSlug)
}

func (h StoreHost) ListTenants(ctx context.Context, after string, limit int) ([]sdk.Tenant, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	return h.Store.ListTenants(ctx, store.ListTenantsQuery{After: after, Limit: limit})
}

func (h StoreHost) GetPlan(ctx context.Context, id string) (sdk.Plan, error) {
	return h.Store.GetPlan(ctx, id)
}

func (h StoreHost) Entitlements(ctx context.Context, tenantID string) (sdk.Entitlements, error) {
	t, err := h.GetTenant(ctx, tenantID)
	if err != nil {
		return sdk.Entitlements{}, err
	}
	return store.ResolveEntitlements(ctx, h.Store, t)
}

// TenantActions are the state-changing operations plugins may perform
// through sdk.Host; *tenant.Service implements them.
type TenantActions interface {
	Suspend(ctx context.Context, idOrSlug, reason string) (sdk.Tenant, error)
	Resume(ctx context.Context, idOrSlug string) (sdk.Tenant, error)
	SetPlan(ctx context.Context, idOrSlug, plan string) (sdk.Tenant, error)
	RecordUsageValue(ctx context.Context, idOrSlug, metric string, delta int64) (int64, error)
}

var errHostNotReady = errors.New("host actions are not available yet")

func (h *StoreHost) actions() (TenantActions, error) {
	if h.Actions == nil {
		return nil, errHostNotReady
	}
	return h.Actions, nil
}

func (h *StoreHost) SuspendTenant(ctx context.Context, idOrSlug, reason string) (sdk.Tenant, error) {
	a, err := h.actions()
	if err != nil {
		return sdk.Tenant{}, err
	}
	return a.Suspend(ctx, idOrSlug, reason)
}

func (h *StoreHost) ResumeTenant(ctx context.Context, idOrSlug string) (sdk.Tenant, error) {
	a, err := h.actions()
	if err != nil {
		return sdk.Tenant{}, err
	}
	return a.Resume(ctx, idOrSlug)
}

func (h *StoreHost) SetTenantPlan(ctx context.Context, idOrSlug, plan string) (sdk.Tenant, error) {
	a, err := h.actions()
	if err != nil {
		return sdk.Tenant{}, err
	}
	return a.SetPlan(ctx, idOrSlug, plan)
}

func (h *StoreHost) RecordUsage(ctx context.Context, idOrSlug, metric string, delta int64) (int64, error) {
	a, err := h.actions()
	if err != nil {
		return 0, err
	}
	return a.RecordUsageValue(ctx, idOrSlug, metric, delta)
}

// pluginHost is the Host handed to one plugin instance: writes run as the
// plugin, so events record "plugin:<instance>" as their actor.
type pluginHost struct {
	sdk.Host
	instance string
}

func (h pluginHost) as(ctx context.Context) context.Context {
	return sdk.WithPrincipal(ctx, &sdk.Principal{Subject: h.instance, Kind: "service", Authenticator: "plugin"})
}

func (h pluginHost) SuspendTenant(ctx context.Context, idOrSlug, reason string) (sdk.Tenant, error) {
	return h.Host.SuspendTenant(h.as(ctx), idOrSlug, reason)
}

func (h pluginHost) ResumeTenant(ctx context.Context, idOrSlug string) (sdk.Tenant, error) {
	return h.Host.ResumeTenant(h.as(ctx), idOrSlug)
}

func (h pluginHost) SetTenantPlan(ctx context.Context, idOrSlug, plan string) (sdk.Tenant, error) {
	return h.Host.SetTenantPlan(h.as(ctx), idOrSlug, plan)
}

func (h pluginHost) RecordUsage(ctx context.Context, idOrSlug, metric string, delta int64) (int64, error) {
	return h.Host.RecordUsage(h.as(ctx), idOrSlug, metric, delta)
}
