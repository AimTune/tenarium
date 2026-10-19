package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/AimTune/tenarium/internal/events"
	"github.com/AimTune/tenarium/internal/metrics"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// ProvisionerRef is a provisioner together with the plugin that owns it.
type ProvisionerRef struct {
	Plugin      string
	Provisioner sdk.Provisioner
}

func (r ProvisionerRef) String() string { return r.Plugin + "/" + r.Provisioner.Name() }

// Runner executes provisioners in response to lifecycle events. It is itself
// an event subscriber, so provisioning inherits the outbox's durability: if
// the process dies mid-way, the event is redelivered and the (idempotent)
// provisioners run again.
type Runner struct {
	svc          *Service
	provisioners []ProvisionerRef
	log          *slog.Logger
	metrics      *metrics.Metrics
	// stepAttempts is how often a single Provision call is tried before the
	// tenant is marked failed.
	stepAttempts int
	stepBackoff  time.Duration
}

func NewRunner(svc *Service, provisioners []ProvisionerRef, log *slog.Logger, m *metrics.Metrics) *Runner {
	if m == nil {
		m = metrics.New()
	}
	return &Runner{svc: svc, provisioners: provisioners, log: log, metrics: m, stepAttempts: 3, stepBackoff: time.Second}
}

func (r *Runner) count(op, result string) {
	r.metrics.ProvisioningRuns.WithLabelValues(op, result).Inc()
}

// Subscription returns the core subscription that drives provisioning.
func (r *Runner) Subscription() events.Subscription {
	opts := sdk.DefaultSubscribeOptions()
	opts.Timeout = 10 * time.Minute
	return events.Subscription{
		Name: "core/provisioning",
		Filter: sdk.EventFilter{Types: []string{
			sdk.EventTenantCreated, sdk.EventTenantProvisioning, sdk.EventTenantDeleting,
			sdk.EventTenantRegionChanged, // moves with reprovisioning
		}},
		Handler: r.handle,
		Options: opts,
	}
}

func (r *Runner) handle(ctx context.Context, e sdk.Event) error {
	var data sdk.TenantEventData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return fmt.Errorf("decode event: %w", err)
	}
	// Act on current state, not the event snapshot: the event may be a
	// redelivery and the tenant may have moved on.
	t, err := r.svc.store.GetTenant(ctx, data.Tenant.ID)
	if errors.Is(err, sdk.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	switch {
	case t.Status == sdk.StatusProvisioning && e.Type != sdk.EventTenantDeleting:
		return r.provision(ctx, t)
	case t.Status == sdk.StatusDeleting && e.Type == sdk.EventTenantDeleting:
		return r.deprovision(ctx, t)
	}
	return nil
}

func (r *Runner) provision(ctx context.Context, t sdk.Tenant) error {
	log := r.log.With("tenant_id", t.ID)
	for _, p := range r.provisioners {
		err := r.retry(ctx, func() error { return p.Provisioner.Provision(ctx, t) })
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			log.Warn("provisioning failed", "provisioner", p.String(), "err", err)
			r.count("provision", "failure")
			return r.svc.markProvisioningFailed(ctx, t.ID, fmt.Sprintf("%s: %v", p, err))
		}
	}
	log.Info("tenant provisioned")
	r.count("provision", "success")
	return r.svc.markProvisioned(ctx, t.ID)
}

// deprovision runs in reverse order. A tenant is never reported deleted
// while its resources may still exist: if a step keeps failing, the tenant
// becomes "failed" with the reason, and deleting it again retries. Failing
// fast (instead of retrying forever) keeps one stuck tenant from blocking
// provisioning for everyone else.
func (r *Runner) deprovision(ctx context.Context, t sdk.Tenant) error {
	for i := len(r.provisioners) - 1; i >= 0; i-- {
		p := r.provisioners[i]
		err := r.retry(ctx, func() error { return p.Provisioner.Deprovision(ctx, t) })
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			r.log.Warn("deprovisioning failed", "tenant_id", t.ID, "provisioner", p.String(), "err", err)
			r.count("deprovision", "failure")
			return r.svc.markDeprovisioningFailed(ctx, t.ID, fmt.Sprintf("deprovisioning %s: %v; delete again to retry", p, err))
		}
	}
	r.log.Info("tenant deprovisioned", "tenant_id", t.ID)
	r.count("deprovision", "success")
	return r.svc.markDeprovisioned(ctx, t.ID)
}

func (r *Runner) retry(ctx context.Context, fn func() error) error {
	var err error
	for attempt := range r.stepAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(r.stepBackoff << (attempt - 1)):
			}
		}
		if err = fn(); err == nil {
			return nil
		}
	}
	return err
}
