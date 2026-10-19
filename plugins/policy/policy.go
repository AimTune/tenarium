// Package policy enforces simple tenant rules through synchronous hooks. It
// doubles as the reference example for hooks and plugin HTTP routes.
package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sync/atomic"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("policy", func() sdk.Plugin { return &Plugin{} })
}

type Config struct {
	// ReservedSlugs cannot be used by tenants (e.g. "www", "admin").
	ReservedSlugs []string `json:"reserved_slugs"`
	// AllowedPlans restricts Tenant.Plan; empty allows any.
	AllowedPlans []string `json:"allowed_plans"`
	// DefaultPlan is applied on create when no plan is given.
	DefaultPlan string `json:"default_plan"`
	// DefaultLabels are added on create unless already present.
	DefaultLabels map[string]string `json:"default_labels"`
	// RequiredLabels must be present on create and update.
	RequiredLabels []string `json:"required_labels"`
}

type Plugin struct {
	cfg Config
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:          "policy",
		Name:        "Tenant Policy",
		Version:     "0.1.0",
		Description: "Reserved slugs, plan allow-list, default and required labels.",
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	// Defaults first, so validation below sees them.
	r.Hook(sdk.HookBeforeTenantCreate, p.applyDefaults, sdk.WithPriority(-100))
	r.Hook(sdk.HookBeforeTenantCreate, p.validate)
	r.Hook(sdk.HookBeforeTenantUpdate, p.validate)
	r.Route("GET /rules", http.HandlerFunc(p.rules))
	return nil
}

// Reconfigure applies all rules without a restart; the hooks and the
// /rules route stay registered and use the new rules immediately.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	p.next.Store(n)
	return nil
}

func (p *Plugin) applyDefaults(ctx context.Context, req *sdk.HookRequest) error {
	if n := p.next.Load(); n != nil {
		return n.applyDefaults(ctx, req)
	}
	t := req.Tenant
	if t.Plan == "" {
		t.Plan = p.cfg.DefaultPlan
	}
	for k, v := range p.cfg.DefaultLabels {
		if t.Labels == nil {
			t.Labels = map[string]string{}
		}
		if _, ok := t.Labels[k]; !ok {
			t.Labels[k] = v
		}
	}
	return nil
}

func (p *Plugin) validate(ctx context.Context, req *sdk.HookRequest) error {
	if n := p.next.Load(); n != nil {
		return n.validate(ctx, req)
	}
	t := req.Tenant
	if req.Point == sdk.HookBeforeTenantCreate && slices.Contains(p.cfg.ReservedSlugs, t.Slug) {
		return sdk.Reject("slug %q is reserved", t.Slug)
	}
	if len(p.cfg.AllowedPlans) > 0 && !slices.Contains(p.cfg.AllowedPlans, t.Plan) {
		return sdk.Reject("plan %q is not allowed", t.Plan)
	}
	for _, k := range p.cfg.RequiredLabels {
		if _, ok := t.Labels[k]; !ok {
			return sdk.Reject("label %q is required", k)
		}
	}
	return nil
}

func (p *Plugin) rules(w http.ResponseWriter, r *http.Request) {
	if n := p.next.Load(); n != nil {
		n.rules(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p.cfg)
}
