// Package guard is an example plugin meant to run out of process. It uses
// every extension point that crosses the process boundary:
//
//   - a hook rejecting slugs with a forbidden prefix,
//   - a subscription counting tenant events,
//   - a no-op provisioner that records what it provisioned,
//   - an authorizer that denies deletes to non-admins,
//   - a route reporting the counters.
package guard

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/AimTune/tenarium/pkg/sdk"
)

type Config struct {
	ForbiddenPrefix string `json:"forbidden_prefix"`
}

type Plugin struct {
	cfg Config

	mu          sync.Mutex
	events      map[string]int
	provisioned []string
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "guard", Name: "Guard (example)", Version: "1.0.0", Description: "Example external plugin."}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if p.cfg.ForbiddenPrefix == "" {
		p.cfg.ForbiddenPrefix = "test-"
	}
	p.events = map[string]int{}
	r.Hook(sdk.HookBeforeTenantCreate, func(_ context.Context, req *sdk.HookRequest) error {
		if strings.HasPrefix(req.Tenant.Slug, p.cfg.ForbiddenPrefix) {
			return sdk.Reject("slugs starting with %q are not allowed", p.cfg.ForbiddenPrefix)
		}
		if req.Tenant.Labels == nil {
			req.Tenant.Labels = map[string]string{}
		}
		req.Tenant.Labels["guarded"] = "true"
		return nil
	})
	r.Subscribe("count", sdk.EventFilter{Types: []string{"tenant.*"}}, func(_ context.Context, e sdk.Event) error {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.events[e.Type]++
		return nil
	})
	r.Provisioner(provisioner{p})
	r.Authorizer(authorizer{})
	r.Route("GET /stats", http.HandlerFunc(p.stats))
	return nil
}

func (p *Plugin) stats(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	caller := ""
	if pr, ok := sdk.PrincipalFrom(r.Context()); ok {
		caller = pr.Subject
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"events": p.events, "provisioned": p.provisioned, "caller": caller})
}

type provisioner struct{ p *Plugin }

func (provisioner) Name() string { return "noop" }

func (pr provisioner) Provision(_ context.Context, t sdk.Tenant) error {
	pr.p.mu.Lock()
	defer pr.p.mu.Unlock()
	if !slices.Contains(pr.p.provisioned, t.Slug) {
		pr.p.provisioned = append(pr.p.provisioned, t.Slug)
	}
	return nil
}

func (provisioner) Deprovision(context.Context, sdk.Tenant) error { return nil }

type authorizer struct{}

func (authorizer) Name() string { return "no-delete" }

func (authorizer) Authorize(_ context.Context, p *sdk.Principal, action sdk.Action, _ sdk.Resource) (sdk.Decision, error) {
	if action == sdk.ActionTenantsDelete && !slices.Contains(p.Roles, "admin") {
		return sdk.Deny, nil
	}
	return sdk.Allow, nil
}
