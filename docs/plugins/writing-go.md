# Writing Go plugins

## Skeleton

```go
package quota

import (
	"context"
	"encoding/json"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("seat-guard", func() sdk.Plugin { return &Plugin{} })
}

type Config struct {
	MaxTrialTenantsPerDomain int `json:"max_trial_tenants_per_domain"`
}

type Plugin struct {
	cfg  Config
	host sdk.Host
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:      "seat-guard",
		Name:    "Seat guard",
		Version: "1.0.0",
		// Optional: validated before Init, with errors pointing at the bad field.
		ConfigSchema: json.RawMessage(`{"type":"object","properties":{"max_trial_tenants_per_domain":{"type":"integer","minimum":1}},"additionalProperties":false}`),
	}
}

func (p *Plugin) Init(ctx context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil { // strict: unknown keys are errors
		return err
	}
	p.host = r.Host()
	r.Hook(sdk.HookBeforeMemberAdd, p.checkSeats)
	r.Subscribe("welcome", sdk.EventFilter{Types: []string{sdk.EventMemberAdded}}, p.sendWelcome,
		sdk.WithMaxAttempts(20))
	return nil
}
```

Optional interfaces:

- `sdk.Stopper`: `Stop(ctx)` on shutdown (close connections, flush buffers).
- `sdk.HealthChecker`: `Health(ctx)`, reported by `/readyz`.

## Rules of the road

- **Event handlers must be idempotent.** Delivery is at least once, so deduplicate on `e.ID`
  if a side effect must not happen twice. Return an error to retry; after `MaxAttempts` the
  event is dead-lettered.
- **Provisioners must be idempotent and tolerate unknown tenants.** `Provision` may run again
  after a crash or a retry. `Deprovision` may run for a tenant that was never provisioned (for
  example when the plugin's scope changed).
- **Hooks must be fast.** They run on the request path. Return `sdk.Reject("...")` for a business
  rule violation (the client gets 422 with your message); any other error is a 500.
- **Registrations happen only in `Init`.** Calling the registrar later panics.
- **Check access in routes.** Routes are reachable by any caller allowed `plugins:route`,
  including tenant-scoped ones. Before returning tenant data, call
  `r.Host().Authorize(ctx, sdk.ActionTenantsRead, sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID})`.
- **Use the caller.** `sdk.PrincipalFrom(ctx)` returns the API caller in hooks, routes and
  authorizers. Event handlers and provisioners run asynchronously and have no caller; use the
  event's `Actor` field instead.

## Reading data

```go
t, err := r.Host().GetTenant(ctx, "acme")               // ID or slug
ent, err := r.Host().Entitlements(ctx, t.ID)            // plan + overrides
if limit, ok := ent.Limit("projects"); ok && used >= limit { ... }
page, err := r.Host().ListTenants(ctx, afterID, 500)
```

Decode event payloads with the matching type: `sdk.TenantEventData`, `sdk.MemberEventData`,
`sdk.PlanEventData`, `sdk.UsageEventData`, `sdk.UsagePeriodData` or `sdk.UserEventData`. The
JSON Schema of every event type's data is in the [event schema registry](../event-schemas.md).
Tenant events carry `Tenant.Region`, `PlanRevision` and `AddOns`; `tenant.region_changed` has
the old region in `Previous.Region`.

## Changing state

The host can also change tenants. These calls run hooks and emit events like API calls, with
the plugin instance as the actor (`plugin:<instance>`):

```go
t, err := r.Host().SuspendTenant(ctx, tenantID, "billing: invoice overdue")
t, err = r.Host().ResumeTenant(ctx, tenantID)
t, err = r.Host().SetTenantPlan(ctx, tenantID, "pro")
value, err := r.Host().RecordUsage(ctx, tenantID, "api_calls", 1)   // enforces limits
u, err := r.Host().GetUser(ctx, "ada@acme.io")                      // ID or email
```

Billing plugins (`stripe`, `chargebee`, `paddle`) use these to drive the tenant lifecycle from
webhooks.

## Reloading configuration

A plugin can accept a changed `config` without a restart (SIGHUP or `POST /v1/admin/reload`,
see [reloading the configuration](../operations.md#reloading-the-configuration)) by implementing
the optional `sdk.Reconfigurer`:

```go
type Reconfigurer interface {
	Reconfigure(ctx context.Context, decode func(v any) error) error
}
```

`decode` decodes the new configuration exactly like `Registrar.Config`, after the manifest's
`ConfigSchema` accepted it. Returning an error keeps the old configuration and reports the
instance under `failed`. Subscriptions, hooks, routes and filters registered in `Init` cannot
change this way; settings read at run time (endpoints, credentials, templates, timeouts) can.
Without the interface, any config change of the instance is reported as `restart_required`.

The pattern used by the built-in `smtp` and `webhook` plugins: build a fresh, fully configured
copy, validate it, then swap it in atomically, so deliveries in flight finish with the old
settings and none ever sees a half-applied one:

```go
type Plugin struct {
	cfg  Config
	next atomic.Pointer[Plugin] // configuration applied by Reconfigure
}

func (p *Plugin) current() *Plugin {
	if n := p.next.Load(); n != nil {
		return n
	}
	return p
}

func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if !slices.Equal(n.cfg.Events, p.cfg.Events) { // fixed by the subscription made in Init
		return errors.New("events take effect after a restart")
	}
	if err := n.validate(); err != nil {
		return err
	}
	p.next.Store(n)
	return nil
}
```

Handlers then read their settings through `p.current()`.

## Testing

`pkg/sdk/sdktest` gives you a recording registrar and an in-memory host:

```go
func TestRejectsTrials(t *testing.T) {
	ctx := context.Background()
	reg := sdktest.NewRegistrar(map[string]any{"max_trial_tenants_per_domain": 1})
	if err := (&Plugin{}).Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	tenant := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme"})
	err := reg.RunHooks(ctx, &sdk.HookRequest{Point: sdk.HookBeforeMemberAdd, Tenant: &tenant, Member: &sdk.Member{...}})
	...
	err = reg.Deliver(ctx, "welcome", sdktest.MemberEvent(sdk.EventMemberAdded, member))
}
```

## Shipping it

**As part of a custom binary** (recommended for Go plugins):

```sh
go install github.com/AimTune/tenarium/cmd/tenarium-build@latest
tenarium-build -o tenarium --with github.com/acme/seat-guard@v1.0.0
tenarium-build -o tenarium --with github.com/acme/seat-guard=../seat-guard   # local checkout
```

This generates a `main` that blank-imports `plugins/all` plus your modules (use `-no-builtins`
to leave out the built-in plugins) and builds it. You can also write that `main.go` yourself:

```go
package main

import (
	"github.com/AimTune/tenarium/pkg/server"
	_ "github.com/AimTune/tenarium/plugins/all"
	_ "github.com/acme/seat-guard"
)

func main() { server.Main() }
```

**As an external process**, without rebuilding Tenarium:

```go
func main() { log.Fatal(extplugin.Serve(&quota.Plugin{})) }
```

See [External plugins](external.md).
