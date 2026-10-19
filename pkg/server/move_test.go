package server_test

import (
	"context"
	"sync"
	"testing"

	"github.com/AimTune/tenarium/internal/plugin"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/server"
)

// regional records which tenants it provisioned.
type regional struct{}

var (
	regionalMu    sync.Mutex
	provisionedIn = map[string][]string{} // instance → tenant slugs
)

func (regional) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "regional", Name: "Regional", Version: "0"}
}
func (regional) Init(_ context.Context, r sdk.Registrar) error {
	name := r.InstanceName()
	r.Provisioner(regionalProvisioner{instance: name})
	return nil
}

type regionalProvisioner struct{ instance string }

func (p regionalProvisioner) Name() string { return "resources" }
func (p regionalProvisioner) Provision(_ context.Context, t sdk.Tenant) error {
	regionalMu.Lock()
	defer regionalMu.Unlock()
	provisionedIn[p.instance] = append(provisionedIn[p.instance], t.Slug)
	return nil
}
func (regionalProvisioner) Deprovision(context.Context, sdk.Tenant) error { return nil }

func init() { sdk.Register("regional", func() sdk.Plugin { return regional{} }) }

func provisioned(instance string) []string {
	regionalMu.Lock()
	defer regionalMu.Unlock()
	return append([]string(nil), provisionedIn[instance]...)
}

func TestMoveWithReprovisioning(t *testing.T) {
	cfg := baseConfig()
	cfg.Tenants.Regions = []string{"eu", "us"}
	cfg.Plugins = []server.PluginSpec{
		{Name: "regional-eu", Plugin: "regional", Scope: &plugin.Scope{Regions: []string{"eu"}}},
		{Name: "regional-us", Plugin: "regional", Scope: &plugin.Scope{Regions: []string{"us"}}},
	}
	c := client{t: t, base: startServer(t, cfg)}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "mover", "name": "Mover", "region": "us"})
	waitFor(t, "provisioning in us", func() bool {
		_, tn := c.do("GET", "/v1/tenants/mover", nil)
		return tn["status"] == "active"
	})
	if got := provisioned("regional-eu"); len(got) != 0 {
		t.Fatalf("eu provisioner ran for a us tenant: %v", got)
	}

	code, tn := c.do("POST", "/v1/tenants/mover/move", map[string]any{"region": "eu", "reprovision": true})
	if code != 200 || tn["status"] != "provisioning" || tn["maintenance"] == nil {
		t.Fatalf("move: %d %v", code, tn)
	}
	waitFor(t, "provisioning in eu and the end of maintenance", func() bool {
		_, tn := c.do("GET", "/v1/tenants/mover", nil)
		return tn["status"] == "active" && tn["maintenance"] == nil
	})
	if got := provisioned("regional-eu"); len(got) != 1 || got[0] != "mover" {
		t.Fatalf("eu provisioner: %v", got)
	}
	_, evs := c.do("GET", "/v1/events?type=tenant.*&limit=100", nil)
	types := map[string]bool{}
	for _, e := range evs["items"].([]any) {
		types[e.(map[string]any)["type"].(string)] = true
	}
	for _, want := range []string{"tenant.region_changed", "tenant.provisioned", "tenant.maintenance_ended"} {
		if !types[want] {
			t.Fatalf("missing %s in %v", want, types)
		}
	}
}
