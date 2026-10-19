package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func TestLifecycleAndCatalog(t *testing.T) {
	ctx := context.Background()
	cfg := baseConfig()
	cfg.Tenants.Regions = []string{"eu", "us"}
	c := newClient(t, startServer(t, cfg), client.WithAPIKey(apiKey))

	must(c.Plans.Create(ctx, client.CreatePlanRequest{ID: "pro", Name: "Pro", Limits: map[string]int64{"seats": 5}}))
	must(c.Plans.Create(ctx, client.CreatePlanRequest{ID: "seats", Name: "Seats", Limits: map[string]int64{"seats": 5}}))
	must(c.Templates.Put(ctx, "agency", client.TenantTemplate{Name: "Agency", Plan: "pro", Region: "eu",
		Roles: []client.TemplateRole{{Name: "auditor", Actions: []string{"tenants:read"}}}}))
	if ts := must(c.Templates.List(ctx)); len(ts) != 1 || ts[0].ID != "agency" {
		t.Fatalf("templates: %+v", ts)
	}
	tn := must(c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "acme", Name: "Acme", Template: "agency",
		AddOns: []string{"seats"}, Branding: &sdk.Branding{DisplayName: "ACME"}}))
	if tn.Plan != "pro" || tn.Region != "eu" || len(tn.AddOns) != 1 || tn.Branding == nil {
		t.Fatalf("created: %+v", tn)
	}
	if e := must(c.Tenants.Entitlements(ctx, "acme")); e.Limits["seats"] != 10 {
		t.Fatalf("entitlements: %+v", e)
	}

	must(c.Plans.Update(ctx, "pro", client.UpdatePlanRequest{Limits: &map[string]int64{"seats": 3}, Grandfather: true}))
	if revs := must(c.Plans.Revisions(ctx, "pro")); len(revs) != 2 {
		t.Fatalf("revisions: %+v", revs)
	}
	if tn = must(c.Tenants.Get(ctx, "acme")); tn.PlanRevision != 1 {
		t.Fatalf("not grandfathered: %+v", tn)
	}
	must(c.Tenants.SetPlanRevision(ctx, "acme", 0))

	r := must(c.Rollouts.Put(ctx, "beta", client.Rollout{Percentage: 100, Enabled: true, Regions: []string{"us"}}))
	if r.Feature != "beta" {
		t.Fatalf("rollout: %+v", r)
	}
	if e := must(c.Tenants.Entitlements(ctx, "acme")); e.Features["beta"] {
		t.Fatal("rollout applied outside its region")
	}
	if moved := must(c.Tenants.Move(ctx, "acme", "us", client.MoveOptions{})); moved.Region != "us" {
		t.Fatalf("move: %+v", moved)
	}
	if e := must(c.Tenants.Entitlements(ctx, "acme")); !e.Features["beta"] {
		t.Fatal("rollout not applied after the move")
	}
	if err := c.Rollouts.Delete(ctx, "beta"); err != nil {
		t.Fatal(err)
	}

	if m := must(c.Tenants.StartMaintenance(ctx, "acme", "upgrade", time.Time{})); m.Maintenance == nil {
		t.Fatal("maintenance not started")
	}
	if m := must(c.Tenants.EndMaintenance(ctx, "acme")); m.Maintenance != nil {
		t.Fatal("maintenance not ended")
	}
	if h := must(c.Tenants.Health(ctx, "acme")); h.Grade == "" {
		t.Fatalf("health: %+v", h)
	}
	if cl := must(c.Tenants.Clone(ctx, "acme", client.CloneTenantRequest{Slug: "acme-2", Name: "Acme 2"})); cl.Plan != "pro" {
		t.Fatalf("clone: %+v", cl)
	}
	if err := c.Templates.Delete(ctx, "agency"); err != nil {
		t.Fatal(err)
	}
}
