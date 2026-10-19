package tenant

import (
	"context"
	"errors"
	"testing"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func ptr[T any](v T) *T { return &v }

func TestPlansAndEntitlements(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc := NewService(s, Options{RequireKnownPlans: true})

	if _, err := svc.Create(ctx, CreateInput{Slug: "a", Name: "A", Plan: "pro"}); err == nil {
		t.Fatal("unknown plan accepted with RequireKnownPlans")
	}
	p, err := svc.CreatePlan(ctx, PlanInput{ID: "pro", Name: "Pro",
		Features: map[string]bool{"sso": true, "audit": false}, Limits: map[string]int64{"seats": 10, "projects": 5}})
	if err != nil || p.Version != 1 {
		t.Fatalf("create plan: %+v %v", p, err)
	}
	tn, err := svc.Create(ctx, CreateInput{Slug: "a", Name: "A", Plan: "pro",
		Features: map[string]bool{"audit": true}, Limits: map[string]int64{"seats": 50}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := svc.Entitlements(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !e.HasFeature("sso") || !e.HasFeature("audit") || e.Limits["seats"] != 50 || e.Limits["projects"] != 5 {
		t.Fatalf("entitlements: %+v", e)
	}

	if err := svc.DeletePlan(ctx, "pro"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("deleting a plan in use: %v", err)
	}
	if _, err := svc.UpdatePlan(ctx, "pro", PlanUpdate{Limits: ptr(map[string]int64{"seats": -1})}, nil); err == nil {
		t.Fatal("negative limit accepted")
	}
	p, err = svc.UpdatePlan(ctx, "pro", PlanUpdate{Name: ptr("Pro 2")}, ptr(int64(1)))
	if err != nil || p.Version != 2 {
		t.Fatalf("update plan: %+v %v", p, err)
	}
	if _, err := svc.UpdatePlan(ctx, "pro", PlanUpdate{Name: ptr("x")}, ptr(int64(1))); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale plan update: %v", err)
	}

	if _, err := svc.CreatePlan(ctx, PlanInput{ID: "free", Name: "Free"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Update(ctx, tn.ID, UpdateInput{Plan: ptr("free")}, nil); err != nil {
		t.Fatal(err)
	}
	types := eventTypes(t, s)
	if types[len(types)-1] != sdk.EventTenantPlanChanged || types[len(types)-2] != sdk.EventTenantUpdated {
		t.Fatalf("plan change events: %v", types)
	}
	if err := svc.DeletePlan(ctx, "pro"); err != nil {
		t.Fatalf("delete unused plan: %v", err)
	}
}

func TestHierarchy(t *testing.T) {
	ctx := context.Background()
	svc := NewService(memory.New(), Options{})
	org, _ := svc.Create(ctx, CreateInput{Slug: "org", Name: "Org"})
	ws, err := svc.Create(ctx, CreateInput{Slug: "ws", Name: "WS", ParentID: "org"})
	if err != nil || ws.ParentID != org.ID {
		t.Fatalf("child: %+v %v", ws, err)
	}
	if _, err := svc.Create(ctx, CreateInput{Slug: "x", Name: "X", ParentID: "missing"}); err == nil {
		t.Fatal("missing parent accepted")
	}
	if _, err := svc.Delete(ctx, org.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("deleting parent with live child: %v", err)
	}
	if _, err := svc.Delete(ctx, ws.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Delete(ctx, org.ID); err != nil {
		t.Fatalf("delete parent after child: %v", err)
	}
	if _, err := svc.Create(ctx, CreateInput{Slug: "y", Name: "Y", ParentID: org.ID}); err == nil {
		t.Fatal("child of deleted parent accepted")
	}
}

func TestUsageQuota(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc := NewService(s, Options{})
	if _, err := svc.CreatePlan(ctx, PlanInput{ID: "p", Name: "P", Limits: map[string]int64{"api_calls": 3}}); err != nil {
		t.Fatal(err)
	}
	tn, _ := svc.Create(ctx, CreateInput{Slug: "u", Name: "U", Plan: "p"})
	for range 3 {
		if _, err := svc.RecordUsage(ctx, tn.ID, "api_calls", 1); err != nil {
			t.Fatal(err)
		}
	}
	var qe *QuotaError
	if _, err := svc.RecordUsage(ctx, tn.ID, "api_calls", 1); !errors.As(err, &qe) || qe.Current != 3 {
		t.Fatalf("quota: %v", err)
	}
	if evts := eventTypes(t, s); evts[len(evts)-1] != sdk.EventTenantQuotaExceeded {
		t.Fatalf("no quota event: %v", evts)
	}
	if it, err := svc.RecordUsage(ctx, tn.ID, "storage_gb", 100); err != nil || it.Limit != nil || it.Value != 100 {
		t.Fatalf("unlimited metric: %+v %v", it, err)
	}
	items, _ := svc.Usage(ctx, tn.ID)
	if len(items) != 2 || items[0].Metric != "api_calls" || *items[0].Limit != 3 {
		t.Fatalf("usage: %+v", items)
	}
	if _, err := svc.Suspend(ctx, tn.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RecordUsage(ctx, tn.ID, "storage_gb", 1); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("suspended tenant consumed quota: %v", err)
	}
	if _, err := svc.RecordUsage(ctx, tn.ID, "storage_gb", -1); err != nil {
		t.Fatalf("suspended tenant cannot release quota: %v", err)
	}
}

func TestSettingsSchema(t *testing.T) {
	sch, err := schema.Compile([]byte(`{"type":"object","properties":{"region":{"enum":["eu","us"]}},"required":["region"]}`))
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(memory.New(), Options{SettingsSchema: sch})
	var ve *ValidationError
	if _, err := svc.Create(context.Background(), CreateInput{Slug: "a", Name: "A"}); !errors.As(err, &ve) || ve.Field != "settings" {
		t.Fatalf("missing required setting: %v", err)
	}
	if _, err := svc.Create(context.Background(), CreateInput{Slug: "a", Name: "A", Settings: map[string]any{"region": "mars"}}); !errors.As(err, &ve) {
		t.Fatalf("bad enum: %v", err)
	}
	tn, err := svc.Create(context.Background(), CreateInput{Slug: "a", Name: "A", Settings: map[string]any{"region": "eu"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Update(context.Background(), tn.ID, UpdateInput{Settings: map[string]any{"region": nil}}, nil); !errors.As(err, &ve) {
		t.Fatalf("merge patch removed required setting: %v", err)
	}
}

type flakyDeprov struct{ failing bool }

func (p *flakyDeprov) Name() string                                { return "flaky" }
func (p *flakyDeprov) Provision(context.Context, sdk.Tenant) error { return nil }
func (p *flakyDeprov) Deprovision(context.Context, sdk.Tenant) error {
	if p.failing {
		return errors.New("backend down")
	}
	return nil
}

func TestFailedDeprovisioningCanBeRetried(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc := NewService(s, Options{HasProvisioners: true})
	prov := &flakyDeprov{failing: true}
	r := NewRunner(svc, []ProvisionerRef{{Plugin: "test", Provisioner: prov}}, discard, nil)
	r.stepBackoff = 0
	var cursor int64

	tn, _ := svc.Create(ctx, CreateInput{Slug: "a", Name: "A"})
	drive(t, s, r, &cursor)
	if _, err := svc.Delete(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	drive(t, s, r, &cursor)
	if got, _ := svc.Get(ctx, tn.ID); got.Status != sdk.StatusFailed || got.StatusReason == "" {
		t.Fatalf("want failed with reason, got %+v", got)
	}

	prov.failing = false
	if _, err := svc.Delete(ctx, tn.ID); err != nil {
		t.Fatalf("delete again: %v", err)
	}
	drive(t, s, r, &cursor)
	if got, _ := svc.Get(ctx, tn.ID); got.Status != sdk.StatusDeleted {
		t.Fatalf("want deleted, got %+v", got)
	}
}
