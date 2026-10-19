package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func testPlanRevisions(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	put := func(rev int64, limit int64) error {
		return s.InTx(ctx, func(tx store.Tx) error {
			return tx.PutPlanRevision(ctx, store.PlanRevision{PlanID: "pro", Revision: rev,
				Features: map[string]bool{"sso": true}, Limits: map[string]int64{"seats": limit}, CreatedAt: now})
		})
	}
	for _, r := range []int64{1, 2} {
		if err := put(r, r*10); err != nil {
			t.Fatal(err)
		}
	}
	// Idempotent: a second write of revision 1 keeps the original.
	if err := put(1, 99); err != nil {
		t.Fatal(err)
	}
	// A failed transaction leaves nothing behind.
	boom := errors.New("boom")
	if err := s.InTx(ctx, func(tx store.Tx) error {
		if err := tx.PutPlanRevision(ctx, store.PlanRevision{PlanID: "pro", Revision: 3, CreatedAt: now}); err != nil {
			return err
		}
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("tx: %v", err)
	}
	revs, err := s.ListPlanRevisions(ctx, "pro")
	if err != nil || len(revs) != 2 || revs[0].Revision != 2 || revs[1].Revision != 1 {
		t.Fatalf("list: %+v %v", revs, err)
	}
	r, err := s.GetPlanRevision(ctx, "pro", 1)
	if err != nil || r.Limits["seats"] != 10 || !r.Features["sso"] || !r.CreatedAt.Equal(now) {
		t.Fatalf("get: %+v %v", r, err)
	}
	if _, err := s.GetPlanRevision(ctx, "pro", 3); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rolled back revision: %v", err)
	}
	if revs, _ := s.ListPlanRevisions(ctx, "free"); len(revs) != 0 {
		t.Fatalf("other plan: %+v", revs)
	}
}

func testRollouts(t *testing.T, s store.Store) {
	ctx := context.Background()
	if _, err := s.GetRollout(ctx, "beta"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	r := store.Rollout{Feature: "beta", Percentage: 25, Plans: []string{"pro"}, Labels: map[string]string{"tier": "a"},
		Include: []string{"t1"}, Enabled: true, UpdatedAt: time.Now().UTC().Truncate(time.Millisecond)}
	if err := s.PutRollout(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Percentage = 50
	if err := s.PutRollout(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRollout(ctx, store.Rollout{Feature: "alpha"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRollout(ctx, "beta")
	if err != nil || got.Percentage != 50 || got.Plans[0] != "pro" || got.Labels["tier"] != "a" || !got.Enabled {
		t.Fatalf("get: %+v %v", got, err)
	}
	all, err := s.ListRollouts(ctx)
	if err != nil || len(all) != 2 || all[0].Feature != "alpha" {
		t.Fatalf("list: %+v %v", all, err)
	}
	if err := s.DeleteRollout(ctx, "beta"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRollout(ctx, "beta"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

func testTenantPlacement(t *testing.T, s store.Store) {
	ctx := context.Background()
	tn := tenant("place")
	tn.PlanRevision, tn.AddOns, tn.Region = 2, []string{"extra-seats"}, "eu"
	anchor := time.Date(2026, 1, 31, 10, 0, 0, 0, time.UTC)
	tn.BillingAnchor = &anchor
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.CreateTenant(ctx, tn) }); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTenant(ctx, tn.ID)
	if err != nil || got.PlanRevision != 2 || got.Region != "eu" || len(got.AddOns) != 1 || got.BillingAnchor == nil || !got.BillingAnchor.Equal(anchor) {
		t.Fatalf("get: %+v %v", got, err)
	}
	got.Region, got.AddOns, got.PlanRevision = "us", nil, 0
	got.BillingAnchor = nil
	got.Version++
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.UpdateTenant(ctx, got, got.Version-1) }); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetTenant(ctx, tn.ID)
	if got.Region != "us" || got.AddOns != nil || got.PlanRevision != 0 || got.BillingAnchor != nil {
		t.Fatalf("updated: %+v", got)
	}
}

func testEventTraceContext(t *testing.T, s store.Store) {
	ctx := context.Background()
	tp := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	mustTx(t, s, func(tx store.Tx) error {
		_, err := tx.AppendEvents(ctx, sdk.Event{ID: newID(), Type: "traced", Source: "test", Time: time.Now(),
			TraceParent: tp, TraceState: "vendor=x", DataSchema: "https://t.example/v1/event-schemas/traced/1"})
		return err
	})
	evs, err := s.QueryEvents(ctx, store.EventQuery{Types: []string{"traced"}})
	if err != nil || len(evs) != 1 || evs[0].TraceParent != tp || evs[0].TraceState != "vendor=x" || evs[0].DataSchema == "" {
		t.Fatalf("query: %+v %v", evs, err)
	}
	last, _ := s.LastEventSeq(ctx)
	evs, _ = s.ReadEvents(ctx, last-1, 1)
	if len(evs) != 1 || evs[0].TraceParent != tp {
		t.Fatalf("read: %+v", evs)
	}
}

func testTenantExtras(t *testing.T, s store.Store) {
	ctx := context.Background()
	tn := tenant("extras")
	until := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	tn.Branding = &sdk.Branding{DisplayName: "Extras", PrimaryColor: "#112233"}
	tn.Maintenance = &sdk.Maintenance{Message: "moving", StartedAt: until.Add(-time.Hour), Until: &until}
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateTenant(ctx, tn) })
	got, err := s.GetTenant(ctx, tn.ID)
	if err != nil || got.Branding == nil || got.Branding.PrimaryColor != "#112233" || got.Maintenance == nil ||
		!got.Maintenance.Until.Equal(until) || got.Maintenance.Message != "moving" {
		t.Fatalf("get: %+v %v", got, err)
	}
	got.Branding, got.Maintenance = nil, nil
	got.Version++
	mustTx(t, s, func(tx store.Tx) error { return tx.UpdateTenant(ctx, got, got.Version-1) })
	if got, _ = s.GetTenant(ctx, tn.ID); got.Branding != nil || got.Maintenance != nil {
		t.Fatalf("cleared: %+v %+v", got.Branding, got.Maintenance)
	}

	if _, err := s.GetTenantTemplate(ctx, "starter"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing template: %v", err)
	}
	tpl := store.TenantTemplate{ID: "starter", Name: "Starter", Plan: "pro", Labels: map[string]string{"tier": "s"},
		Settings: map[string]any{"theme": "dark"}, Roles: []store.TemplateRole{{Name: "auditor", Actions: []string{"tenants:read"}}},
		UpdatedAt: time.Now().UTC().Truncate(time.Millisecond)}
	if err := s.PutTenantTemplate(ctx, tpl); err != nil {
		t.Fatal(err)
	}
	tpl.Name = "Starter v2"
	if err := s.PutTenantTemplate(ctx, tpl); err != nil {
		t.Fatal(err)
	}
	if err := s.PutTenantTemplate(ctx, store.TenantTemplate{ID: "agency", Name: "Agency"}); err != nil {
		t.Fatal(err)
	}
	g, err := s.GetTenantTemplate(ctx, "starter")
	if err != nil || g.Name != "Starter v2" || g.Roles[0].Actions[0] != "tenants:read" || g.Settings["theme"] != "dark" {
		t.Fatalf("get template: %+v %v", g, err)
	}
	if all, _ := s.ListTenantTemplates(ctx); len(all) != 2 || all[0].ID != "agency" {
		t.Fatalf("list: %+v", all)
	}
	if err := s.DeleteTenantTemplate(ctx, "starter"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTenantTemplate(ctx, "starter"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}
