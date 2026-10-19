package tenant

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func TestPlanRevisionsAndGrandfathering(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc := NewService(s, Options{})
	if _, err := svc.CreatePlan(ctx, PlanInput{ID: "pro", Name: "Pro", Limits: map[string]int64{"seats": 10}}); err != nil {
		t.Fatal(err)
	}
	old, _ := svc.Create(ctx, CreateInput{Slug: "old", Name: "Old", Plan: "pro"})
	if _, err := svc.UpdatePlan(ctx, "pro", PlanUpdate{Limits: &map[string]int64{"seats": 5}, Grandfather: true}, nil); err != nil {
		t.Fatal(err)
	}
	fresh, _ := svc.Create(ctx, CreateInput{Slug: "fresh", Name: "Fresh", Plan: "pro"})

	if e, _ := svc.Entitlements(ctx, "old"); e.Limits["seats"] != 10 || e.PlanRevision != 1 {
		t.Fatalf("grandfathered: %+v", e)
	}
	if e, _ := svc.Entitlements(ctx, fresh.ID); e.Limits["seats"] != 5 || e.PlanRevision != 0 {
		t.Fatalf("new subscriber: %+v", e)
	}
	revs, err := svc.ListPlanRevisions(ctx, "pro")
	if err != nil || len(revs) != 2 || revs[0].Revision != 2 {
		t.Fatalf("revisions: %+v %v", revs, err)
	}
	// Without grandfathering, unpinned tenants follow the plan.
	if _, err := svc.UpdatePlan(ctx, "pro", PlanUpdate{Limits: &map[string]int64{"seats": 7}}, nil); err != nil {
		t.Fatal(err)
	}
	if e, _ := svc.Entitlements(ctx, fresh.ID); e.Limits["seats"] != 7 {
		t.Fatalf("follows plan: %+v", e)
	}
	if e, _ := svc.Entitlements(ctx, old.ID); e.Limits["seats"] != 10 {
		t.Fatalf("still pinned: %+v", e)
	}
	// Migrate the pinned tenant.
	if _, err := svc.SetPlanRevision(ctx, "old", 9); err == nil {
		t.Fatal("unknown revision accepted")
	}
	if tn, err := svc.SetPlanRevision(ctx, "old", 0); err != nil || tn.PlanRevision != 0 {
		t.Fatalf("unpin: %+v %v", tn, err)
	}
	if e, _ := svc.Entitlements(ctx, old.ID); e.Limits["seats"] != 7 {
		t.Fatalf("unpinned: %+v", e)
	}
	// Changing plan resets a pin.
	if _, err := svc.SetPlanRevision(ctx, "old", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePlan(ctx, PlanInput{ID: "team", Name: "Team"}); err != nil {
		t.Fatal(err)
	}
	if tn, _ := svc.Update(ctx, "old", UpdateInput{Plan: ptr("team")}, nil); tn.PlanRevision != 0 {
		t.Fatalf("plan change kept pin: %+v", tn)
	}
}

func TestAddOns(t *testing.T) {
	ctx := context.Background()
	svc := NewService(memory.New(), Options{})
	if _, err := svc.CreatePlan(ctx, PlanInput{ID: "pro", Name: "Pro", Features: map[string]bool{"sso": false},
		Limits: map[string]int64{"seats": 10}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePlan(ctx, PlanInput{ID: "seats-pack", Name: "Seats", Features: map[string]bool{"sso": true},
		Limits: map[string]int64{"seats": 25, "storage": 100}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, CreateInput{Slug: "x", Name: "X", Plan: "pro", AddOns: []string{"nope"}}); err == nil {
		t.Fatal("unknown add-on accepted")
	}
	if _, err := svc.Create(ctx, CreateInput{Slug: "x", Name: "X", Plan: "pro", AddOns: []string{"pro"}}); err == nil {
		t.Fatal("plan as its own add-on accepted")
	}
	tn, err := svc.Create(ctx, CreateInput{Slug: "x", Name: "X", Plan: "pro", AddOns: []string{"seats-pack"}})
	if err != nil {
		t.Fatal(err)
	}
	e, _ := svc.Entitlements(ctx, tn.ID)
	if e.Limits["seats"] != 35 || !e.Features["sso"] {
		t.Fatalf("stacked: %+v", e)
	}
	if _, ok := e.Limits["storage"]; ok {
		t.Fatalf("add-on limited a metric the plan leaves unlimited: %+v", e)
	}
	if _, err := svc.Update(ctx, tn.ID, UpdateInput{AddOns: &[]string{}}, nil); err != nil {
		t.Fatal(err)
	}
	if e, _ := svc.Entitlements(ctx, tn.ID); e.Limits["seats"] != 10 {
		t.Fatalf("removed: %+v", e)
	}
}

func TestRollouts(t *testing.T) {
	ctx := context.Background()
	svc := NewService(memory.New(), Options{})
	var ids []string
	for i := range 200 {
		tn, err := svc.Create(ctx, CreateInput{Slug: fmt.Sprintf("t%d", i), Name: "T", Plan: "pro"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, tn.ID)
	}
	enabled := func() (n int, set map[string]bool) {
		set = map[string]bool{}
		for _, id := range ids {
			if e, _ := svc.Entitlements(ctx, id); e.Features["beta"] {
				n++
				set[id] = true
			}
		}
		return n, set
	}
	if _, err := svc.PutRollout(ctx, store.Rollout{Feature: "beta", Percentage: 101}); err == nil {
		t.Fatal("percentage over 100 accepted")
	}
	if _, err := svc.PutRollout(ctx, store.Rollout{Feature: "beta", Percentage: 20, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	n20, set20 := enabled()
	if n20 < 20 || n20 > 60 {
		t.Fatalf("20%% rollout enabled %d of 200", n20)
	}
	if _, err := svc.PutRollout(ctx, store.Rollout{Feature: "beta", Percentage: 50, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	n50, set50 := enabled()
	for id := range set20 {
		if !set50[id] {
			t.Fatal("raising the percentage dropped a tenant")
		}
	}
	if n50 <= n20 {
		t.Fatalf("50%% (%d) not above 20%% (%d)", n50, n20)
	}
	// Tenant overrides win; exclude and include apply; disabled is off.
	var in, out string
	for _, id := range ids[1:] {
		if set50[id] && out == "" {
			out = id
		} else if !set50[id] && in == "" {
			in = id
		}
	}
	if _, err := svc.Update(ctx, ids[0], UpdateInput{Features: &map[string]bool{"beta": false}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutRollout(ctx, store.Rollout{Feature: "beta", Percentage: 50, Enabled: true, Include: []string{in}, Exclude: []string{out}}); err != nil {
		t.Fatal(err)
	}
	if e, _ := svc.Entitlements(ctx, in); !e.Features["beta"] {
		t.Fatal("include ignored")
	}
	if e, _ := svc.Entitlements(ctx, out); e.Features["beta"] {
		t.Fatal("exclude ignored")
	}
	if e, _ := svc.Entitlements(ctx, ids[0]); e.Features["beta"] {
		t.Fatal("tenant override lost")
	}
	if _, err := svc.PutRollout(ctx, store.Rollout{Feature: "beta", Percentage: 100, Plans: []string{"free"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if n, _ := enabled(); n != 0 {
		t.Fatalf("plan filter: %d", n)
	}
	if _, err := svc.PutRollout(ctx, store.Rollout{Feature: "beta", Percentage: 100}); err != nil {
		t.Fatal(err)
	}
	if n, _ := enabled(); n != 0 {
		t.Fatalf("kill switch: %d", n)
	}
	if err := svc.DeleteRollout(ctx, "beta"); err != nil {
		t.Fatal(err)
	}
}

func TestRegions(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc := NewService(s, Options{Regions: []string{"eu", "us"}, DefaultRegion: "eu"})
	p, err := svc.Create(ctx, CreateInput{Slug: "p", Name: "P", Region: "us"})
	if err != nil || p.Region != "us" {
		t.Fatalf("create: %+v %v", p, err)
	}
	c, _ := svc.Create(ctx, CreateInput{Slug: "c", Name: "C", ParentID: p.ID})
	if c.Region != "us" {
		t.Fatalf("child did not inherit region: %q", c.Region)
	}
	if d, _ := svc.Create(ctx, CreateInput{Slug: "d", Name: "D"}); d.Region != "eu" {
		t.Fatalf("default: %q", d.Region)
	}
	if _, err := svc.Create(ctx, CreateInput{Slug: "e", Name: "E", Region: "ap"}); err == nil {
		t.Fatal("unknown region accepted")
	}
	if _, err := svc.MoveRegion(ctx, "p", MoveInput{Region: "ap"}); err == nil {
		t.Fatal("moved to unknown region")
	}
	moved, err := svc.MoveRegion(ctx, "p", MoveInput{Region: "eu"})
	if err != nil || moved.Region != "eu" {
		t.Fatalf("move: %+v %v", moved, err)
	}
	if _, err := svc.MoveRegion(ctx, "p", MoveInput{Region: "eu"}); err == nil {
		t.Fatal("no-op move accepted")
	}
	evs, _ := s.ReadEvents(ctx, 0, 1000)
	var found bool
	for _, e := range evs {
		found = found || e.Type == sdk.EventTenantRegionChanged
	}
	if !found {
		t.Fatal("no tenant.region_changed event")
	}
	// Without configured regions, none is required.
	if tn, err := NewService(memory.New(), Options{}).Create(ctx, CreateInput{Slug: "f", Name: "F"}); err != nil || tn.Region != "" {
		t.Fatalf("no regions: %+v %v", tn, err)
	}
	var ve *ValidationError
	if _, err := NewService(memory.New(), Options{Regions: []string{"eu"}}).Create(ctx, CreateInput{Slug: "g", Name: "G"}); !errors.As(err, &ve) {
		t.Fatalf("region required: %v", err)
	}
}

func TestTokensCarryRegion(t *testing.T) {
	ctx := context.Background()
	svc, _ := newUserService(t, memory.New(), nil, nil)
	if err := svc.SetRegions([]string{"eu"}, "eu"); err != nil {
		t.Fatal(err)
	}
	tn, _ := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme"})
	u, _ := svc.CreateUser(ctx, UserInput{Email: "a@example.com", Password: goodPassword})
	if _, err := svc.AddMember(ctx, tn.ID, MemberInput{UserID: u.ID, Role: "owner"}); err != nil {
		t.Fatal(err)
	}
	pair, err := svc.SignIn(ctx, LoginInput{Email: "a@example.com", Password: goodPassword, Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := svc.userOpts.Issuer.Verify(pair.AccessToken)
	if err != nil || c.Region != "eu" || c.TenantID != tn.ID {
		t.Fatalf("claims: %+v %v", c, err)
	}
}
