package tenant

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func TestTemplatesAndCloning(t *testing.T) {
	ctx := context.Background()
	svc, _ := newUserService(t, memory.New(), nil, nil)
	if _, err := svc.CreatePlan(ctx, PlanInput{ID: "pro", Name: "Pro"}); err != nil {
		t.Fatal(err)
	}
	var ve *ValidationError
	if _, err := svc.PutTemplate(ctx, store.TenantTemplate{ID: "bad", Name: "Bad", Roles: []store.TemplateRole{{Name: "owner", Actions: []string{"tenants:read"}}}}); !errors.As(err, &ve) {
		t.Fatalf("built-in role name accepted: %v", err)
	}
	if _, err := svc.PutTemplate(ctx, store.TenantTemplate{ID: "bad", Name: "Bad", Branding: &sdk.Branding{PrimaryColor: "red"}}); !errors.As(err, &ve) {
		t.Fatalf("bad color accepted: %v", err)
	}
	tpl, err := svc.PutTemplate(ctx, store.TenantTemplate{ID: "agency", Name: "Agency", Plan: "pro",
		Labels: map[string]string{"kind": "agency", "tier": "b"}, Settings: map[string]any{"theme": map[string]any{"color": "blue", "font": "x"}},
		Limits:   map[string]int64{"seats": 10},
		Branding: &sdk.Branding{DisplayName: "Agency", PrimaryColor: "#123456"},
		Roles:    []store.TemplateRole{{Name: "auditor", Actions: []string{"tenants:read", "events:read"}}}})
	if err != nil || tpl.UpdatedAt.IsZero() {
		t.Fatalf("put: %+v %v", tpl, err)
	}
	if _, err := svc.Create(ctx, CreateInput{Slug: "x", Name: "X", Template: "nope"}); !errors.As(err, &ve) {
		t.Fatalf("unknown template: %v", err)
	}
	a, err := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme", Template: "agency",
		Labels: map[string]string{"tier": "a"}, Settings: map[string]any{"theme": map[string]any{"color": "red"}}})
	if err != nil {
		t.Fatal(err)
	}
	theme := a.Settings["theme"].(map[string]any)
	if a.Plan != "pro" || a.Labels["kind"] != "agency" || a.Labels["tier"] != "a" || theme["color"] != "red" || theme["font"] != "x" ||
		a.Limits["seats"] != 10 || a.Branding.DisplayName != "Agency" {
		t.Fatalf("templated tenant: %+v", a)
	}
	if roles, _ := svc.ListRoles(ctx, a.ID); len(roles) != 1 || roles[0].Name != "auditor" {
		t.Fatalf("template roles: %+v", roles)
	}

	owner, _ := svc.CreateUser(ctx, UserInput{Email: "o@example.com", Password: goodPassword})
	if _, err := svc.AddMember(ctx, a.ID, MemberInput{UserID: owner.ID, Role: "owner"}); err != nil {
		t.Fatal(err)
	}
	c, err := svc.CloneTenant(ctx, "acme", CloneInput{Slug: "acme-copy", Name: "Acme copy", Members: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.Labels[LabelClonedFrom] != a.ID || c.Plan != "pro" || c.Branding == nil || c.Limits["seats"] != 10 {
		t.Fatalf("clone: %+v", c)
	}
	if roles, _ := svc.ListRoles(ctx, c.ID); len(roles) != 1 {
		t.Fatalf("cloned roles: %+v", roles)
	}
	if ms, _ := svc.ListMembers(ctx, c.ID); len(ms) != 1 || ms[0].Role != "owner" {
		t.Fatalf("cloned members: %+v", ms)
	}
}

func TestMaintenanceBrandingHealth(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc, _ := newUserService(t, s, nil, nil)
	tn, _ := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme", Limits: map[string]int64{"calls": 10}})

	if _, err := svc.BrandingFor(ctx, "acme", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no branding: %v", err)
	}
	if _, err := svc.Update(ctx, "acme", UpdateInput{Branding: &sdk.Branding{LogoURL: "http://insecure"}}, nil); err == nil {
		t.Fatal("http logo accepted")
	}
	if _, err := svc.Update(ctx, "acme", UpdateInput{Branding: &sdk.Branding{DisplayName: "ACME", LogoURL: "https://cdn.example.com/l.png"}}, nil); err != nil {
		t.Fatal(err)
	}
	if b, err := svc.BrandingFor(ctx, "acme", ""); err != nil || b.DisplayName != "ACME" || b.Slug != "acme" {
		t.Fatalf("branding: %+v %v", b, err)
	}
	if u, _ := svc.Update(ctx, "acme", UpdateInput{Branding: &sdk.Branding{}}, nil); u.Branding != nil {
		t.Fatal("empty branding did not clear it")
	}

	past := time.Now().Add(-time.Minute)
	if _, err := svc.StartMaintenance(ctx, "acme", "moving", &past); err == nil {
		t.Fatal("window in the past accepted")
	}
	if _, err := svc.StartMaintenance(ctx, "acme", "moving to eu", nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.CheckWritable(ctx, tn.ID); !errors.Is(err, ErrMaintenance) {
		t.Fatalf("writable during maintenance: %v", err)
	}
	h, _ := svc.TenantHealth(ctx, "acme")
	if h.Score != 80 || h.Grade != "healthy" {
		// maintenance (10) + no active members (10)
		t.Fatalf("health in maintenance: %+v", h)
	}
	if _, err := svc.EndMaintenance(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if err := svc.CheckWritable(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EndMaintenance(ctx, "acme"); err == nil {
		t.Fatal("ended twice")
	}

	if _, err := svc.RecordUsage(ctx, "acme", "calls", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RecordUsage(ctx, "acme", "calls", 1); err == nil { // refused: quota event
		t.Fatal("usage over quota accepted")
	}
	if _, err := svc.Suspend(ctx, "acme", "unpaid"); err != nil {
		t.Fatal(err)
	}
	h, _ = svc.TenantHealth(ctx, "acme")
	names := map[string]int{}
	for _, f := range h.Factors {
		names[f.Name] = f.Impact
	}
	if names["status"] != 40 || names["usage"] != 20 || names["quota_refusals"] != 5 || names["members"] != 10 || h.Score != 25 || h.Grade != "critical" {
		t.Fatalf("health: %+v", h)
	}
}
