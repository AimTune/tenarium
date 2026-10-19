package controller

import (
	"slices"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

func TestTenantPlacementBillingAndBranding(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx
	e.createPlan("pro", map[string]int64{"seats": 10})
	e.createPlan("extra-seats", map[string]int64{"seats": 5})

	anchor := metav1.NewTime(time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC))
	cr := newTenant("acme", "acme")
	cr.Spec.Plan = "pro"
	cr.Spec.AddOns = []string{"extra-seats"}
	cr.Spec.Region = "eu"
	cr.Spec.BillingAnchor = &anchor
	cr.Spec.Branding = &tenariumv1.Branding{DisplayName: "Acme", PrimaryColor: "#112233", LogoURL: "https://acme.example/logo.png"}
	e.create(cr)

	got := e.syncTenant("acme")
	id := got.Status.ID
	if got.Status.Region != "eu" || got.Status.Health == nil || !got.Status.BrandingManaged || got.Status.Maintenance != nil {
		t.Fatalf("status = %+v", got.Status)
	}
	if got.Status.Entitlements == nil || got.Status.Entitlements.Limits["seats"] != 15 {
		t.Fatalf("entitlements with add-on = %+v", got.Status.Entitlements)
	}
	remote, err := e.api.Tenants.Get(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Region != "eu" || !slices.Equal(remote.AddOns, []string{"extra-seats"}) ||
		remote.BillingAnchor == nil || !remote.BillingAnchor.Equal(anchor.Time) ||
		remote.Branding == nil || remote.Branding.DisplayName != "Acme" || remote.Branding.PrimaryColor != "#112233" {
		t.Fatalf("remote = %+v", remote)
	}
	e.drainEvents()

	// A second sync changes nothing.
	if _, err := e.reconcileTenant("acme"); err != nil {
		t.Fatal(err)
	}
	if again, _ := e.api.Tenants.Get(ctx, "acme"); again.Version != remote.Version {
		t.Fatalf("idle sync wrote the tenant: version %d -> %d", remote.Version, again.Version)
	}

	// Changing the region moves the tenant (same ID); removing the add-ons
	// and the branding clears them.
	cr = e.tenant("acme")
	cr.Spec.Region = "us"
	cr.Spec.AddOns = []string{}
	cr.Spec.Branding = nil
	cr.Spec.BillingAnchor = nil
	if err := e.k8s.Update(ctx, cr); err != nil {
		t.Fatal(err)
	}
	got = e.syncTenant("acme")
	remote, _ = e.api.Tenants.Get(ctx, "acme")
	if remote.ID != id || remote.Region != "us" || got.Status.Region != "us" {
		t.Fatalf("not moved: remote %+v, status %+v", remote, got.Status)
	}
	if len(remote.AddOns) != 0 || remote.Branding != nil || got.Status.BrandingManaged {
		t.Fatalf("add-ons/branding not cleared: %+v, managed=%v", remote, got.Status.BrandingManaged)
	}
	// The anchor the spec set is removed with it.
	if remote.BillingAnchor != nil || got.Status.BillingAnchorManaged {
		t.Fatalf("billing anchor not cleared: %v, managed=%v", remote.BillingAnchor, got.Status.BillingAnchorManaged)
	}
	// An anchor set elsewhere afterwards is left alone.
	other := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if _, err := e.api.Tenants.Update(ctx, "acme", client.UpdateTenantRequest{BillingAnchor: &other}); err != nil {
		t.Fatal(err)
	}
	e.syncTenant("acme")
	if remote, _ = e.api.Tenants.Get(ctx, "acme"); remote.BillingAnchor == nil {
		t.Fatal("unmanaged billing anchor removed")
	}
	if !hasEvent(e.drainEvents(), EventMoved) {
		t.Fatal("no Moved event")
	}

	// Drift: someone sets branding on a tenant whose spec no longer manages
	// it. It is kept.
	if _, err := e.api.Tenants.Update(ctx, "acme", client.UpdateTenantRequest{Branding: &sdk.Branding{DisplayName: "Theirs"}}); err != nil {
		t.Fatal(err)
	}
	e.syncTenant("acme")
	if remote, _ = e.api.Tenants.Get(ctx, "acme"); remote.Branding == nil || remote.Branding.DisplayName != "Theirs" {
		t.Fatalf("unmanaged branding changed: %+v", remote.Branding)
	}

	// Maintenance shows in the status.
	if _, err := e.api.Tenants.StartMaintenance(ctx, "acme", "copying data", time.Time{}); err != nil {
		t.Fatal(err)
	}
	got = e.syncTenant("acme")
	if m := got.Status.Maintenance; m == nil || !m.Active || m.Message != "copying data" {
		t.Fatalf("maintenance = %+v", m)
	}
	if _, err := e.api.Tenants.EndMaintenance(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if got = e.syncTenant("acme"); got.Status.Maintenance != nil && got.Status.Maintenance.Active {
		t.Fatalf("maintenance still active: %+v", got.Status.Maintenance)
	}
}

func TestTenantPlanRevision(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx
	e.createPlan("pro", map[string]int64{"seats": 10})
	// A second revision of the plan.
	p := e.plan("pro")
	p.Spec.Limits = map[string]int64{"seats": 20}
	if err := e.k8s.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.plans.Reconcile(ctx, req("pro")); err != nil {
		t.Fatal(err)
	}
	revs, err := e.api.Plans.Revisions(ctx, "pro")
	if err != nil || len(revs) < 2 {
		t.Fatalf("revisions = %+v, %v", revs, err)
	}
	oldest := revs[len(revs)-1].Revision

	cr := newTenant("acme", "acme")
	cr.Spec.Plan = "pro"
	cr.Spec.PlanRevision = &oldest
	e.create(cr)
	got := e.syncTenant("acme")
	if got.Status.PlanRevision != oldest || got.Status.Entitlements == nil || got.Status.Entitlements.Limits["seats"] != 10 {
		t.Fatalf("status = %+v, entitlements = %+v", got.Status, got.Status.Entitlements)
	}

	// Unpin.
	got.Spec.PlanRevision = new(int64)
	if err := e.k8s.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	got = e.syncTenant("acme")
	if got.Status.PlanRevision != 0 || got.Status.Entitlements.Limits["seats"] != 20 {
		t.Fatalf("not unpinned: %+v, %+v", got.Status, got.Status.Entitlements)
	}
}

func TestTenantFromTemplate(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx
	e.createPlan("pro", nil)
	e.create(&tenariumv1.TenantTemplate{ObjectMeta: metav1.ObjectMeta{Name: "startup"},
		Spec: tenariumv1.TenantTemplateSpec{Plan: "pro", Region: "eu", Labels: map[string]string{"segment": "startup"}}})
	if _, err := e.templates.Reconcile(ctx, req("startup")); err != nil {
		t.Fatal(err)
	}

	cr := newTenant("acme", "acme")
	cr.Spec.Template = "startup"
	e.create(cr)
	got := e.syncTenant("acme")
	remote, err := e.api.Tenants.Get(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Plan != "pro" || remote.Region != "eu" || remote.Labels["segment"] != "startup" ||
		remote.Labels[tenariumv1.OwnerLabel] != string(got.UID) {
		t.Fatalf("template not applied: %+v", remote)
	}
	if got.Status.Region != "eu" {
		t.Fatalf("status region = %q", got.Status.Region)
	}

	// The template is create-only: changing it does nothing.
	got.Spec.Template = "other"
	if err := e.k8s.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	e.syncTenant("acme")
	if after, _ := e.api.Tenants.Get(ctx, "acme"); after.Version != remote.Version {
		t.Fatalf("template change wrote the tenant: %+v", after)
	}
}

func TestBrandingUpdate(t *testing.T) {
	spec := &tenariumv1.Branding{DisplayName: "Acme", SupportURL: "https://help.acme.example"}
	acme := sdk.Branding{DisplayName: "Acme", SupportURL: "https://help.acme.example"}
	other := sdk.Branding{DisplayName: "Other"}
	for _, tc := range []struct {
		name    string
		spec    *tenariumv1.Branding
		managed bool
		remote  *sdk.Branding
		want    *sdk.Branding
	}{
		{"unmanaged keeps remote", nil, false, &other, nil},
		{"removed from spec clears", nil, true, &other, &sdk.Branding{}},
		{"removed, already clear", nil, true, nil, nil},
		{"equal", spec, true, &acme, nil},
		{"differs", spec, false, &other, &acme},
		{"set on empty", spec, false, nil, &acme},
		{"empty spec clears", &tenariumv1.Branding{}, true, &other, &sdk.Branding{}},
		{"empty spec, none", &tenariumv1.Branding{}, true, nil, nil},
	} {
		tn := &tenariumv1.Tenant{Spec: tenariumv1.TenantSpec{Branding: tc.spec}, Status: tenariumv1.TenantStatus{BrandingManaged: tc.managed}}
		got := brandingUpdate(tn, tc.remote)
		if (got == nil) != (tc.want == nil) || got != nil && *got != *tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestSameTimeAndMaintenanceStatus(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	withNanos := now.Add(300 * time.Millisecond)
	if !sameTime(now, &withNanos) || sameTime(now, nil) || sameTime(now, ptr(now.Add(time.Hour))) {
		t.Fatal("sameTime")
	}

	if maintenanceStatus(sdk.Tenant{}, now) != nil {
		t.Fatal("no window should give nil")
	}
	past := now.Add(-time.Minute)
	m := maintenanceStatus(sdk.Tenant{Maintenance: &sdk.Maintenance{Message: "m", Until: &past, MoveTo: "us"}}, now)
	if m == nil || m.Active || m.Message != "m" || m.MoveTo != "us" || m.Until == nil {
		t.Fatalf("expired window = %+v", m)
	}
	m = maintenanceStatus(sdk.Tenant{Maintenance: &sdk.Maintenance{StartedAt: past}}, now)
	if m == nil || !m.Active {
		t.Fatalf("open window = %+v", m)
	}
}

func ptr[T any](v T) *T { return &v }
