package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

// setPlanRevision pins the tenant to spec.planRevision when it is set and
// differs from the tenant's pin.
func (r *TenantReconciler) setPlanRevision(ctx context.Context, c *client.Client, t *tenariumv1.Tenant, remote sdk.Tenant) (sdk.Tenant, error) {
	want := t.Spec.PlanRevision
	if want == nil || *want == remote.PlanRevision || !remote.IsLive() {
		return remote, nil
	}
	updated, err := c.Tenants.SetPlanRevision(ctx, remote.ID, *want)
	if err != nil {
		return remote, err
	}
	r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, EventUpdated, "Update", "pinned tenant %s to plan revision %d", remote.Slug, *want)
	return updated, nil
}

// move moves the tenant to spec.region when it is set and differs from the
// tenant's region. A region change never recreates the tenant.
func (r *TenantReconciler) move(ctx context.Context, c *client.Client, t *tenariumv1.Tenant, remote sdk.Tenant) (sdk.Tenant, error) {
	region := t.Spec.Region
	if region == "" || region == remote.Region || !remote.IsLive() {
		return remote, nil
	}
	if t.Spec.MoveReprovision && remote.Status != sdk.StatusActive {
		// A reprovisioning move needs an active tenant; a later sync retries.
		return remote, nil
	}
	updated, err := c.Tenants.Move(ctx, remote.ID, region, client.MoveOptions{Reprovision: t.Spec.MoveReprovision})
	if err != nil {
		return remote, err
	}
	r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, EventMoved, "Move", "moved tenant %s from region %q to %q", remote.Slug, remote.Region, region)
	return updated, nil
}

// refreshHealth records the tenant's health score. Errors keep the last
// known score: health is informational and must not fail the sync.
func (r *TenantReconciler) refreshHealth(ctx context.Context, c *client.Client, t *tenariumv1.Tenant) {
	h, err := c.Tenants.Health(ctx, t.Status.ID)
	if err != nil {
		log.FromContext(ctx).V(1).Info("cannot read tenant health", "tenant", t.Status.ID, "error", err.Error())
		return
	}
	t.Status.Health = &tenariumv1.HealthStatus{Score: h.Score, Grade: h.Grade}
}

// maintenanceStatus summarizes the tenant's maintenance window; nil when
// it has none.
func maintenanceStatus(remote sdk.Tenant, now time.Time) *tenariumv1.MaintenanceStatus {
	m := remote.Maintenance
	if m == nil {
		return nil
	}
	s := &tenariumv1.MaintenanceStatus{Active: remote.MaintenanceActive(now), Message: m.Message, MoveTo: m.MoveTo}
	if m.Until != nil {
		u := metav1.NewTime(*m.Until)
		s.Until = &u
	}
	return s
}

// toSDKBranding converts spec branding to the API type; nil stays nil.
func toSDKBranding(b *tenariumv1.Branding) *sdk.Branding {
	if b == nil {
		return nil
	}
	return &sdk.Branding{
		DisplayName: b.DisplayName, LogoURL: b.LogoURL, IconURL: b.IconURL,
		PrimaryColor: b.PrimaryColor, AccentColor: b.AccentColor,
		SupportEmail: b.SupportEmail, SupportURL: b.SupportURL,
	}
}

// brandingUpdate returns the branding to send, or nil when nothing needs to
// change. With spec.branding set it is the spec's value (an empty value
// clears the branding). Without it the tenant's branding is left alone,
// unless the operator applied spec.branding before: then removing it from
// the spec clears the branding.
func brandingUpdate(t *tenariumv1.Tenant, remote *sdk.Branding) *sdk.Branding {
	var have sdk.Branding
	if remote != nil {
		have = *remote
	}
	want := toSDKBranding(t.Spec.Branding)
	if want == nil {
		if !t.Status.BrandingManaged || remote == nil {
			return nil
		}
		want = &sdk.Branding{}
	}
	if *want == have {
		return nil
	}
	return want
}

// sameTime reports whether a spec time (second precision) equals the
// remote time.
func sameTime(want time.Time, have *time.Time) bool {
	return have != nil && want.Truncate(time.Second).Equal(have.Truncate(time.Second))
}
