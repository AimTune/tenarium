package controller

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

func newTenant(name, slug string) *tenariumv1.Tenant {
	return &tenariumv1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       tenariumv1.TenantSpec{Slug: slug, DeletionPolicy: tenariumv1.DeletionPolicyDelete},
	}
}

// remoteGone reports whether the tenant no longer exists (or is deleted).
func remoteGone(t *testing.T, api *client.Client, id string) bool {
	t.Helper()
	rt, err := api.Tenants.Get(context.Background(), id)
	if client.IsNotFound(err) {
		return true
	}
	if err != nil {
		t.Fatal(err)
	}
	return rt.Status == sdk.StatusDeleted
}

func TestTenantLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx

	e.create(&tenariumv1.Plan{
		ObjectMeta: metav1.ObjectMeta{Name: "pro"},
		Spec: tenariumv1.PlanSpec{Name: "Pro", Features: map[string]bool{"sso": true, "audit": false},
			Limits: map[string]int64{"seats": 10}},
	})
	if _, err := e.plans.Reconcile(ctx, req("pro")); err != nil {
		t.Fatal(err)
	}

	cr := newTenant("acme", "acme")
	cr.Spec.Name = "Acme Inc"
	cr.Spec.Plan = "pro"
	cr.Spec.Labels = map[string]string{"env": "prod"}
	cr.Spec.Settings = raw(`{"theme":"dark","nested":{"a":1,"b":2}}`)
	cr.Spec.Features = map[string]bool{"audit": true}
	cr.Spec.Limits = map[string]int64{"seats": 25}
	e.create(cr)

	got := e.syncTenant("acme")
	if !slices.Contains(got.Finalizers, tenariumv1.Finalizer) {
		t.Fatalf("finalizer missing: %v", got.Finalizers)
	}
	if got.Status.ID == "" || got.Status.Phase != "active" || got.Status.Version == 0 {
		t.Fatalf("status = %+v", got.Status)
	}
	if c := condition(got.Status.Conditions, tenariumv1.ConditionSynced); c.Status != metav1.ConditionTrue {
		t.Fatalf("Synced = %+v", c)
	}
	ent := got.Status.Entitlements
	if ent == nil || ent.Plan != "pro" || !reflect.DeepEqual(ent.EnabledFeatures, []string{"audit", "sso"}) || ent.Limits["seats"] != 25 {
		t.Fatalf("entitlements = %+v", ent)
	}
	if !hasEvent(e.drainEvents(), "Created") {
		t.Fatal("no Created event")
	}

	remote, err := e.api.Tenants.Get(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Name != "Acme Inc" || remote.Plan != "pro" || remote.Labels["env"] != "prod" ||
		remote.Labels[tenariumv1.OwnerLabel] != string(cr.UID) || remote.Settings["theme"] != "dark" {
		t.Fatalf("remote = %+v", remote)
	}

	// Spec change: rename, drop a settings key and a nested key.
	got.Spec.Name = "Acme Corp"
	got.Spec.Settings = raw(`{"nested":{"a":1}}`)
	if err := e.k8s.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	e.syncTenant("acme")
	remote, _ = e.api.Tenants.Get(ctx, "acme")
	if remote.Name != "Acme Corp" || !reflect.DeepEqual(remote.Settings, map[string]any{"nested": map[string]any{"a": float64(1)}}) {
		t.Fatalf("after update: name=%q settings=%v", remote.Name, remote.Settings)
	}

	// Drift: someone changes the tenant behind the operator's back.
	if _, err := e.api.Tenants.Update(ctx, "acme", client.UpdateTenantRequest{
		Name: client.Ptr("Hacked"), Limits: &map[string]int64{"seats": 1},
	}); err != nil {
		t.Fatal(err)
	}
	e.drainEvents()
	e.syncTenant("acme")
	remote, _ = e.api.Tenants.Get(ctx, "acme")
	if remote.Name != "Acme Corp" || remote.Limits["seats"] != 25 {
		t.Fatalf("drift not repaired: %+v", remote)
	}
	if evs := e.drainEvents(); !hasEvent(evs, "name, limits") {
		t.Fatalf("events = %v", evs)
	}

	// A reconcile without changes sends no update.
	before, _ := e.api.Tenants.Get(ctx, "acme")
	e.syncTenant("acme")
	after, _ := e.api.Tenants.Get(ctx, "acme")
	if before.Version != after.Version {
		t.Fatalf("no-op reconcile changed version %d -> %d", before.Version, after.Version)
	}

	// Deletion honors the default policy (Delete).
	id := remote.ID
	if err := e.k8s.Delete(ctx, e.tenant("acme")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reconcileTenant("acme"); err != nil {
		t.Fatal(err)
	}
	if !e.gone(&tenariumv1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "default"}}) {
		t.Fatal("Tenant resource still exists")
	}
	if !remoteGone(t, e.api, id) {
		t.Fatal("remote tenant not deleted")
	}
}

func TestTenantRemoteDeletedIsRecreated(t *testing.T) {
	e := newEnv(t)
	e.create(newTenant("solo", "solo"))
	first := e.syncTenant("solo").Status.ID
	if _, err := e.api.Tenants.Delete(e.ctx, first); err != nil {
		t.Fatal(err)
	}
	// Slugs of deleted tenants may stay reserved; either way the operator
	// must notice and report the missing tenant.
	_, err := e.reconcileTenant("solo")
	evs := e.drainEvents()
	if !hasEvent(evs, EventRemoteMissing) {
		t.Fatalf("events = %v", evs)
	}
	got := e.tenant("solo")
	if err == nil {
		if got.Status.ID == "" || got.Status.ID == first {
			t.Fatalf("expected a new tenant, status = %+v", got.Status)
		}
	} else if condition(got.Status.Conditions, tenariumv1.ConditionSynced).Status != metav1.ConditionFalse {
		t.Fatalf("conditions = %+v", got.Status.Conditions)
	}
}

func TestTenantAdoption(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx
	existing, err := e.api.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "legacy", Name: "Legacy", Labels: map[string]string{"team": "x"}})
	if err != nil {
		t.Fatal(err)
	}

	cr := newTenant("legacy", "legacy")
	cr.Spec.Name = "Legacy Co"
	e.create(cr)
	res, err := e.reconcileTenant("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a slow requeue")
	}
	got := e.tenant("legacy")
	if c := condition(got.Status.Conditions, tenariumv1.ConditionSynced); c.Status != metav1.ConditionFalse || c.Reason != ReasonAlreadyExists {
		t.Fatalf("Synced = %+v", c)
	}
	if got.Status.ID != "" {
		t.Fatalf("status.id = %q", got.Status.ID)
	}
	if r, _ := e.api.Tenants.Get(ctx, "legacy"); r.Name != "Legacy" || r.Version != existing.Version {
		t.Fatalf("tenant touched without adopt annotation: %+v", r)
	}

	got.Annotations = map[string]string{tenariumv1.AnnotationAdopt: "true"}
	if err := e.k8s.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	got = e.syncTenant("legacy")
	if got.Status.ID != existing.ID || !got.Status.Adopted {
		t.Fatalf("status = %+v", got.Status)
	}
	r, _ := e.api.Tenants.Get(ctx, "legacy")
	// spec.labels is unset: existing labels are kept, the owner label added.
	if r.Name != "Legacy Co" || r.Labels["team"] != "x" || r.Labels[tenariumv1.OwnerLabel] != string(got.UID) {
		t.Fatalf("remote = %+v", r)
	}
	if !hasEvent(e.drainEvents(), EventAdopted) {
		t.Fatal("no Adopted event")
	}

	// A second resource with the same slug is refused even with adopt=true.
	other := newTenant("legacy-2", "legacy")
	other.Annotations = map[string]string{tenariumv1.AnnotationAdopt: "true"}
	e.create(other)
	if _, err := e.reconcileTenant("legacy-2"); err != nil {
		t.Fatal(err)
	}
	if c := condition(e.tenant("legacy-2").Status.Conditions, tenariumv1.ConditionSynced); c.Reason != ReasonOwnedByOther {
		t.Fatalf("Synced = %+v", c)
	}
}

func TestTenantCrashRecoveryClaimsOwnTenant(t *testing.T) {
	e := newEnv(t)
	cr := newTenant("crash", "crash")
	e.create(cr)
	// The tenant was created by this resource but the status was lost.
	if _, err := e.api.Tenants.Create(e.ctx, client.CreateTenantRequest{
		Slug: "crash", Name: "crash", Labels: map[string]string{tenariumv1.OwnerLabel: string(cr.UID)},
	}); err != nil {
		t.Fatal(err)
	}
	got := e.syncTenant("crash")
	if got.Status.Adopted || got.Status.ID == "" {
		t.Fatalf("status = %+v", got.Status)
	}
}

func TestTenantOrphanPolicy(t *testing.T) {
	e := newEnv(t)
	cr := newTenant("keep", "keep")
	cr.Spec.DeletionPolicy = tenariumv1.DeletionPolicyOrphan
	cr.Spec.Labels = map[string]string{"a": "b"}
	e.create(cr)
	id := e.syncTenant("keep").Status.ID

	if err := e.k8s.Delete(e.ctx, e.tenant("keep")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reconcileTenant("keep"); err != nil {
		t.Fatal(err)
	}
	if !e.gone(cr) {
		t.Fatal("Tenant resource still exists")
	}
	r, err := e.api.Tenants.Get(e.ctx, id)
	if err != nil || r.Status != sdk.StatusActive {
		t.Fatalf("remote = %+v, %v", r, err)
	}
	if _, ok := r.Labels[tenariumv1.OwnerLabel]; ok || r.Labels["a"] != "b" {
		t.Fatalf("labels = %v", r.Labels)
	}
}

func TestTenantParentChild(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx
	parent := newTenant("org", "org")
	child := newTenant("ws", "org-ws")
	child.Spec.Parent = &tenariumv1.ParentReference{Name: "org"}
	e.create(parent)
	e.create(child)

	// The child waits for its parent.
	res, err := e.reconcileTenant("ws")
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected requeue while waiting for the parent")
	}
	if c := condition(e.tenant("ws").Status.Conditions, tenariumv1.ConditionReady); c.Reason != ReasonWaitingForParent {
		t.Fatalf("Ready = %+v", c)
	}
	if _, err := e.api.Tenants.Get(ctx, "org-ws"); !client.IsNotFound(err) {
		t.Fatalf("child created before parent: %v", err)
	}

	// The watch maps parent changes to its children.
	pid := e.syncTenant("org").Status.ID
	if reqs := e.tenants.childrenOf(ctx, e.tenant("org")); len(reqs) != 1 || reqs[0].Name != "ws" {
		t.Fatalf("childrenOf = %v", reqs)
	}
	got := e.syncTenant("ws")
	if got.Status.ParentID != pid {
		t.Fatalf("parentID = %q, want %q", got.Status.ParentID, pid)
	}
	if r, _ := e.api.Tenants.Get(ctx, "org-ws"); r.ParentID != pid {
		t.Fatalf("remote parent = %q", r.ParentID)
	}

	// A child by slug reference.
	bySlug := newTenant("ws2", "org-ws2")
	bySlug.Spec.Parent = &tenariumv1.ParentReference{Slug: "org"}
	e.create(bySlug)
	if got := e.syncTenant("ws2"); got.Status.ParentID != pid {
		t.Fatalf("parentID = %q", got.Status.ParentID)
	}

	// The parent cannot be deleted while it has live children.
	if err := e.k8s.Delete(ctx, e.tenant("org")); err != nil {
		t.Fatal(err)
	}
	res, err = e.reconcileTenant("org")
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter == 0 || e.gone(&tenariumv1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "org", Namespace: "default"}}) {
		t.Fatal("parent deletion should be blocked")
	}
	if c := condition(e.tenant("org").Status.Conditions, tenariumv1.ConditionSynced); c.Reason != ReasonDeleteBlocked {
		t.Fatalf("Synced = %+v", c)
	}

	for _, n := range []string{"ws", "ws2"} {
		if err := e.k8s.Delete(ctx, e.tenant(n)); err != nil {
			t.Fatal(err)
		}
		if _, err := e.reconcileTenant(n); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.reconcileTenant("org"); err != nil {
		t.Fatal(err)
	}
	if !remoteGone(t, e.api, pid) {
		t.Fatal("parent not deleted")
	}
}

func TestTenantSchedule(t *testing.T) {
	e := newEnv(t)
	cr := newTenant("trial", "trial")
	at := metav1.NewTime(time.Now().Add(48 * time.Hour).Truncate(time.Second))
	cr.Spec.Schedule = []tenariumv1.ScheduledAction{
		{Action: "suspend", After: "14d", Reason: "trial ended"},
		{Action: "delete", At: &at},
	}
	e.create(cr)
	got := e.syncTenant("trial")
	if n := len(got.Status.ScheduledActions); n != 2 {
		t.Fatalf("scheduled = %+v", got.Status.ScheduledActions)
	}
	for _, s := range got.Status.ScheduledActions {
		if s.ID == "" || s.State != "pending" || s.RunAt == nil {
			t.Fatalf("scheduled action = %+v", s)
		}
	}

	// Reconciling again does not schedule twice.
	e.syncTenant("trial")
	var list struct {
		Items []scheduledAction `json:"items"`
	}
	if err := e.api.Do(e.ctx, "GET", "/v1/tenants/trial/schedule", nil, nil, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 2 {
		t.Fatalf("remote schedule = %+v", list.Items)
	}

	// Removing an entry cancels the pending action.
	got = e.tenant("trial")
	got.Spec.Schedule = got.Spec.Schedule[:1]
	if err := e.k8s.Update(e.ctx, got); err != nil {
		t.Fatal(err)
	}
	got = e.syncTenant("trial")
	if len(got.Status.ScheduledActions) != 1 || got.Status.ScheduledActions[0].Action != "suspend" {
		t.Fatalf("scheduled = %+v", got.Status.ScheduledActions)
	}
	if err := e.api.Do(e.ctx, "GET", "/v1/tenants/trial/schedule", nil, nil, &list); err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, a := range list.Items {
		states[a.Action] = a.Status
	}
	if states["delete"] != "canceled" || states["suspend"] != "pending" {
		t.Fatalf("remote states = %v", states)
	}
}

func TestTenantAPIErrorsAreRetried(t *testing.T) {
	e := newEnv(t)
	// Point the default connection at a closed port.
	ln := mustListen(t)
	addr := ln.Addr().String()
	ln.Close()
	e.tenants.Connections = &Connections{Reader: e.k8s, Default: DefaultConnection{URL: "http://" + addr, APIKey: "x"}}
	e.create(newTenant("down", "down"))
	if _, err := e.reconcileTenant("down"); err == nil {
		t.Fatal("expected an error so the request is retried with backoff")
	}
	got := e.tenant("down")
	if c := condition(got.Status.Conditions, tenariumv1.ConditionSynced); c.Status != metav1.ConditionFalse || c.Reason != ReasonConnectionError {
		t.Fatalf("Synced = %+v", c)
	}
	if !hasEvent(e.drainEvents(), EventSyncFailed) {
		t.Fatal("no SyncFailed event")
	}

	// Validation errors from the API are reported as APIError.
	e.tenants.Connections = &Connections{Reader: e.k8s, Default: DefaultConnection{URL: e.api.BaseURL(), APIKey: testAPIKey}}
	bad := newTenant("bad", "bad")
	bad.Spec.Labels = map[string]string{"not a valid key!": "x"}
	e.create(bad)
	_, err := e.reconcileTenant("bad")
	if !client.IsValidation(err) {
		t.Fatalf("err = %v", err)
	}
	if c := condition(e.tenant("bad").Status.Conditions, tenariumv1.ConditionSynced); c.Reason != ReasonAPIError {
		t.Fatalf("Synced = %+v", c)
	}

	// No connection at all.
	e.tenants.Connections = &Connections{Reader: e.k8s}
	if _, err := e.reconcileTenant("down"); err == nil {
		t.Fatal("expected errNoConnection")
	}
}

func TestTenantUsesTenariumConnection(t *testing.T) {
	e := newEnv(t)
	e.create(secret("tenarium-creds", map[string]string{"api-key": testAPIKey}))
	e.create(&tenariumv1.TenariumConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "main"},
		Spec: tenariumv1.TenariumConnectionSpec{URL: e.api.BaseURL(),
			APIKeySecretRef: tenariumv1.SecretKeyReference{Name: "tenarium-creds"}},
	})
	// No default connection: only connectionRef works.
	e.tenants.Connections = &Connections{Reader: e.k8s}
	cr := newTenant("via-conn", "via-conn")
	cr.Spec.ConnectionRef = &tenariumv1.ConnectionReference{Name: "main"}
	e.create(cr)
	e.syncTenant("via-conn")
}

func TestMergePatch(t *testing.T) {
	from := map[string]any{"a": 1.0, "b": map[string]any{"x": 1.0, "y": 2.0}, "c": "gone", "d": []any{1.0}}
	to := map[string]any{"a": 1.0, "b": map[string]any{"x": 1.0, "z": 3.0}, "d": []any{2.0}, "e": true}
	want := map[string]any{"b": map[string]any{"y": nil, "z": 3.0}, "c": nil, "d": []any{2.0}, "e": true}
	if got := mergePatch(from, to); !reflect.DeepEqual(got, want) {
		t.Fatalf("mergePatch = %v, want %v", got, want)
	}
	if got := mergePatch(to, to); got != nil {
		t.Fatalf("equal maps: %v", got)
	}
}

func TestScheduleKeyStable(t *testing.T) {
	at := metav1.NewTime(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	a := tenariumv1.ScheduledAction{Action: "delete", At: &at}
	b := tenariumv1.ScheduledAction{Action: "delete", At: &at}
	c := tenariumv1.ScheduledAction{Action: "suspend", At: &at}
	if scheduleKey(a) != scheduleKey(b) || scheduleKey(a) == scheduleKey(c) {
		t.Fatal("schedule keys are not stable or not distinct")
	}
}
