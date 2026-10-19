package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/AimTune/tenarium/pkg/client"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

func TestRolloutLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx
	e.create(&tenariumv1.Rollout{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-export"},
		Spec: tenariumv1.RolloutSpec{Feature: "audit_export", Enabled: true, Percentage: 10,
			Plans: []string{"pro"}, Regions: []string{"eu"}, Labels: map[string]string{"beta": "yes"}},
	})
	if _, err := e.rollouts.Reconcile(ctx, req("audit-export")); err != nil {
		t.Fatal(err)
	}
	ro := e.rollout("audit-export")
	if ro.Status.Feature != "audit_export" || condition(ro.Status.Conditions, tenariumv1.ConditionReady).Status != metav1.ConditionTrue {
		t.Fatalf("status = %+v", ro.Status)
	}
	remote, err := e.api.Rollouts.Get(ctx, "audit_export")
	if err != nil || !remote.Enabled || remote.Percentage != 10 || remote.Plans[0] != "pro" || remote.Labels["beta"] != "yes" {
		t.Fatalf("remote = %+v, %v", remote, err)
	}

	// An idle sync does not rewrite the rollout.
	if _, err := e.rollouts.Reconcile(ctx, req("audit-export")); err != nil {
		t.Fatal(err)
	}
	if again, _ := e.api.Rollouts.Get(ctx, "audit_export"); !again.UpdatedAt.Equal(remote.UpdatedAt) {
		t.Fatal("idle sync rewrote the rollout")
	}

	// Update.
	ro = e.rollout("audit-export")
	ro.Spec.Percentage = 50
	ro.Spec.Plans = nil
	if err := e.k8s.Update(ctx, ro); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rollouts.Reconcile(ctx, req("audit-export")); err != nil {
		t.Fatal(err)
	}
	if remote, _ = e.api.Rollouts.Get(ctx, "audit_export"); remote.Percentage != 50 || len(remote.Plans) != 0 {
		t.Fatalf("remote = %+v", remote)
	}

	// Drift repair.
	remote.Enabled = false
	if _, err := e.api.Rollouts.Put(ctx, "audit_export", remote); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rollouts.Reconcile(ctx, req("audit-export")); err != nil {
		t.Fatal(err)
	}
	if remote, _ = e.api.Rollouts.Get(ctx, "audit_export"); !remote.Enabled {
		t.Fatal("drift not repaired")
	}
	if !hasEvent(e.drainEvents(), EventDriftRepaired) {
		t.Fatal("no DriftRepaired event")
	}

	// Deleted outside Kubernetes: recreated.
	if err := e.api.Rollouts.Delete(ctx, "audit_export"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rollouts.Reconcile(ctx, req("audit-export")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.api.Rollouts.Get(ctx, "audit_export"); err != nil {
		t.Fatalf("not recreated: %v", err)
	}

	// Delete.
	if err := e.k8s.Delete(ctx, e.rollout("audit-export")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rollouts.Reconcile(ctx, req("audit-export")); err != nil {
		t.Fatal(err)
	}
	if !e.gone(&tenariumv1.Rollout{ObjectMeta: metav1.ObjectMeta{Name: "audit-export", Namespace: "default"}}) {
		t.Fatal("Rollout resource still exists")
	}
	if _, err := e.api.Rollouts.Get(ctx, "audit_export"); !client.IsNotFound(err) {
		t.Fatalf("remote rollout not deleted: %v", err)
	}
}

func TestRolloutAdoptionAndOrphan(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx
	if _, err := e.api.Rollouts.Put(ctx, "dark-mode", client.Rollout{Percentage: 5, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// Feature defaults to metadata.name.
	e.create(&tenariumv1.Rollout{ObjectMeta: metav1.ObjectMeta{Name: "dark-mode"},
		Spec: tenariumv1.RolloutSpec{Percentage: 100, Enabled: true, DeletionPolicy: tenariumv1.DeletionPolicyOrphan}})
	if _, err := e.rollouts.Reconcile(ctx, req("dark-mode")); err != nil {
		t.Fatal(err)
	}
	if c := condition(e.rollout("dark-mode").Status.Conditions, tenariumv1.ConditionSynced); c.Reason != ReasonAlreadyExists {
		t.Fatalf("Synced = %+v", c)
	}
	if r, _ := e.api.Rollouts.Get(ctx, "dark-mode"); r.Percentage != 5 {
		t.Fatal("rollout changed without adopt annotation")
	}

	ro := e.rollout("dark-mode")
	ro.Annotations = map[string]string{tenariumv1.AnnotationAdopt: "true"}
	if err := e.k8s.Update(ctx, ro); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rollouts.Reconcile(ctx, req("dark-mode")); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.api.Rollouts.Get(ctx, "dark-mode"); r.Percentage != 100 {
		t.Fatalf("adopted rollout not updated: %+v", r)
	}
	if ro = e.rollout("dark-mode"); ro.Status.Feature != "dark-mode" {
		t.Fatalf("status = %+v", ro.Status)
	}

	// Orphan: the remote rollout stays.
	if err := e.k8s.Delete(ctx, ro); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rollouts.Reconcile(ctx, req("dark-mode")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.api.Rollouts.Get(ctx, "dark-mode"); err != nil {
		t.Fatalf("orphaned rollout was deleted: %v", err)
	}
}

func TestRolloutInvalidSpecFails(t *testing.T) {
	e := newEnv(t)
	// Rejected by the server (a tenant cannot be both included and
	// excluded): the Synced condition carries the API error.
	e.create(&tenariumv1.Rollout{ObjectMeta: metav1.ObjectMeta{Name: "bad"},
		Spec: tenariumv1.RolloutSpec{Include: []string{"t1"}, Exclude: []string{"t1"}}})
	if _, err := e.rollouts.Reconcile(e.ctx, req("bad")); err == nil {
		t.Fatal("expected an error")
	}
	ro := e.rollout("bad")
	if c := condition(ro.Status.Conditions, tenariumv1.ConditionSynced); c.Status != metav1.ConditionFalse || c.Reason != ReasonAPIError {
		t.Fatalf("Synced = %+v", c)
	}
	if ro.Status.Feature != "" {
		t.Fatalf("status = %+v", ro.Status)
	}
}

func TestRolloutEqual(t *testing.T) {
	a := client.Rollout{Percentage: 10, Enabled: true, Plans: []string{"pro"}, Labels: map[string]string{"a": "b"}}
	b := a
	b.Plans = []string{"pro"}
	b.Feature = "ignored"
	if !rolloutEqual(a, b) {
		t.Fatal("equal rollouts differ")
	}
	if !rolloutEqual(client.Rollout{Include: []string{}}, client.Rollout{}) {
		t.Fatal("empty and nil lists differ")
	}
	for _, mod := range []func(*client.Rollout){
		func(r *client.Rollout) { r.Percentage = 11 },
		func(r *client.Rollout) { r.Enabled = false },
		func(r *client.Rollout) { r.Regions = []string{"eu"} },
		func(r *client.Rollout) { r.Labels = nil },
		func(r *client.Rollout) { r.Exclude = []string{"x"} },
	} {
		c := a
		mod(&c)
		if rolloutEqual(a, c) {
			t.Fatalf("difference not detected: %+v", c)
		}
	}
	ro := &tenariumv1.Rollout{ObjectMeta: metav1.ObjectMeta{Name: "x"}, Spec: tenariumv1.RolloutSpec{Percentage: 3}}
	if d := desiredRollout(ro); d.Feature != "x" || d.Percentage != 3 {
		t.Fatalf("desired = %+v", d)
	}
}
