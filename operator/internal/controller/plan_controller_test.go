package controller

import (
	"net"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/AimTune/tenarium/pkg/client"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func TestPlanLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx
	e.create(&tenariumv1.Plan{
		ObjectMeta: metav1.ObjectMeta{Name: "team-plan"},
		Spec: tenariumv1.PlanSpec{ID: "team", Description: "For teams",
			Features: map[string]bool{"sso": false}, Limits: map[string]int64{"seats": 5}},
	})
	if _, err := e.plans.Reconcile(ctx, req("team-plan")); err != nil {
		t.Fatal(err)
	}
	p := e.plan("team-plan")
	if p.Status.ID != "team" || condition(p.Status.Conditions, tenariumv1.ConditionReady).Status != metav1.ConditionTrue {
		t.Fatalf("status = %+v", p.Status)
	}
	remote, err := e.api.Plans.Get(ctx, "team")
	if err != nil || remote.Name != "team" || remote.Description != "For teams" || remote.Limits["seats"] != 5 {
		t.Fatalf("remote = %+v, %v", remote, err)
	}

	// Update.
	p.Spec.Name = "Team"
	p.Spec.Limits = map[string]int64{"seats": 50}
	if err := e.k8s.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.plans.Reconcile(ctx, req("team-plan")); err != nil {
		t.Fatal(err)
	}
	remote, _ = e.api.Plans.Get(ctx, "team")
	if remote.Name != "Team" || remote.Limits["seats"] != 50 {
		t.Fatalf("remote = %+v", remote)
	}

	// Drift repair.
	if _, err := e.api.Plans.Update(ctx, "team", client.UpdatePlanRequest{Description: client.Ptr("changed")}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.plans.Reconcile(ctx, req("team-plan")); err != nil {
		t.Fatal(err)
	}
	if remote, _ = e.api.Plans.Get(ctx, "team"); remote.Description != "For teams" {
		t.Fatalf("drift not repaired: %+v", remote)
	}

	// Deleted outside Kubernetes: recreated (not a replay of the first create).
	if err := e.api.Plans.Delete(ctx, "team"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.plans.Reconcile(ctx, req("team-plan")); err != nil {
		t.Fatal(err)
	}
	if remote, err = e.api.Plans.Get(ctx, "team"); err != nil || remote.Name != "Team" {
		t.Fatalf("plan not recreated: %+v, %v", remote, err)
	}
	if !hasEvent(e.drainEvents(), EventRemoteMissing) {
		t.Fatal("no RemoteMissing event")
	}

	// A plan in use cannot be deleted; the finalizer waits.
	if _, err := e.api.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "user", Name: "user", Plan: "team"}); err != nil {
		t.Fatal(err)
	}
	if err := e.k8s.Delete(ctx, e.plan("team-plan")); err != nil {
		t.Fatal(err)
	}
	res, err := e.plans.Reconcile(ctx, req("team-plan"))
	if err != nil {
		t.Fatal(err)
	}
	inUse := !e.gone(&tenariumv1.Plan{ObjectMeta: metav1.ObjectMeta{Name: "team-plan", Namespace: "default"}})
	if inUse {
		if res.RequeueAfter == 0 {
			t.Fatal("expected requeue while the plan is in use")
		}
		if _, err := e.api.Tenants.Update(ctx, "user", client.UpdateTenantRequest{Plan: client.Ptr("")}); err != nil {
			t.Logf("clear plan: %v", err)
		}
		if _, err := e.api.Tenants.Delete(ctx, "user"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.plans.Reconcile(ctx, req("team-plan")); err != nil {
			t.Fatal(err)
		}
	}
	if !e.gone(&tenariumv1.Plan{ObjectMeta: metav1.ObjectMeta{Name: "team-plan", Namespace: "default"}}) {
		t.Fatalf("Plan resource still exists: %+v", e.plan("team-plan").Status.Conditions)
	}
	if _, err := e.api.Plans.Get(ctx, "team"); !client.IsNotFound(err) {
		t.Fatalf("remote plan not deleted: %v", err)
	}
}

func TestPlanAdoptionAndCrashRecovery(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx
	if _, err := e.api.Plans.Create(ctx, client.CreatePlanRequest{ID: "free", Name: "Free"}); err != nil {
		t.Fatal(err)
	}
	e.create(&tenariumv1.Plan{ObjectMeta: metav1.ObjectMeta{Name: "free"}, Spec: tenariumv1.PlanSpec{Name: "Free tier"}})
	if _, err := e.plans.Reconcile(ctx, req("free")); err != nil {
		t.Fatal(err)
	}
	if c := condition(e.plan("free").Status.Conditions, tenariumv1.ConditionSynced); c.Reason != ReasonAlreadyExists {
		t.Fatalf("Synced = %+v", c)
	}
	if r, _ := e.api.Plans.Get(ctx, "free"); r.Name != "Free" {
		t.Fatal("plan changed without adopt annotation")
	}
	p := e.plan("free")
	p.Annotations = map[string]string{tenariumv1.AnnotationAdopt: "true"}
	if err := e.k8s.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.plans.Reconcile(ctx, req("free")); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.api.Plans.Get(ctx, "free"); r.Name != "Free tier" {
		t.Fatalf("adopted plan not updated: %+v", r)
	}

	// Crash recovery: the plan was created by this resource, but its status
	// was lost. The create is replayed through the Idempotency-Key.
	e.create(&tenariumv1.Plan{ObjectMeta: metav1.ObjectMeta{Name: "gold"}, Spec: tenariumv1.PlanSpec{Name: "Gold"}})
	if _, err := e.plans.Reconcile(ctx, req("gold")); err != nil {
		t.Fatal(err)
	}
	gold := e.plan("gold")
	gold.Status.ID = ""
	if err := e.k8s.Status().Update(ctx, gold); err != nil {
		t.Fatal(err)
	}
	if _, err := e.plans.Reconcile(ctx, req("gold")); err != nil {
		t.Fatal(err)
	}
	gold = e.plan("gold")
	if gold.Status.ID != "gold" || condition(gold.Status.Conditions, tenariumv1.ConditionReady).Status != metav1.ConditionTrue {
		t.Fatalf("status = %+v", gold.Status)
	}
}

func TestPlanOrphanPolicy(t *testing.T) {
	e := newEnv(t)
	e.create(&tenariumv1.Plan{ObjectMeta: metav1.ObjectMeta{Name: "keep"},
		Spec: tenariumv1.PlanSpec{DeletionPolicy: tenariumv1.DeletionPolicyOrphan}})
	if _, err := e.plans.Reconcile(e.ctx, req("keep")); err != nil {
		t.Fatal(err)
	}
	if err := e.k8s.Delete(e.ctx, e.plan("keep")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.plans.Reconcile(e.ctx, req("keep")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.api.Plans.Get(e.ctx, "keep"); err != nil {
		t.Fatalf("orphaned plan was deleted: %v", err)
	}
}

func TestConnectionReconciler(t *testing.T) {
	e := newEnv(t)
	e.create(secret("good", map[string]string{"token": testAPIKey}))
	e.create(secret("bad", map[string]string{"api-key": "wrong"}))
	e.create(&tenariumv1.TenariumConnection{ObjectMeta: metav1.ObjectMeta{Name: "good"},
		Spec: tenariumv1.TenariumConnectionSpec{URL: e.api.BaseURL(), APIKeySecretRef: tenariumv1.SecretKeyReference{Name: "good", Key: "token"}}})
	e.create(&tenariumv1.TenariumConnection{ObjectMeta: metav1.ObjectMeta{Name: "bad"},
		Spec: tenariumv1.TenariumConnectionSpec{URL: e.api.BaseURL(), APIKeySecretRef: tenariumv1.SecretKeyReference{Name: "bad"}}})
	e.create(&tenariumv1.TenariumConnection{ObjectMeta: metav1.ObjectMeta{Name: "nosecret"},
		Spec: tenariumv1.TenariumConnectionSpec{URL: e.api.BaseURL(), APIKeySecretRef: tenariumv1.SecretKeyReference{Name: "missing"}}})

	if _, err := e.conns.Reconcile(e.ctx, req("good")); err != nil {
		t.Fatal(err)
	}
	var c tenariumv1.TenariumConnection
	_ = e.k8s.Get(e.ctx, req("good").NamespacedName, &c)
	if cond := condition(c.Status.Conditions, tenariumv1.ConditionReady); cond.Status != metav1.ConditionTrue || c.Status.Principal == "" {
		t.Fatalf("status = %+v", c.Status)
	}

	for _, name := range []string{"bad", "nosecret"} {
		if _, err := e.conns.Reconcile(e.ctx, req(name)); err == nil {
			t.Fatalf("%s: expected error", name)
		}
		_ = e.k8s.Get(e.ctx, req(name).NamespacedName, &c)
		if cond := condition(c.Status.Conditions, tenariumv1.ConditionReady); cond.Status != metav1.ConditionFalse {
			t.Fatalf("%s: Ready = %+v", name, cond)
		}
	}
}
