//go:build envtest

package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"

	"github.com/AimTune/tenarium/pkg/client"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

// TestEnvtest runs the manager against a real API server (envtest) and a
// real in-process Tenarium server. It needs the envtest binaries:
//
//	KUBEBUILDER_ASSETS=$(setup-envtest use -p path 1.37.x) go test -tags envtest ./...
//
// controller-runtime v0.25 envtest does not build on Windows; use Linux,
// WSL or "make test-envtest-docker".
func TestEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set; see operator/README.md")
	}
	oldWait := waitRequeue
	waitRequeue = 300 * time.Millisecond
	t.Cleanup(func() { waitRequeue = oldWait })

	te := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = te.Stop() })

	url := startTenarium(t)
	api, _ := client.New(url, client.WithAPIKey(testAPIKey))
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: testScheme(), Metrics: metricsserver.Options{BindAddress: "0"}})
	if err != nil {
		t.Fatal(err)
	}
	conns := &Connections{Reader: mgr.GetAPIReader(), Default: DefaultConnection{URL: url, APIKey: testAPIKey}}
	rec := mgr.GetEventRecorder("tenarium-operator")
	if err := (&TenantReconciler{Client: mgr.GetClient(), Connections: conns, Recorder: rec, ResyncPeriod: time.Second, MaxBackoff: time.Second}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	if err := (&PlanReconciler{Client: mgr.GetClient(), Connections: conns, Recorder: rec, ResyncPeriod: time.Second, MaxBackoff: time.Second}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	if err := (&RolloutReconciler{Client: mgr.GetClient(), Connections: conns, Recorder: rec, ResyncPeriod: time.Second, MaxBackoff: time.Second}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	if err := (&TenantTemplateReconciler{Client: mgr.GetClient(), Connections: conns, Recorder: rec, ResyncPeriod: time.Second, MaxBackoff: time.Second}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	if err := (&ConnectionReconciler{Client: mgr.GetClient(), Connections: conns, Recorder: rec}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	k8s, err := ctrlclient.New(cfg, ctrlclient.Options{Scheme: testScheme()})
	if err != nil {
		t.Fatal(err)
	}

	eventually := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	ready := func(name string) func() bool {
		return func() bool {
			var tn tenariumv1.Tenant
			if err := k8s.Get(ctx, ctrlclient.ObjectKey{Namespace: "default", Name: name}, &tn); err != nil {
				return false
			}
			return meta.IsStatusConditionTrue(tn.Status.Conditions, tenariumv1.ConditionReady)
		}
	}

	plan := &tenariumv1.Plan{ObjectMeta: metav1.ObjectMeta{Name: "starter", Namespace: "default"},
		Spec: tenariumv1.PlanSpec{Limits: map[string]int64{"seats": 3}}}
	child := &tenariumv1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "team", Namespace: "default"},
		Spec: tenariumv1.TenantSpec{Slug: "big-team", Parent: &tenariumv1.ParentReference{Name: "big"}}}
	parent := &tenariumv1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "big", Namespace: "default"},
		Spec: tenariumv1.TenantSpec{Slug: "big", Plan: "starter", Settings: raw(`{"region":"eu"}`)}}
	// Child first: it must wait for its parent.
	for _, o := range []ctrlclient.Object{child, plan, parent} {
		if err := k8s.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	eventually("parent ready", ready("big"))
	eventually("child ready", ready("team"))

	var gotChild, gotParent tenariumv1.Tenant
	_ = k8s.Get(ctx, ctrlclient.ObjectKeyFromObject(child), &gotChild)
	_ = k8s.Get(ctx, ctrlclient.ObjectKeyFromObject(parent), &gotParent)
	if gotChild.Status.ParentID != gotParent.Status.ID || gotChild.Status.Entitlements == nil ||
		gotChild.Status.Entitlements.Plan != "starter" || gotChild.Status.ObservedGeneration != gotChild.Generation {
		t.Fatalf("child status = %+v", gotChild.Status)
	}
	if gotParent.Spec.DeletionPolicy != tenariumv1.DeletionPolicyDelete {
		t.Fatalf("deletionPolicy default = %q", gotParent.Spec.DeletionPolicy)
	}

	// CRD validation (CEL): slug and parent are immutable, parent needs
	// exactly one of name/slug.
	gotParent.Spec.Slug = "renamed"
	if err := k8s.Update(ctx, &gotParent); err == nil || !strings.Contains(err.Error(), "slug is immutable") {
		t.Fatalf("slug change: %v", err)
	}
	bad := &tenariumv1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "default"},
		Spec: tenariumv1.TenantSpec{Slug: "bad", Parent: &tenariumv1.ParentReference{Name: "a", Slug: "b"}}}
	if err := k8s.Create(ctx, bad); err == nil || !strings.Contains(err.Error(), "exactly one of name and slug") {
		t.Fatalf("bad parent: %v", err)
	}

	// Drift is repaired by the periodic resync.
	if _, err := api.Tenants.Update(ctx, "big", client.UpdateTenantRequest{Name: client.Ptr("drifted")}); err != nil {
		t.Fatal(err)
	}
	eventually("drift repaired", func() bool {
		r, err := api.Tenants.Get(ctx, "big")
		return err == nil && r.Name == "big"
	})

	// Rollouts and templates, and a tenant created from a template that is
	// then moved to another region.
	rollout := &tenariumv1.Rollout{ObjectMeta: metav1.ObjectMeta{Name: "new-editor", Namespace: "default"},
		Spec: tenariumv1.RolloutSpec{Enabled: true, Percentage: 20, Plans: []string{"starter"}}}
	tmpl := &tenariumv1.TenantTemplate{ObjectMeta: metav1.ObjectMeta{Name: "startup", Namespace: "default"},
		Spec: tenariumv1.TenantTemplateSpec{Plan: "starter", Region: "eu", Settings: raw(`{"theme":"light"}`),
			Branding: &tenariumv1.Branding{PrimaryColor: "#123456"}}}
	for _, o := range []ctrlclient.Object{rollout, tmpl} {
		if err := k8s.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	eventually("rollout synced", func() bool {
		r, err := api.Rollouts.Get(ctx, "new-editor")
		return err == nil && r.Percentage == 20
	})
	eventually("template synced", func() bool {
		r, err := api.Templates.Get(ctx, "startup")
		return err == nil && r.Region == "eu"
	})
	var gotRollout tenariumv1.Rollout
	_ = k8s.Get(ctx, ctrlclient.ObjectKeyFromObject(rollout), &gotRollout)
	gotRollout.Spec.Percentage = 101
	if err := k8s.Update(ctx, &gotRollout); err == nil || !strings.Contains(err.Error(), "percentage") {
		t.Fatalf("percentage 101: %v", err)
	}
	gotRollout.Spec.Percentage = 20
	gotRollout.Spec.Feature = "other"
	if err := k8s.Update(ctx, &gotRollout); err == nil || !strings.Contains(err.Error(), "feature is immutable") {
		t.Fatalf("feature change: %v", err)
	}
	fromTpl := &tenariumv1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "tpl-user", Namespace: "default"},
		Spec: tenariumv1.TenantSpec{Slug: "tpl-user", Template: "startup", AddOns: []string{}}}
	if err := k8s.Create(ctx, fromTpl); err != nil {
		t.Fatal(err)
	}
	eventually("template tenant ready", ready("tpl-user"))
	if r, _ := api.Tenants.Get(ctx, "tpl-user"); r.Region != "eu" || r.Plan != "starter" || r.Branding == nil {
		t.Fatalf("template not applied: %+v", r)
	}
	_ = k8s.Get(ctx, ctrlclient.ObjectKeyFromObject(fromTpl), fromTpl)
	fromTpl.Spec.Region = "us"
	if err := k8s.Update(ctx, fromTpl); err != nil {
		t.Fatal(err)
	}
	eventually("tenant moved", func() bool {
		var tn tenariumv1.Tenant
		return k8s.Get(ctx, ctrlclient.ObjectKeyFromObject(fromTpl), &tn) == nil && tn.Status.Region == "us" && tn.Status.Health != nil
	})
	for _, o := range []ctrlclient.Object{fromTpl, rollout, tmpl} {
		if err := k8s.Delete(ctx, o); err != nil {
			t.Fatal(err)
		}
		eventually("deleted "+o.GetName(), func() bool {
			return k8s.Get(ctx, ctrlclient.ObjectKeyFromObject(o), o) != nil
		})
	}
	if _, err := api.Rollouts.Get(ctx, "new-editor"); !client.IsNotFound(err) {
		t.Fatalf("remote rollout not deleted: %v", err)
	}
	if _, err := api.Templates.Get(ctx, "startup"); !client.IsNotFound(err) {
		t.Fatalf("remote template not deleted: %v", err)
	}

	// Deleting both at once: the parent waits for the child.
	pid := gotParent.Status.ID
	for _, o := range []ctrlclient.Object{parent, child, plan} {
		if err := k8s.Delete(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	for _, o := range []ctrlclient.Object{child, parent, plan} {
		eventually("deleted "+o.GetName(), func() bool {
			return k8s.Get(ctx, ctrlclient.ObjectKeyFromObject(o), o) != nil
		})
	}
	if !remoteGone(t, api, pid) {
		t.Fatal("remote parent not deleted")
	}
	if _, err := api.Plans.Get(ctx, "starter"); !client.IsNotFound(err) {
		t.Fatalf("remote plan not deleted: %v", err)
	}
}

// TestSamplesValid creates every object of config/samples in a real API
// server, so the samples stay valid against the CRD schemas and CEL rules.
func TestSamplesValid(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set; see operator/README.md")
	}
	te := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = te.Stop() })
	k8s, err := ctrlclient.New(cfg, ctrlclient.Options{Scheme: testScheme()})
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join("..", "..", "config", "samples", "*.yaml"))
	n := 0
	for _, f := range files {
		if filepath.Base(f) == "kustomization.yaml" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, doc := range strings.Split(string(data), "\n---") {
			var u unstructured.Unstructured
			if err := yaml.Unmarshal([]byte(doc), &u.Object); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if len(u.Object) == 0 {
				continue
			}
			if err := k8s.Create(context.Background(), &u); err != nil {
				t.Fatalf("%s: %s %s: %v", f, u.GetKind(), u.GetName(), err)
			}
			n++
		}
	}
	if n < 9 {
		t.Fatalf("only %d sample objects", n)
	}
}
