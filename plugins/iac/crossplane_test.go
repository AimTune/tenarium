package iac

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

var claimGVR = schema.GroupVersionResource{Group: "platform.acme.io", Version: "v1alpha1", Resource: "databases"}

const claimManifest = `apiVersion: platform.acme.io/v1alpha1
kind: Database
metadata:
  name: tenant-{{.Slug}}
  namespace: tenants
  annotations:
    acme.io/owner: "{{.Name}}"
spec:
  plan: {{.Plan}}
  storageGB: {{index .Entitlements.Limits "cpu"}}
  labels: {{json .Labels}}
  writeConnectionSecretToRef:
    name: tenant-{{.Slug}}-db
`

func crossplaneConfig() map[string]any {
	return map[string]any{
		"engine": "crossplane",
		"crossplane": map[string]any{
			"manifest":      claimManifest,
			"resource":      "databases",
			"poll_interval": "5ms",
		},
	}
}

type xpEnv struct {
	p    *Plugin
	reg  *sdktest.Registrar
	kube *dynamicfake.FakeDynamicClient
}

func setupCrossplane(t *testing.T, cfg map[string]any, objs ...runtime.Object) *xpEnv {
	t.Helper()
	kube := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		claimGVR:   "DatabaseList",
		secretsGVR: "SecretList",
	}, objs...)
	p := New(nil, kube)
	reg := sdktest.NewRegistrar(cfg)
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"cpu": 4}})
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	return &xpEnv{p: p, reg: reg, kube: kube}
}

// becomeReady makes created claims Ready with status fields, like the
// Crossplane controllers would.
func (e *xpEnv) becomeReady() {
	e.kube.PrependReactor("create", "databases", func(a k8stesting.Action) (bool, runtime.Object, error) {
		u := a.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured)
		_ = unstructured.SetNestedSlice(u.Object, []any{
			map[string]any{"type": "Synced", "status": "True", "reason": "ReconcileSuccess"},
			map[string]any{"type": "Ready", "status": "True", "reason": "Available", "lastTransitionTime": "2026-01-02T03:04:05Z"},
		}, "status", "conditions")
		_ = unstructured.SetNestedField(u.Object, "db.acme.internal", "status", "endpoint")
		return false, nil, nil
	})
}

func (e *xpEnv) claim(t *testing.T, name string) *unstructured.Unstructured {
	t.Helper()
	u, err := e.kube.Resource(claimGVR).Namespace("tenants").Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func secret(ns, name string, keys ...string) *unstructured.Unstructured {
	data := map[string]any{}
	for _, k := range keys {
		data[k] = "c2VjcmV0" // "secret"
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"data":     data,
	}}
}

func TestCrossplaneProvision(t *testing.T) {
	ctx := context.Background()
	e := setupCrossplane(t, crossplaneConfig(), secret("tenants", "tenant-acme-db", "password", "username", "endpoint"))
	e.becomeReady()
	tn := e.reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "pro", Labels: map[string]string{"tier": "gold"}, Version: 1})
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	u := e.claim(t, "tenant-acme")
	if u.GetLabels()[LabelTenantID] != tn.ID || u.GetLabels()[LabelManagedBy] != "tenarium" || u.GetAnnotations()["acme.io/owner"] != "Acme" {
		t.Errorf("metadata = %v %v", u.GetLabels(), u.GetAnnotations())
	}
	if plan, _, _ := unstructured.NestedString(u.Object, "spec", "plan"); plan != "pro" {
		t.Errorf("spec.plan = %q", plan)
	}
	if gb, _, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", "storageGB"); gb != int64(4) {
		t.Errorf("spec.storageGB = %#v", gb)
	}
	if l, _, _ := unstructured.NestedStringMap(u.Object, "spec", "labels"); l["tier"] != "gold" {
		t.Errorf("spec.labels = %v", l)
	}

	rec := serve(e.reg, &sdk.Principal{Subject: "admin"}, "/tenants/acme/outputs")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET outputs = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "c2VjcmV0") {
		t.Fatalf("secret value served: %s", rec.Body)
	}
	var resp OutputsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Engine != "crossplane" || resp.Ready == nil || !*resp.Ready || resp.Outputs["endpoint"].Value != "db.acme.internal" {
		t.Errorf("response = %s", rec.Body)
	}
	if _, ok := resp.Outputs["conditions"]; ok {
		t.Error("conditions exposed as an output")
	}
	cs := resp.ConnectionSecret
	if cs == nil || cs.Name != "tenant-acme-db" || cs.Namespace != "tenants" || !slices.Equal(cs.Keys, []string{"endpoint", "password", "username"}) {
		t.Errorf("connection secret = %+v", cs)
	}

	// Re-apply after a plan change updates the spec in place and keeps
	// status and foreign labels.
	u.SetLabels(map[string]string{LabelTenantID: tn.ID, "other": "kept"})
	if _, err := e.kube.Resource(claimGVR).Namespace("tenants").Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	tn.Plan = "enterprise"
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	u = e.claim(t, "tenant-acme")
	if plan, _, _ := unstructured.NestedString(u.Object, "spec", "plan"); plan != "enterprise" {
		t.Errorf("spec.plan after update = %q", plan)
	}
	if u.GetLabels()["other"] != "kept" || u.GetLabels()[LabelManagedBy] != "tenarium" {
		t.Errorf("labels after update = %v", u.GetLabels())
	}

	// Deprovision deletes the claim and waits until it is gone.
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := e.kube.Resource(claimGVR).Namespace("tenants").Get(ctx, "tenant-acme", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("claim still exists: %v", err)
	}
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal("second deprovision:", err)
	}
	if rec := serve(e.reg, &sdk.Principal{Subject: "admin"}, "/tenants/acme/outputs"); rec.Code != http.StatusNotFound {
		t.Errorf("outputs after delete = %d", rec.Code)
	}
}

func TestCrossplaneNeverAdopts(t *testing.T) {
	ctx := context.Background()
	foreign := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "platform.acme.io/v1alpha1", "kind": "Database",
		"metadata": map[string]any{"name": "tenant-acme", "namespace": "tenants",
			"labels": map[string]any{LabelTenantID: "someone-else"}},
		"spec": map[string]any{"plan": "free"},
	}}
	e := setupCrossplane(t, crossplaneConfig(), foreign)
	tn := e.reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	err := e.p.Provision(ctx, tn)
	if !errors.Is(err, errNotOwned) {
		t.Fatalf("provision = %v", err)
	}
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := e.kube.Resource(claimGVR).Namespace("tenants").Get(ctx, "tenant-acme", metav1.GetOptions{}); err != nil {
		t.Fatalf("foreign claim deleted: %v", err)
	}
	if rec := serve(e.reg, &sdk.Principal{Subject: "admin"}, "/tenants/acme/outputs"); rec.Code != http.StatusNotFound {
		t.Errorf("outputs of a foreign claim = %d", rec.Code)
	}
}

func TestCrossplaneWaitTimeout(t *testing.T) {
	cfg := crossplaneConfig()
	cfg["timeout"] = "60ms"
	e := setupCrossplane(t, cfg)
	// Not ready: the composition reports a problem.
	e.kube.PrependReactor("create", "databases", func(a k8stesting.Action) (bool, runtime.Object, error) {
		u := a.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured)
		_ = unstructured.SetNestedSlice(u.Object, []any{
			map[string]any{"type": "Ready", "status": "False", "reason": "Creating"},
			map[string]any{"type": "Synced", "status": "False", "reason": "ReconcileError", "message": "quota exceeded"},
		}, "status", "conditions")
		return false, nil, nil
	})
	start := time.Now()
	err := e.p.Provision(context.Background(), e.reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"}))
	if err == nil || !strings.Contains(err.Error(), "not ready") || !strings.Contains(err.Error(), "quota exceeded") ||
		!strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not honored")
	}
}

func TestCrossplaneNoWaitClusterScoped(t *testing.T) {
	ctx := context.Background()
	gvr := schema.GroupVersionResource{Group: "platform.acme.io", Version: "v1alpha1", Resource: "xdatabases"}
	kube := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		gvr: "XDatabaseList", secretsGVR: "SecretList",
	})
	p := New(nil, kube)
	reg := sdktest.NewRegistrar(map[string]any{
		"engine": "crossplane",
		"crossplane": map[string]any{
			"manifest": "apiVersion: platform.acme.io/v1alpha1\nkind: XDatabase\nmetadata:\n  name: '{{dns1123 .ID}}'\nspec: {}\n",
			"resource": "xdatabases",
			"wait":     false,
		},
	})
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.Resource(gvr).Get(ctx, tn.ID, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
}
