package controller

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/server"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

const testAPIKey = "operator-test-key"

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(tenariumv1.AddToScheme(s))
	return s
}

// startTenarium runs a real in-process Tenarium server with the memory
// store and returns its URL.
func startTenarium(t *testing.T) string {
	t.Helper()
	cfg := server.DefaultConfig()
	cfg.Server.APIKeys = []string{testAPIKey}
	cfg.Auth.RateLimit = 0
	cfg.UI.Enabled = false
	cfg.Events.PollInterval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	app, err := server.New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return "http://" + ln.Addr().String()
}

// env bundles a fake Kubernetes client, the reconcilers and a Tenarium
// client for checking the remote side.
type env struct {
	t         *testing.T
	ctx       context.Context
	k8s       ctrlclient.Client
	api       *client.Client
	rec       *events.FakeRecorder
	tenants   *TenantReconciler
	plans     *PlanReconciler
	rollouts  *RolloutReconciler
	templates *TenantTemplateReconciler
	conns     *ConnectionReconciler
}

func newEnv(t *testing.T, objs ...ctrlclient.Object) *env {
	t.Helper()
	url := startTenarium(t)
	k8s := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(objs...).
		WithStatusSubresource(&tenariumv1.Tenant{}, &tenariumv1.Plan{}, &tenariumv1.Rollout{}, &tenariumv1.TenantTemplate{}, &tenariumv1.TenariumConnection{}).
		WithIndex(&tenariumv1.Tenant{}, indexParent, tenantParentName).
		Build()
	api, err := client.New(url, client.WithAPIKey(testAPIKey))
	if err != nil {
		t.Fatal(err)
	}
	rec := events.NewFakeRecorder(1000)
	conns := &Connections{Reader: k8s, Default: DefaultConnection{URL: url, APIKey: testAPIKey}}
	return &env{
		t: t, ctx: context.Background(), k8s: k8s, api: api, rec: rec,
		tenants:   &TenantReconciler{Client: k8s, Connections: conns, Recorder: rec, ResyncPeriod: time.Minute},
		plans:     &PlanReconciler{Client: k8s, Connections: conns, Recorder: rec, ResyncPeriod: time.Minute},
		rollouts:  &RolloutReconciler{Client: k8s, Connections: conns, Recorder: rec, ResyncPeriod: time.Minute},
		templates: &TenantTemplateReconciler{Client: k8s, Connections: conns, Recorder: rec, ResyncPeriod: time.Minute},
		conns:     &ConnectionReconciler{Client: k8s, Connections: conns, Recorder: rec, ResyncPeriod: time.Minute},
	}
}

func (e *env) rollout(name string) *tenariumv1.Rollout {
	e.t.Helper()
	var r tenariumv1.Rollout
	if err := e.k8s.Get(e.ctx, req(name).NamespacedName, &r); err != nil {
		e.t.Fatal(err)
	}
	return &r
}

func (e *env) template(name string) *tenariumv1.TenantTemplate {
	e.t.Helper()
	var tpl tenariumv1.TenantTemplate
	if err := e.k8s.Get(e.ctx, req(name).NamespacedName, &tpl); err != nil {
		e.t.Fatal(err)
	}
	return &tpl
}

// createPlan creates and reconciles a Plan resource.
func (e *env) createPlan(id string, limits map[string]int64) {
	e.t.Helper()
	e.create(&tenariumv1.Plan{ObjectMeta: metav1.ObjectMeta{Name: id}, Spec: tenariumv1.PlanSpec{Limits: limits}})
	if _, err := e.plans.Reconcile(e.ctx, req(id)); err != nil {
		e.t.Fatal(err)
	}
}

var uidSeq int

func newUID() types.UID {
	uidSeq++
	return types.UID(fmt.Sprintf("00000000-0000-0000-0000-%012d", uidSeq))
}

func (e *env) create(obj ctrlclient.Object) {
	e.t.Helper()
	if obj.GetNamespace() == "" {
		obj.SetNamespace("default")
	}
	if obj.GetUID() == "" {
		obj.SetUID(newUID())
	}
	if err := e.k8s.Create(e.ctx, obj); err != nil {
		e.t.Fatal(err)
	}
}

func req(name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: name}}
}

func (e *env) reconcileTenant(name string) (ctrl.Result, error) {
	e.t.Helper()
	return e.tenants.Reconcile(e.ctx, req(name))
}

// syncTenant reconciles until the tenant is Ready or fails the test.
func (e *env) syncTenant(name string) *tenariumv1.Tenant {
	e.t.Helper()
	for range 5 {
		if _, err := e.reconcileTenant(name); err != nil {
			e.t.Fatalf("reconcile %s: %v", name, err)
		}
		t := e.tenant(name)
		if meta.IsStatusConditionTrue(t.Status.Conditions, tenariumv1.ConditionReady) {
			return t
		}
	}
	t := e.tenant(name)
	e.t.Fatalf("tenant %s not ready: %+v", name, t.Status.Conditions)
	return nil
}

func (e *env) tenant(name string) *tenariumv1.Tenant {
	e.t.Helper()
	var t tenariumv1.Tenant
	if err := e.k8s.Get(e.ctx, req(name).NamespacedName, &t); err != nil {
		e.t.Fatal(err)
	}
	return &t
}

func (e *env) plan(name string) *tenariumv1.Plan {
	e.t.Helper()
	var p tenariumv1.Plan
	if err := e.k8s.Get(e.ctx, req(name).NamespacedName, &p); err != nil {
		e.t.Fatal(err)
	}
	return &p
}

func (e *env) gone(obj ctrlclient.Object) bool {
	err := e.k8s.Get(e.ctx, ctrlclient.ObjectKeyFromObject(obj), obj)
	return err != nil
}

// drainEvents returns the events recorded so far.
func (e *env) drainEvents() []string {
	var out []string
	for {
		select {
		case ev := <-e.rec.Events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func hasEvent(evs []string, substr string) bool {
	for _, ev := range evs {
		if strings.Contains(ev, substr) {
			return true
		}
	}
	return false
}

func condition(conds []metav1.Condition, typ string) metav1.Condition {
	if c := meta.FindStatusCondition(conds, typ); c != nil {
		return *c
	}
	return metav1.Condition{}
}

func secret(name string, data map[string]string) *corev1.Secret {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}, Data: map[string][]byte{}}
	for k, v := range data {
		s.Data[k] = []byte(v)
	}
	return s
}

func raw(js string) *runtime.RawExtension { return &runtime.RawExtension{Raw: []byte(js)} }
