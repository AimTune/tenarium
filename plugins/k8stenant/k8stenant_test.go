package k8stenant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func fullConfig() map[string]any {
	return map[string]any{
		"labels":      map[string]any{"team": "{{.Slug}}-team", "env": "prod"},
		"annotations": map[string]any{"tenarium.io/tenant-name": "{{.Name}}"},
		"quota": map[string]any{
			"requests.cpu": "cpu_cores", "requests.memory": "memory_gib",
			"pods": "pods", "count/services": "services",
		},
		"quota_units": map[string]any{"memory_gib": "Gi", "cpu_cores": ""},
		"limit_range": map[string]any{
			"default":         map[string]any{"cpu": "500m", "memory": "512Mi"},
			"default_request": map[string]any{"cpu": "100m", "memory": "128Mi"},
		},
		"allow_from_namespace_labels": map[string]any{"kubernetes.io/metadata.name": "ingress-nginx"},
		"role_bindings": []any{
			map[string]any{"role": "admin", "group": "tenant:{{.Slug}}:admins"},
			map[string]any{"name": "tenarium-viewer", "role": "view", "user": "{{.Slug}}-auditor"},
		},
		"suspend_scale_to_zero": true,
	}
}

type env struct {
	p    *Plugin
	reg  *sdktest.Registrar
	kube *fake.Clientset
}

func setup(t *testing.T, cfg map[string]any, objs ...runtime.Object) *env {
	t.Helper()
	kube := fake.NewClientset(objs...)
	p := New(kube)
	p.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	reg := sdktest.NewRegistrar(cfg)
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"cpu_cores": 4, "memory_gib": 8, "pods": 20}})
	reg.HostImpl.AddPlan(sdk.Plan{ID: "max", Limits: map[string]int64{"cpu_cores": 16, "memory_gib": 64, "pods": 100, "services": 10}})
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "namespace" {
		t.Fatalf("provisioners = %v", reg.Provisioners)
	}
	return &env{p: p, reg: reg, kube: kube}
}

func (e *env) addTenant(slug string) sdk.Tenant {
	return e.reg.HostImpl.AddTenant(sdk.Tenant{
		Slug: slug, Name: "Acme Corp", Plan: "pro", Limits: map[string]int64{"pods": 50},
	})
}

func (e *env) ns(t *testing.T, name string) *corev1.Namespace {
	t.Helper()
	ns, err := e.kube.CoreV1().Namespaces().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return ns
}

func (e *env) quota(t *testing.T, ns string) corev1.ResourceList {
	t.Helper()
	q, err := e.kube.CoreV1().ResourceQuotas(ns).Get(context.Background(), QuotaName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return q.Spec.Hard
}

func wantQuota(t *testing.T, got corev1.ResourceList, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("quota = %v, want %v", got, want)
	}
	for k, v := range want {
		q, ok := got[corev1.ResourceName(k)]
		if !ok || q.Cmp(resource.MustParse(v)) != 0 {
			t.Fatalf("quota %s = %v, want %s (all: %v)", k, q.String(), v, got)
		}
	}
}

func TestProvision(t *testing.T) {
	ctx := context.Background()
	e := setup(t, fullConfig())
	tn := e.addTenant("acme")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}

	ns := e.ns(t, "tenant-acme")
	for k, v := range map[string]string{
		LabelManagedBy: "tenarium", LabelTenantID: tn.ID, LabelTenantSlug: "acme", LabelPlan: "pro",
		"team": "acme-team", "env": "prod",
	} {
		if ns.Labels[k] != v {
			t.Errorf("label %s = %q, want %q", k, ns.Labels[k], v)
		}
	}
	if ns.Annotations["tenarium.io/tenant-name"] != "Acme Corp" {
		t.Errorf("annotations = %v", ns.Annotations)
	}

	// Plan limits with the tenant's pods override; services is not limited.
	wantQuota(t, e.quota(t, "tenant-acme"), map[string]string{
		"requests.cpu": "4", "requests.memory": "8Gi", "pods": "50",
	})

	lr, err := e.kube.CoreV1().LimitRanges("tenant-acme").Get(ctx, LimitRangeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	item := lr.Spec.Limits[0]
	if item.Type != corev1.LimitTypeContainer || item.Default.Cpu().String() != "500m" ||
		item.Default.Memory().String() != "512Mi" || item.DefaultRequest.Cpu().String() != "100m" {
		t.Fatalf("limit range = %+v", item)
	}

	np, err := e.kube.NetworkingV1().NetworkPolicies("tenant-acme").Get(ctx, NetworkPolicyName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(np.Spec.PodSelector.MatchLabels) != 0 || len(np.Spec.PolicyTypes) != 1 ||
		np.Spec.PolicyTypes[0] != networkingv1.PolicyTypeIngress || len(np.Spec.Ingress) != 1 {
		t.Fatalf("network policy = %+v", np.Spec)
	}
	from := np.Spec.Ingress[0].From
	if len(from) != 2 || from[0].PodSelector == nil || from[0].NamespaceSelector != nil ||
		from[1].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "ingress-nginx" {
		t.Fatalf("ingress from = %+v", from)
	}

	rbs, err := e.kube.RbacV1().RoleBindings("tenant-acme").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]rbacv1.RoleBinding{}
	for _, rb := range rbs.Items {
		got[rb.Name] = rb
	}
	admin, viewer := got["tenarium-admin"], got["tenarium-viewer"]
	if len(got) != 2 || admin.RoleRef.Kind != "ClusterRole" || admin.RoleRef.Name != "admin" ||
		admin.Subjects[0].Kind != "Group" || admin.Subjects[0].Name != "tenant:acme:admins" ||
		viewer.RoleRef.Name != "view" || viewer.Subjects[0].Kind != "User" || viewer.Subjects[0].Name != "acme-auditor" {
		t.Fatalf("role bindings = %+v", got)
	}
	if admin.Labels[LabelTenantID] != tn.ID {
		t.Fatalf("role binding labels = %v", admin.Labels)
	}
}

func countObjects(t *testing.T, kube kubernetes.Interface, ns string) [5]int {
	t.Helper()
	ctx := context.Background()
	nss, _ := kube.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	qs, _ := kube.CoreV1().ResourceQuotas(ns).List(ctx, metav1.ListOptions{})
	lrs, _ := kube.CoreV1().LimitRanges(ns).List(ctx, metav1.ListOptions{})
	nps, _ := kube.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	rbs, _ := kube.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
	return [5]int{len(nss.Items), len(qs.Items), len(lrs.Items), len(nps.Items), len(rbs.Items)}
}

func TestProvisionIdempotentAndResync(t *testing.T) {
	ctx := context.Background()
	e := setup(t, fullConfig())
	tn := e.addTenant("acme")
	for range 2 {
		if err := e.p.Provision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	if got := countObjects(t, e.kube, "tenant-acme"); got != [5]int{1, 1, 1, 1, 2} {
		t.Fatalf("objects after two provisions = %v", got)
	}

	// Change the plan and drop the override: the event re-syncs quota and
	// the plan label.
	tn.Plan, tn.Limits = "max", nil
	e.reg.HostImpl.AddTenant(tn)
	if err := e.reg.Deliver(ctx, "lifecycle", sdktest.TenantEvent(sdk.EventTenantPlanChanged, tn)); err != nil {
		t.Fatal(err)
	}
	wantQuota(t, e.quota(t, "tenant-acme"), map[string]string{
		"requests.cpu": "16", "requests.memory": "64Gi", "pods": "100", "count/services": "10",
	})
	if l := e.ns(t, "tenant-acme").Labels[LabelPlan]; l != "max" {
		t.Fatalf("plan label = %q", l)
	}

	// A tenant override arriving with tenant.updated converges too.
	tn.Limits = map[string]int64{"services": 3}
	e.reg.HostImpl.AddTenant(tn)
	if err := e.reg.Deliver(ctx, "lifecycle", sdktest.TenantEvent(sdk.EventTenantUpdated, tn)); err != nil {
		t.Fatal(err)
	}
	if q := e.quota(t, "tenant-acme")["count/services"]; q.Value() != 3 {
		t.Fatalf("services quota = %v", q.String())
	}
	if got := countObjects(t, e.kube, "tenant-acme"); got != [5]int{1, 1, 1, 1, 2} {
		t.Fatalf("objects after resync = %v", got)
	}

	// Events for a tenant without a namespace are ignored.
	other := e.addTenant("other")
	if err := e.reg.Deliver(ctx, "lifecycle", sdktest.TenantEvent(sdk.EventTenantUpdated, other)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.kube.CoreV1().Namespaces().Get(ctx, "tenant-other", metav1.GetOptions{}); err == nil {
		t.Fatal("event created a namespace")
	}
}

func TestConvergeRemovesUnconfigured(t *testing.T) {
	ctx := context.Background()
	e := setup(t, fullConfig())
	kube := e.kube
	tn := e.addTenant("acme")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	// A foreign role binding in the namespace must survive.
	foreign := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "mine", Namespace: "tenant-acme"},
		RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "edit"}}
	if _, err := kube.RbacV1().RoleBindings("tenant-acme").Create(ctx, foreign, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	p2 := New(kube)
	reg := sdktest.NewRegistrar(map[string]any{
		"network_policy": "none",
		"role_bindings":  []any{map[string]any{"role": "edit", "name": "tenarium-admin", "group": "g-{{.Slug}}"}},
	})
	reg.HostImpl = e.reg.HostImpl
	if err := p2.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := p2.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	// quota, limit range and network policy removed; admin binding replaced
	// (roleRef changed), viewer removed, foreign kept.
	if got := countObjects(t, kube, "tenant-acme"); got != [5]int{1, 0, 0, 0, 2} {
		t.Fatalf("objects = %v", got)
	}
	rb, err := kube.RbacV1().RoleBindings("tenant-acme").Get(ctx, "tenarium-admin", metav1.GetOptions{})
	if err != nil || rb.RoleRef.Name != "edit" || rb.Subjects[0].Name != "g-acme" {
		t.Fatalf("admin binding = %+v, %v", rb, err)
	}
}

func TestConflicts(t *testing.T) {
	ctx := context.Background()
	foreign := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-taken",
		Labels: map[string]string{LabelManagedBy: "tenarium", LabelTenantID: "someone-else"}}}
	unlabeled := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-kube"}}
	e := setup(t, nil, foreign, unlabeled)

	for slug, want := range map[string]string{"taken": "belongs to tenant someone-else", "kube": "not managed by tenarium"} {
		tn := e.addTenant(slug)
		err := e.p.Provision(ctx, tn)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: error %v, want %q", slug, err, want)
		}
		// Nothing was created inside, and deprovision leaves it alone.
		if got := countObjects(t, e.kube, "tenant-"+slug); got[1]+got[2]+got[3]+got[4] != 0 {
			t.Fatalf("%s: objects created in a foreign namespace: %v", slug, got)
		}
		if err := e.p.Deprovision(ctx, tn); err != nil {
			t.Fatal(err)
		}
		ns := e.ns(t, "tenant-"+slug)
		if _, ok := ns.Annotations[AnnotationDeletedAt]; ok {
			t.Fatal("foreign namespace annotated")
		}
	}
}

func TestDeprovision(t *testing.T) {
	ctx := context.Background()
	e := setup(t, nil)
	tn := e.addTenant("acme")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := e.p.Deprovision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.kube.CoreV1().Namespaces().Get(ctx, "tenant-acme", metav1.GetOptions{}); err == nil {
		t.Fatal("namespace not deleted")
	}
	var foreground bool
	for _, a := range e.kube.Actions() {
		if a.GetVerb() == "delete" && a.GetResource().Resource == "namespaces" {
			da := a.(interface{ GetDeleteOptions() metav1.DeleteOptions })
			pp := da.GetDeleteOptions().PropagationPolicy
			foreground = pp != nil && *pp == metav1.DeletePropagationForeground
		}
	}
	if !foreground {
		t.Fatal("namespace not deleted with foreground propagation")
	}
}

func TestDeprovisionKeep(t *testing.T) {
	ctx := context.Background()
	e := setup(t, map[string]any{"on_deprovision": "keep"})
	tn := e.addTenant("acme")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	ns := e.ns(t, "tenant-acme")
	if ns.Annotations[AnnotationDeletedAt] != "2026-01-02T03:04:05Z" || ns.Labels[LabelManagedBy] != "tenarium" {
		t.Fatalf("namespace meta = %v %v", ns.Labels, ns.Annotations)
	}
	// Idempotent: the first timestamp stays.
	e.p.now = time.Now
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if e.ns(t, "tenant-acme").Annotations[AnnotationDeletedAt] != "2026-01-02T03:04:05Z" {
		t.Fatal("deleted-at overwritten")
	}
}

func replicas(n int32) *int32 { return &n }

func TestSuspendResume(t *testing.T) {
	ctx := context.Background()
	e := setup(t, fullConfig())
	tn := e.addTenant("acme")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	apps := e.kube.AppsV1()
	mk := func(name string, r *int32) {
		d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant-acme"},
			Spec: appsv1.DeploymentSpec{Replicas: r}}
		if _, err := apps.Deployments("tenant-acme").Create(ctx, d, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	mk("web", replicas(3))
	mk("default", nil)
	mk("idle", replicas(0))
	ss := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "tenant-acme"},
		Spec: appsv1.StatefulSetSpec{Replicas: replicas(2)}}
	if _, err := apps.StatefulSets("tenant-acme").Create(ctx, ss, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	type state struct {
		replicas int32
		record   string
	}
	check := func(when string, want map[string]state) {
		t.Helper()
		for name, w := range want {
			var meta metav1.ObjectMeta
			var r *int32
			if name == "db" {
				s, err := apps.StatefulSets("tenant-acme").Get(ctx, name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				meta, r = s.ObjectMeta, s.Spec.Replicas
			} else {
				d, err := apps.Deployments("tenant-acme").Get(ctx, name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				meta, r = d.ObjectMeta, d.Spec.Replicas
			}
			got := state{replicas: 1, record: meta.Annotations[AnnotationReplicasBeforeSuspend]}
			if r != nil {
				got.replicas = *r
			}
			if got != w {
				t.Errorf("%s: %s = %+v, want %+v", when, name, got, w)
			}
		}
	}

	// A resume without prior suspend changes nothing.
	if err := e.reg.Deliver(ctx, "lifecycle", sdktest.TenantEvent(sdk.EventTenantResumed, tn)); err != nil {
		t.Fatal(err)
	}
	check("resume first", map[string]state{"web": {3, ""}, "default": {1, ""}, "idle": {0, ""}, "db": {2, ""}})

	// A suspended event for a tenant that is active again (replay) is ignored.
	if err := e.reg.Deliver(ctx, "lifecycle", sdktest.TenantEvent(sdk.EventTenantSuspended, tn)); err != nil {
		t.Fatal(err)
	}
	check("stale suspend", map[string]state{"web": {3, ""}})

	suspended, err := e.reg.HostImpl.SuspendTenant(ctx, tn.ID, "unpaid")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := e.reg.Deliver(ctx, "lifecycle", sdktest.TenantEvent(sdk.EventTenantSuspended, suspended)); err != nil {
			t.Fatal(err)
		}
	}
	check("suspend", map[string]state{"web": {0, "3"}, "default": {0, "1"}, "idle": {0, ""}, "db": {0, "2"}})

	resumed, err := e.reg.HostImpl.ResumeTenant(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := e.reg.Deliver(ctx, "lifecycle", sdktest.TenantEvent(sdk.EventTenantResumed, resumed)); err != nil {
			t.Fatal(err)
		}
	}
	check("resume", map[string]state{"web": {3, ""}, "default": {1, ""}, "idle": {0, ""}, "db": {2, ""}})
}

func TestSuspendDisabled(t *testing.T) {
	ctx := context.Background()
	e := setup(t, nil)
	tn := e.addTenant("acme")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "tenant-acme"},
		Spec: appsv1.DeploymentSpec{Replicas: replicas(3)}}
	if _, err := e.kube.AppsV1().Deployments("tenant-acme").Create(ctx, d, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	s, _ := e.reg.HostImpl.SuspendTenant(ctx, tn.ID, "x")
	if err := e.reg.Deliver(ctx, "lifecycle", sdktest.TenantEvent(sdk.EventTenantSuspended, s)); err != nil {
		t.Fatal(err)
	}
	got, _ := e.kube.AppsV1().Deployments("tenant-acme").Get(ctx, "web", metav1.GetOptions{})
	if *got.Spec.Replicas != 3 {
		t.Fatal("scaled without suspend_scale_to_zero")
	}
}

func TestNamespaceName(t *testing.T) {
	p := &Plugin{cfg: Config{NameTemplate: "tenant-{{.Slug}}"}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("very-long-slug-", 6)
	a, err := p.namespaceName(sdk.Tenant{ID: "id-1", Slug: long})
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.namespaceName(sdk.Tenant{ID: "id-2", Slug: long})
	if err != nil {
		t.Fatal(err)
	}
	if len(a) > 63 || len(b) > 63 || a == b || !strings.HasPrefix(a, "tenant-very-long-slug-") {
		t.Fatalf("hashed names %q, %q", a, b)
	}
	for in, want := range map[string]string{
		"Acme_Corp.": "tenant-acme-corp", "acme": "tenant-acme", "ÜBER": "tenant--ber",
	} {
		got, err := p.namespaceName(sdk.Tenant{ID: "x", Slug: in})
		if err != nil || got != want {
			t.Errorf("namespaceName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if s := SanitizeName("--Hello World--"); s != "hello-world" {
		t.Errorf("SanitizeName = %q", s)
	}
}

func TestRoute(t *testing.T) {
	ctx := context.Background()
	e := setup(t, fullConfig())
	tn := e.addTenant("acme")
	other := e.addTenant("other")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	get := func(p *sdk.Principal, tenant string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/tenants/"+tenant, nil)
		if p != nil {
			req = req.WithContext(sdk.WithPrincipal(req.Context(), p))
		}
		rec := httptest.NewRecorder()
		e.reg.Mux.ServeHTTP(rec, req)
		return rec
	}
	admin := &sdk.Principal{Subject: "admin", Kind: "user"}
	rec := get(admin, "acme")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var info TenantInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Namespace != "tenant-acme" || info.Phase != "Active" || info.Quota["requests.memory"] != "8Gi" || info.Quota["pods"] != "50" {
		t.Fatalf("info = %+v", info)
	}

	rec = get(admin, other.ID)
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil || info.Phase != "Missing" || info.Namespace != "tenant-other" {
		t.Fatalf("missing namespace: %d %s", rec.Code, rec.Body)
	}

	scoped := &sdk.Principal{Subject: "u", Kind: "user", TenantID: other.ID}
	for _, c := range []struct {
		p      *sdk.Principal
		tenant string
	}{{scoped, "acme"}, {nil, "acme"}, {admin, "nope"}} {
		if rec := get(c.p, c.tenant); rec.Code != http.StatusNotFound {
			t.Errorf("%v %s: status %d, want 404", c.p, c.tenant, rec.Code)
		}
	}
	if rec := get(scoped, "other"); rec.Code != http.StatusOK {
		t.Errorf("own tenant: status %d", rec.Code)
	}
}

func TestHealth(t *testing.T) {
	e := setup(t, nil)
	if err := e.p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{Config{}, ""},
		{Config{OnDeprovision: "archive"}, "on_deprovision"},
		{Config{NetworkPolicy: "deny"}, "network_policy"},
		{Config{NameTemplate: "t-{{.Slug"}, "name_template"},
		{Config{NameTemplate: "t-{{.Nope}}"}, "name_template"},
		{Config{NameTemplate: "shared"}, "must depend on the tenant"},
		{Config{NameTemplate: "{{if false}}x{{end}}"}, "empty name"},
		{Config{Labels: map[string]string{"bad key!": "x"}}, "invalid key"},
		{Config{Labels: map[string]string{LabelTenantID: "x"}}, "set by the plugin"},
		{Config{Labels: map[string]string{"name": "{{.Name}}"}}, "invalid value"},
		{Config{QuotaUnits: map[string]string{"memory_gib": "Gx"}}, "quota_units"},
		{Config{LimitRange: &LimitRangeConfig{Default: map[string]string{"cpu": "lots"}}}, "limit_range.default"},
		{Config{RoleBindings: []RoleBindingConfig{{Role: "admin"}}}, "exactly one of group or user"},
		{Config{RoleBindings: []RoleBindingConfig{{Role: "admin", Group: "a", User: "b"}}}, "exactly one"},
		{Config{RoleBindings: []RoleBindingConfig{{Group: "a"}}}, "role is required"},
		{Config{RoleBindings: []RoleBindingConfig{{Role: "admin", Group: "a"}, {Role: "admin", User: "b"}}}, "duplicate name"},
		{Config{RoleBindings: []RoleBindingConfig{{Role: "admin", Group: "{{.Nope}}"}}}, "subject"},
		{Config{AllowFromNamespaceLabels: map[string]string{"k": "bad value!"}}, "allow_from_namespace_labels"},
	} {
		p := &Plugin{cfg: tc.cfg}
		err := p.validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%+v: unexpected error %v", tc.cfg, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%+v: error %v, want containing %q", tc.cfg, err, tc.wantErr)
		}
	}

	p := &Plugin{}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.cfg.OnDeprovision != DeprovisionDelete || p.cfg.NetworkPolicy != NetworkPolicyIsolate || p.cfg.NameTemplate != DefaultNameTemplate {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}

	// Unknown fields are rejected by the registrar's strict decoding.
	if err := New(fake.NewClientset()).Init(context.Background(), sdktest.NewRegistrar(map[string]any{"nope": 1})); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestConfigSchema(t *testing.T) {
	s, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(fullConfig()); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[string]any{
		"unknown field":   {"nope": true},
		"bad deprovision": {"on_deprovision": "archive"},
		"bad policy":      {"network_policy": "deny"},
		"binding no role": {"role_bindings": []any{map[string]any{"group": "g"}}},
		"binding both":    {"role_bindings": []any{map[string]any{"role": "r", "group": "g", "user": "u"}}},
		"limit range key": {"limit_range": map[string]any{"max": map[string]any{}}},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%s: expected schema error", name)
		}
	}
}

// TestRealCluster runs against the cluster in $TENARIUM_TEST_KUBECONFIG.
func TestRealCluster(t *testing.T) {
	path := os.Getenv("TENARIUM_TEST_KUBECONFIG")
	if path == "" {
		t.Skip("TENARIUM_TEST_KUBECONFIG not set")
	}
	ctx := context.Background()
	p := &Plugin{}
	cfg := fullConfig()
	cfg["kubeconfig"] = path
	cfg["name_template"] = "tenarium-test-{{.Slug}}"
	reg := sdktest.NewRegistrar(cfg)
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"cpu_cores": 2, "memory_gib": 4, "pods": 10}})
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "it" + time.Now().Format("150405"), Plan: "pro"})
	t.Cleanup(func() { _ = p.Deprovision(context.Background(), tn) })
	for range 2 {
		if err := p.Provision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
}
