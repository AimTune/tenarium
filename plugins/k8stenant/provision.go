package k8stenant

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Name implements sdk.Provisioner.
func (p *Plugin) Name() string { return "namespace" }

// Provision creates the tenant namespace if missing and converges the
// objects inside it. Every step is idempotent.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	ns, err := p.ensureNamespace(ctx, t)
	if err != nil {
		return err
	}
	return p.converge(ctx, t, ns)
}

// owner returns the tenant owning ns ("" when unlabeled).
func owner(ns *corev1.Namespace) string { return ns.Labels[LabelTenantID] }

// ensureNamespace creates or updates the tenant namespace, refusing to adopt
// one that is not labeled with the tenant's ID.
func (p *Plugin) ensureNamespace(ctx context.Context, t sdk.Tenant) (string, error) {
	name, err := p.namespaceName(t)
	if err != nil {
		return "", err
	}
	meta, err := p.namespaceMeta(t)
	if err != nil {
		return "", err
	}
	meta.Name = name
	c := p.client.CoreV1().Namespaces()
	ns, err := c.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		ns, err = c.Create(ctx, &corev1.Namespace{ObjectMeta: meta}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			// Created concurrently: check who owns it below.
			ns, err = c.Get(ctx, name, metav1.GetOptions{})
		}
	}
	if err != nil {
		return "", fmt.Errorf("namespace %s: %w", name, err)
	}
	switch o := owner(ns); {
	case o == "":
		return "", fmt.Errorf("namespace %s already exists and is not managed by tenarium", name)
	case o != t.ID:
		return "", fmt.Errorf("namespace %s belongs to tenant %s", name, o)
	}
	if ns.DeletionTimestamp != nil {
		return "", fmt.Errorf("namespace %s is being deleted; retry once it is gone", name)
	}
	if mergeMeta(&ns.ObjectMeta, meta) {
		if _, err := c.Update(ctx, ns, metav1.UpdateOptions{}); err != nil {
			return "", fmt.Errorf("update namespace %s: %w", name, err)
		}
	}
	return name, nil
}

// mergeMeta copies want's labels and annotations into cur and reports
// whether anything changed. Labels and annotations set by others are kept.
func mergeMeta(cur *metav1.ObjectMeta, want metav1.ObjectMeta) bool {
	changed := false
	merge := func(dst *map[string]string, src map[string]string) {
		for k, v := range src {
			if old, ok := (*dst)[k]; ok && old == v {
				continue
			}
			if *dst == nil {
				*dst = map[string]string{}
			}
			(*dst)[k] = v
			changed = true
		}
	}
	merge(&cur.Labels, want.Labels)
	merge(&cur.Annotations, want.Annotations)
	return changed
}

// converge creates, updates or removes the managed objects in namespace ns.
func (p *Plugin) converge(ctx context.Context, t sdk.Tenant, ns string) error {
	if err := p.syncQuota(ctx, t, ns); err != nil {
		return err
	}
	if err := p.syncLimitRange(ctx, t, ns); err != nil {
		return err
	}
	if err := p.syncNetworkPolicy(ctx, t, ns); err != nil {
		return err
	}
	return p.syncRoleBindings(ctx, t, ns)
}

// objectMeta is the metadata of a managed object in a tenant namespace.
func objectMeta(t sdk.Tenant, ns, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: ns, Labels: tenantLabels(t)}
}

// client is the subset of a typed client used to converge one object.
type client[T metav1.Object] interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (T, error)
	Create(ctx context.Context, obj T, opts metav1.CreateOptions) (T, error)
	Update(ctx context.Context, obj T, opts metav1.UpdateOptions) (T, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

// upsert creates want or, if it exists, lets sync copy want's spec into the
// current object and updates it when sync reports a change.
func upsert[T metav1.Object](ctx context.Context, c client[T], kind string, want T, sync func(cur, want T) bool) error {
	name := want.GetName()
	cur, err := c.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = c.Create(ctx, want, metav1.CreateOptions{})
		if !apierrors.IsAlreadyExists(err) {
			if err != nil {
				return fmt.Errorf("create %s %s/%s: %w", kind, want.GetNamespace(), name, err)
			}
			return nil
		}
		cur, err = c.Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		return fmt.Errorf("get %s %s/%s: %w", kind, want.GetNamespace(), name, err)
	}
	labelsChanged := mergeLabels(cur, want.GetLabels())
	if !sync(cur, want) && !labelsChanged {
		return nil
	}
	if _, err := c.Update(ctx, cur, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update %s %s/%s: %w", kind, want.GetNamespace(), name, err)
	}
	return nil
}

// mergeLabels adds want to o's labels and reports whether any changed.
func mergeLabels(o metav1.Object, want map[string]string) bool {
	m := metav1.ObjectMeta{Labels: o.GetLabels()}
	if !mergeMeta(&m, metav1.ObjectMeta{Labels: want}) {
		return false
	}
	o.SetLabels(m.Labels)
	return true
}

// removeManaged deletes the named object if it exists and was created by
// the plugin; objects created by others are left alone.
func removeManaged[T metav1.Object](ctx context.Context, c client[T], kind, ns, name string) error {
	cur, err := c.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get %s %s/%s: %w", kind, ns, name, err)
	}
	if cur.GetLabels()[LabelManagedBy] != managedByValue {
		return nil
	}
	if err := c.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete %s %s/%s: %w", kind, ns, name, err)
	}
	return nil
}

// QuotaHard computes the ResourceQuota limits from entitlements. Limits the
// tenant does not have, and negative ones, are left out (unlimited).
func (p *Plugin) QuotaHard(e sdk.Entitlements) (corev1.ResourceList, error) {
	hard := corev1.ResourceList{}
	for res, limit := range p.cfg.Quota {
		v, ok := e.Limit(limit)
		if !ok || v < 0 {
			continue
		}
		s := fmt.Sprintf("%d%s", v, p.cfg.QuotaUnits[limit])
		q, err := resource.ParseQuantity(s)
		if err != nil {
			return nil, fmt.Errorf("quota %s: invalid quantity %q", res, s)
		}
		hard[corev1.ResourceName(res)] = q
	}
	return hard, nil
}

func (p *Plugin) syncQuota(ctx context.Context, t sdk.Tenant, ns string) error {
	c := p.client.CoreV1().ResourceQuotas(ns)
	if len(p.cfg.Quota) == 0 {
		return removeManaged(ctx, c, "resourcequota", ns, QuotaName)
	}
	e, err := p.host.Entitlements(ctx, t.ID)
	if err != nil {
		return fmt.Errorf("entitlements of tenant %s: %w", t.ID, err)
	}
	hard, err := p.QuotaHard(e)
	if err != nil {
		return err
	}
	if len(hard) == 0 {
		// Nothing is limited: an empty quota would only add noise.
		return removeManaged(ctx, c, "resourcequota", ns, QuotaName)
	}
	want := &corev1.ResourceQuota{ObjectMeta: objectMeta(t, ns, QuotaName), Spec: corev1.ResourceQuotaSpec{Hard: hard}}
	return upsert(ctx, c, "resourcequota", want, func(cur, want *corev1.ResourceQuota) bool {
		if equality.Semantic.DeepEqual(cur.Spec.Hard, want.Spec.Hard) {
			return false
		}
		cur.Spec.Hard = want.Spec.Hard
		return true
	})
}

func (p *Plugin) syncLimitRange(ctx context.Context, t sdk.Tenant, ns string) error {
	c := p.client.CoreV1().LimitRanges(ns)
	lr := p.cfg.LimitRange
	if lr == nil || len(lr.Default)+len(lr.DefaultRequest) == 0 {
		return removeManaged(ctx, c, "limitrange", ns, LimitRangeName)
	}
	item := corev1.LimitRangeItem{Type: corev1.LimitTypeContainer}
	var err error
	if item.Default, err = resourceList(lr.Default); err != nil {
		return err
	}
	if item.DefaultRequest, err = resourceList(lr.DefaultRequest); err != nil {
		return err
	}
	want := &corev1.LimitRange{
		ObjectMeta: objectMeta(t, ns, LimitRangeName),
		Spec:       corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{item}},
	}
	return upsert(ctx, c, "limitrange", want, func(cur, want *corev1.LimitRange) bool {
		if equality.Semantic.DeepEqual(cur.Spec, want.Spec) {
			return false
		}
		cur.Spec = want.Spec
		return true
	})
}

func resourceList(m map[string]string) (corev1.ResourceList, error) {
	qs, err := quantities(m)
	if err != nil || len(qs) == 0 {
		return nil, err
	}
	out := make(corev1.ResourceList, len(qs))
	for k, q := range qs {
		out[corev1.ResourceName(k)] = q
	}
	return out, nil
}

// networkPolicy admits ingress only from pods in the same namespace and
// from namespaces matching allow_from_namespace_labels.
func (p *Plugin) networkPolicy(t sdk.Tenant, ns string) *networkingv1.NetworkPolicy {
	from := []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}}
	if len(p.cfg.AllowFromNamespaceLabels) > 0 {
		from = append(from, networkingv1.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: p.cfg.AllowFromNamespaceLabels},
		})
	}
	return &networkingv1.NetworkPolicy{
		ObjectMeta: objectMeta(t, ns, NetworkPolicyName),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{{From: from}},
		},
	}
}

func (p *Plugin) syncNetworkPolicy(ctx context.Context, t sdk.Tenant, ns string) error {
	c := p.client.NetworkingV1().NetworkPolicies(ns)
	if p.cfg.NetworkPolicy == NetworkPolicyNone {
		return removeManaged(ctx, c, "networkpolicy", ns, NetworkPolicyName)
	}
	return upsert(ctx, c, "networkpolicy", p.networkPolicy(t, ns), func(cur, want *networkingv1.NetworkPolicy) bool {
		if equality.Semantic.DeepEqual(cur.Spec, want.Spec) {
			return false
		}
		cur.Spec = want.Spec
		return true
	})
}

// roleBindings renders the configured RoleBindings for namespace ns.
func (p *Plugin) roleBindings(t sdk.Tenant, ns string) ([]*rbacv1.RoleBinding, error) {
	out := make([]*rbacv1.RoleBinding, 0, len(p.bindings))
	for _, b := range p.bindings {
		subject, err := render(b.subject, t)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(subject) == "" {
			return nil, fmt.Errorf("role binding %s: subject renders empty for tenant %s", b.name, t.ID)
		}
		out = append(out, &rbacv1.RoleBinding{
			ObjectMeta: objectMeta(t, ns, b.name),
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: b.role},
			Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: b.kind, Name: subject}},
		})
	}
	return out, nil
}

func (p *Plugin) syncRoleBindings(ctx context.Context, t sdk.Tenant, ns string) error {
	want, err := p.roleBindings(t, ns)
	if err != nil {
		return err
	}
	c := p.client.RbacV1().RoleBindings(ns)
	keep := map[string]bool{}
	for _, rb := range want {
		keep[rb.Name] = true
		cur, err := c.Get(ctx, rb.Name, metav1.GetOptions{})
		if err == nil && cur.RoleRef != rb.RoleRef {
			// roleRef is immutable: replace the binding.
			if err := c.Delete(ctx, rb.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete rolebinding %s/%s: %w", ns, rb.Name, err)
			}
		} else if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("get rolebinding %s/%s: %w", ns, rb.Name, err)
		}
		err = upsert(ctx, c, "rolebinding", rb, func(cur, want *rbacv1.RoleBinding) bool {
			if equality.Semantic.DeepEqual(cur.Subjects, want.Subjects) {
				return false
			}
			cur.Subjects = want.Subjects
			return true
		})
		if err != nil {
			return err
		}
	}
	// Remove bindings this plugin created that are no longer configured.
	sel := labels.SelectorFromSet(labels.Set{LabelManagedBy: managedByValue, LabelTenantID: t.ID})
	list, err := c.List(ctx, metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return fmt.Errorf("list rolebindings in %s: %w", ns, err)
	}
	for _, rb := range list.Items {
		if keep[rb.Name] {
			continue
		}
		if err := c.Delete(ctx, rb.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete rolebinding %s/%s: %w", ns, rb.Name, err)
		}
	}
	return nil
}

// Deprovision applies on_deprovision to the tenant namespace. A missing
// namespace is already deprovisioned; one owned by another tenant (or not
// managed by tenarium) is skipped with a warning.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	name, err := p.namespaceName(t)
	if err != nil {
		return err
	}
	c := p.client.CoreV1().Namespaces()
	ns, err := c.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("namespace %s: %w", name, err)
	}
	if o := owner(ns); o != t.ID {
		p.log.Warn("not deprovisioning a namespace owned by another tenant",
			"namespace", name, "tenant_id", t.ID, "owner", o)
		return nil
	}
	if ns.DeletionTimestamp != nil {
		return nil
	}
	if p.cfg.OnDeprovision == DeprovisionKeep {
		if _, ok := ns.Annotations[AnnotationDeletedAt]; ok {
			return nil
		}
		if ns.Annotations == nil {
			ns.Annotations = map[string]string{}
		}
		ns.Annotations[AnnotationDeletedAt] = p.now().UTC().Format(time.RFC3339)
		if _, err := c.Update(ctx, ns, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("annotate namespace %s: %w", name, err)
		}
		return nil
	}
	fg := metav1.DeletePropagationForeground
	err = c.Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: &fg})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete namespace %s: %w", name, err)
	}
	return nil
}
