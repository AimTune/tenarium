// Package k8stenant gives every tenant its own Kubernetes namespace with
// guardrails: a ResourceQuota derived from the tenant's entitlements, default
// container requests and limits, a network policy isolating the namespace
// and RoleBindings for the tenant's groups or users.
//
// The namespace name comes from name_template (a text/template over
// sdk.Tenant, default "tenant-{{.Slug}}"), sanitized to a DNS-1123 label.
// Names longer than 63 characters are shortened and suffixed with a hash of
// the tenant ID. Templates should only use immutable tenant fields (ID,
// Slug), since the name is recomputed on deprovision and on events.
//
// Every namespace the plugin creates is labeled with the tenant ID
// (tenarium.io/tenant-id). A namespace without that label, or labeled with
// another tenant, is never adopted on Provision nor touched on Deprovision,
// so a name clash cannot hand one tenant's workloads to another or delete
// them.
//
// quota maps ResourceQuota resource names to Tenarium limit names, e.g.
// {"requests.memory": "memory_gib"}; quota_units appends a unit suffix to a
// limit's value (memory_gib → "Gi"). Limits the tenant does not have are
// left out of the quota (unlimited). The quota and labels are re-synced on
// tenant.updated and tenant.plan_changed.
//
// With suspend_scale_to_zero, tenant.suspended scales every Deployment and
// StatefulSet in the namespace to zero, remembering the previous replica
// count in the tenarium.io/replicas-before-suspend annotation, and
// tenant.resumed restores it.
package k8stenant

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// PluginID is the ID the plugin registers under.
const PluginID = "kubernetes-tenant"

func init() {
	sdk.Register(PluginID, func() sdk.Plugin { return &Plugin{} })
}

// Deprovision actions and network policy modes.
const (
	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"

	NetworkPolicyIsolate = "isolate"
	NetworkPolicyNone    = "none"
)

// DefaultNameTemplate names tenant namespaces when name_template is unset.
const DefaultNameTemplate = "tenant-{{.Slug}}"

// Labels and annotations set by the plugin.
const (
	LabelManagedBy  = "app.kubernetes.io/managed-by"
	LabelTenantID   = "tenarium.io/tenant-id"
	LabelTenantSlug = "tenarium.io/tenant-slug"
	LabelPlan       = "tenarium.io/plan"

	AnnotationDeletedAt             = "tenarium.io/deleted-at"
	AnnotationReplicasBeforeSuspend = "tenarium.io/replicas-before-suspend"

	managedByValue = "tenarium"
)

// Names of the objects created in each tenant namespace.
const (
	QuotaName         = "tenarium-quota"
	LimitRangeName    = "tenarium-defaults"
	NetworkPolicyName = "tenarium-isolate"
)

// maxNameLen is the maximum length of a DNS-1123 label.
const maxNameLen = validation.DNS1123LabelMaxLength

type Config struct {
	// Kubeconfig is a kubeconfig path. Empty uses the in-cluster config,
	// falling back to the default loading rules ($KUBECONFIG, ~/.kube/config).
	Kubeconfig string `json:"kubeconfig"`
	// Context selects a kubeconfig context.
	Context string  `json:"context"`
	QPS     float32 `json:"qps"`
	Burst   int     `json:"burst"`

	// NameTemplate renders the namespace name from an sdk.Tenant.
	NameTemplate string `json:"name_template"`
	// Labels and Annotations are added to the namespace; values are
	// templates over sdk.Tenant.
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`

	// Quota maps ResourceQuota resource names to Tenarium limit names.
	Quota map[string]string `json:"quota"`
	// QuotaUnits maps Tenarium limit names to a quantity suffix ("Gi").
	QuotaUnits map[string]string `json:"quota_units"`

	LimitRange *LimitRangeConfig `json:"limit_range"`

	// NetworkPolicy is "isolate" (default) or "none".
	NetworkPolicy string `json:"network_policy"`
	// AllowFromNamespaceLabels additionally admits ingress from namespaces
	// matching these labels (e.g. the ingress controller's).
	AllowFromNamespaceLabels map[string]string `json:"allow_from_namespace_labels"`

	RoleBindings []RoleBindingConfig `json:"role_bindings"`

	// OnDeprovision is "delete" (default) or "keep".
	OnDeprovision string `json:"on_deprovision"`
	// SuspendScaleToZero scales workloads to zero while suspended.
	SuspendScaleToZero bool `json:"suspend_scale_to_zero"`
}

// LimitRangeConfig sets default container requests and limits.
type LimitRangeConfig struct {
	Default        map[string]string `json:"default"`
	DefaultRequest map[string]string `json:"default_request"`
}

// RoleBindingConfig binds a ClusterRole to a group or user in the tenant
// namespace. Group and User are templates over sdk.Tenant.
type RoleBindingConfig struct {
	// Name of the RoleBinding; default "tenarium-<role>".
	Name  string `json:"name"`
	Role  string `json:"role"`
	Group string `json:"group"`
	User  string `json:"user"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "kubeconfig": {"type": "string"},
    "context": {"type": "string"},
    "qps": {"type": "number", "minimum": 0},
    "burst": {"type": "integer", "minimum": 0},
    "name_template": {"type": "string", "minLength": 1},
    "labels": {"type": "object", "additionalProperties": {"type": "string"}},
    "annotations": {"type": "object", "additionalProperties": {"type": "string"}},
    "quota": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}},
    "quota_units": {"type": "object", "additionalProperties": {"type": "string"}},
    "limit_range": {
      "type": "object",
      "properties": {
        "default": {"type": "object", "additionalProperties": {"type": "string"}},
        "default_request": {"type": "object", "additionalProperties": {"type": "string"}}
      },
      "additionalProperties": false
    },
    "network_policy": {"enum": ["isolate", "none"]},
    "allow_from_namespace_labels": {"type": "object", "additionalProperties": {"type": "string"}},
    "role_bindings": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "role": {"type": "string", "minLength": 1},
          "group": {"type": "string"},
          "user": {"type": "string"}
        },
        "required": ["role"],
        "oneOf": [{"required": ["group"]}, {"required": ["user"]}],
        "additionalProperties": false
      }
    },
    "on_deprovision": {"enum": ["delete", "keep"]},
    "suspend_scale_to_zero": {"type": "boolean"}
  },
  "additionalProperties": false
}`)

// Plugin is the kubernetes-tenant plugin.
type Plugin struct {
	cfg    Config
	client kubernetes.Interface
	host   sdk.Host
	log    *slog.Logger
	now    func() time.Time

	name        *template.Template
	labels      map[string]*template.Template
	annotations map[string]*template.Template
	bindings    []binding
}

// binding is a compiled RoleBindingConfig.
type binding struct {
	name    string
	role    string
	kind    string // rbacv1.GroupKind or rbacv1.UserKind
	subject *template.Template
}

// New returns a plugin that talks to client instead of building one from
// the connection settings. It is meant for tests and embedding.
func New(client kubernetes.Interface) *Plugin {
	return &Plugin{client: client}
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           PluginID,
		Name:         "Kubernetes Tenant Namespaces",
		Version:      "0.1.0",
		Description:  "Provisions a Kubernetes namespace per tenant with quota, limit range, network policy and role bindings.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	if p.client == nil {
		c, err := newClient(p.cfg)
		if err != nil {
			return err
		}
		p.client = c
	}
	p.host = r.Host()
	p.log = r.Logger()
	if p.now == nil {
		p.now = time.Now
	}
	r.Provisioner(p)
	r.Subscribe("lifecycle", sdk.EventFilter{Types: []string{
		sdk.EventTenantSuspended, sdk.EventTenantResumed,
		sdk.EventTenantPlanChanged, sdk.EventTenantUpdated,
	}}, p.lifecycle)
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
	return nil
}

// newClient builds a clientset from the connection settings.
func newClient(c Config) (kubernetes.Interface, error) {
	var rc *rest.Config
	if c.Kubeconfig == "" && c.Context == "" {
		rc, _ = rest.InClusterConfig()
	}
	if rc == nil {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		rules.ExplicitPath = c.Kubeconfig
		var err error
		rc, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
			&clientcmd.ConfigOverrides{CurrentContext: c.Context}).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("kubeconfig: %w", err)
		}
	}
	if c.QPS > 0 {
		rc.QPS = c.QPS
	}
	if c.Burst > 0 {
		rc.Burst = c.Burst
	}
	rc.UserAgent = "tenarium/" + PluginID
	return kubernetes.NewForConfig(rc)
}

// reservedLabels are set by the plugin and cannot be configured.
var reservedLabels = []string{LabelManagedBy, LabelTenantID, LabelTenantSlug, LabelPlan}

// validate checks and defaults the configuration and compiles templates.
func (p *Plugin) validate() error {
	c := &p.cfg
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDelete
	case DeprovisionDelete, DeprovisionKeep:
	default:
		return fmt.Errorf("on_deprovision must be delete or keep, got %q", c.OnDeprovision)
	}
	switch c.NetworkPolicy {
	case "":
		c.NetworkPolicy = NetworkPolicyIsolate
	case NetworkPolicyIsolate, NetworkPolicyNone:
	default:
		return fmt.Errorf("network_policy must be isolate or none, got %q", c.NetworkPolicy)
	}
	if c.QPS < 0 || c.Burst < 0 {
		return errors.New("qps and burst must not be negative")
	}
	if c.NameTemplate == "" {
		c.NameTemplate = DefaultNameTemplate
	}
	var err error
	if p.name, err = parseTemplate("name_template", c.NameTemplate); err != nil {
		return err
	}

	p.labels = map[string]*template.Template{}
	for k, v := range c.Labels {
		if errs := validation.IsQualifiedName(k); len(errs) > 0 {
			return fmt.Errorf("labels: invalid key %q: %s", k, strings.Join(errs, "; "))
		}
		if slices.Contains(reservedLabels, k) {
			return fmt.Errorf("labels: %q is set by the plugin", k)
		}
		if p.labels[k], err = parseTemplate("labels."+k, v); err != nil {
			return err
		}
	}
	p.annotations = map[string]*template.Template{}
	for k, v := range c.Annotations {
		if errs := validation.IsQualifiedName(k); len(errs) > 0 {
			return fmt.Errorf("annotations: invalid key %q: %s", k, strings.Join(errs, "; "))
		}
		if p.annotations[k], err = parseTemplate("annotations."+k, v); err != nil {
			return err
		}
	}

	for res, limit := range c.Quota {
		if res == "" || limit == "" {
			return fmt.Errorf("quota: empty resource or limit name (%q: %q)", res, limit)
		}
	}
	for limit, unit := range c.QuotaUnits {
		if _, err := resource.ParseQuantity("1" + unit); err != nil {
			return fmt.Errorf("quota_units.%s: invalid unit %q", limit, unit)
		}
	}
	if lr := c.LimitRange; lr != nil {
		for field, m := range map[string]map[string]string{"default": lr.Default, "default_request": lr.DefaultRequest} {
			if _, err := quantities(m); err != nil {
				return fmt.Errorf("limit_range.%s: %w", field, err)
			}
		}
	}
	for k, v := range c.AllowFromNamespaceLabels {
		if errs := validation.IsQualifiedName(k); len(errs) > 0 {
			return fmt.Errorf("allow_from_namespace_labels: invalid key %q", k)
		}
		if errs := validation.IsValidLabelValue(v); len(errs) > 0 {
			return fmt.Errorf("allow_from_namespace_labels.%s: invalid value %q", k, v)
		}
	}

	p.bindings = nil
	seen := map[string]bool{}
	for i, rb := range c.RoleBindings {
		field := fmt.Sprintf("role_bindings[%d]", i)
		if rb.Role == "" {
			return fmt.Errorf("%s.role is required", field)
		}
		if (rb.Group == "") == (rb.User == "") {
			return fmt.Errorf("%s: exactly one of group or user is required", field)
		}
		b := binding{name: rb.Name, role: rb.Role, kind: "Group"}
		if b.name == "" {
			b.name = "tenarium-" + rb.Role
		}
		if errs := validation.IsDNS1123Subdomain(b.name); len(errs) > 0 {
			return fmt.Errorf("%s: invalid name %q: %s", field, b.name, strings.Join(errs, "; "))
		}
		if seen[b.name] {
			return fmt.Errorf("%s: duplicate name %q (set name to tell bindings apart)", field, b.name)
		}
		seen[b.name] = true
		subject := rb.Group
		if rb.User != "" {
			b.kind, subject = "User", rb.User
		}
		if b.subject, err = parseTemplate(field+".subject", subject); err != nil {
			return err
		}
		p.bindings = append(p.bindings, b)
	}

	// Render for two sample tenants: every template must work, and the
	// namespace must depend on the tenant or tenants would share it.
	s1 := sdk.Tenant{ID: "00000000-0000-0000-0000-000000000001", Slug: "example-one", Name: "Example One", Plan: "free"}
	s2 := sdk.Tenant{ID: "00000000-0000-0000-0000-000000000002", Slug: "example-two", Name: "Example Two", Plan: "free"}
	n1, err := p.namespaceName(s1)
	if err != nil {
		return err
	}
	n2, err := p.namespaceName(s2)
	if err != nil {
		return err
	}
	if n1 == n2 {
		return errors.New("name_template must depend on the tenant (e.g. {{.Slug}} or {{.ID}})")
	}
	if _, err := p.namespaceMeta(s1); err != nil {
		return err
	}
	if _, err := p.roleBindings(s1, n1); err != nil {
		return err
	}
	return nil
}

func parseTemplate(field, s string) (*template.Template, error) {
	t, err := template.New(field).Option("missingkey=error").Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return t, nil
}

func render(t *template.Template, tenant sdk.Tenant) (string, error) {
	var b strings.Builder
	if err := t.Execute(&b, tenant); err != nil {
		return "", fmt.Errorf("%s: %w", t.Name(), err)
	}
	return b.String(), nil
}

// quantities parses a map of resource name → quantity.
func quantities(m map[string]string) (map[string]resource.Quantity, error) {
	out := make(map[string]resource.Quantity, len(m))
	for k, v := range m {
		q, err := resource.ParseQuantity(v)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid quantity %q", k, v)
		}
		out[k] = q
	}
	return out, nil
}

// namespaceName renders the tenant's namespace name.
func (p *Plugin) namespaceName(t sdk.Tenant) (string, error) {
	s, err := render(p.name, t)
	if err != nil {
		return "", err
	}
	name := sanitize(s)
	if name == "" {
		return "", fmt.Errorf("name_template renders an empty name for tenant %q", t.ID)
	}
	if len(name) > maxNameLen {
		// Truncating alone could map two tenants to one name; a hash of the
		// tenant ID keeps shortened names distinct.
		sum := sha256.Sum256([]byte(t.ID))
		name = strings.TrimRight(name[:maxNameLen-9], "-") + "-" + hex.EncodeToString(sum[:4])
	}
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		return "", fmt.Errorf("name_template renders invalid namespace %q: %s", name, strings.Join(errs, "; "))
	}
	return name, nil
}

// SanitizeName turns s into a DNS-1123 label: lowercase, characters other
// than [a-z0-9-] become "-", leading and trailing "-" are trimmed. The
// result may exceed 63 characters.
func SanitizeName(s string) string { return sanitize(s) }

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// tenantLabels are the labels identifying a tenant's objects.
func tenantLabels(t sdk.Tenant) map[string]string {
	return map[string]string{
		LabelManagedBy:  managedByValue,
		LabelTenantID:   t.ID,
		LabelTenantSlug: t.Slug,
		LabelPlan:       t.Plan,
	}
}

// namespaceMeta renders the labels and annotations of the tenant namespace.
func (p *Plugin) namespaceMeta(t sdk.Tenant) (metav1.ObjectMeta, error) {
	m := metav1.ObjectMeta{Labels: map[string]string{}, Annotations: map[string]string{}}
	for k, tmpl := range p.labels {
		v, err := render(tmpl, t)
		if err != nil {
			return m, err
		}
		m.Labels[k] = v
	}
	maps.Copy(m.Labels, tenantLabels(t))
	for k, v := range m.Labels {
		if errs := validation.IsValidLabelValue(v); len(errs) > 0 {
			return m, fmt.Errorf("label %s: invalid value %q for tenant %s: %s", k, v, t.ID, strings.Join(errs, "; "))
		}
	}
	for k, tmpl := range p.annotations {
		v, err := render(tmpl, t)
		if err != nil {
			return m, err
		}
		m.Annotations[k] = v
	}
	return m, nil
}

// TenantInfo is the response of GET /tenants/{tenant}.
type TenantInfo struct {
	Namespace string `json:"namespace"`
	// Phase is the namespace phase ("Active", "Terminating"), or "Missing"
	// if it does not exist.
	Phase string `json:"phase"`
	// Quota holds the hard limits of the tenant's ResourceQuota and Used its
	// current usage.
	Quota map[string]string `json:"quota,omitempty"`
	Used  map[string]string `json:"used,omitempty"`
}

func (p *Plugin) serveTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, err := p.host.GetTenant(ctx, r.PathValue("tenant"))
	if errors.Is(err, sdk.ErrNotFound) {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Answer "not found" rather than "forbidden" so callers cannot probe
	// other tenants' slugs.
	res := sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
	if err := p.host.Authorize(ctx, sdk.ActionTenantsRead, res); err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}
	name, err := p.namespaceName(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info := TenantInfo{Namespace: name, Phase: "Missing"}
	ns, err := p.client.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	case ns.Labels[LabelTenantID] != t.ID:
		// Someone else's namespace: report nothing about it.
		info.Phase = "Conflict"
	default:
		info.Phase = string(ns.Status.Phase)
		if info.Phase == "" {
			info.Phase = "Active"
		}
		q, err := p.client.CoreV1().ResourceQuotas(name).Get(ctx, QuotaName, metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if err == nil {
			info.Quota = quantityStrings(q.Spec.Hard)
			info.Used = quantityStrings(q.Status.Used)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func quantityStrings[K ~string](m map[K]resource.Quantity) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[string(k)] = v.String()
	}
	return out
}

// Health checks that the API server is reachable.
func (p *Plugin) Health(context.Context) error {
	_, err := p.client.Discovery().ServerVersion()
	return err
}
