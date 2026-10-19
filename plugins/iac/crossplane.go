package iac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"gopkg.in/yaml.v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

// Labels set on the Crossplane resource.
const (
	LabelManagedBy  = "app.kubernetes.io/managed-by"
	LabelTenantID   = "tenarium.io/tenant-id"
	LabelTenantSlug = "tenarium.io/tenant-slug"

	managedByValue = "tenarium"
)

// DefaultPollInterval is the readiness poll interval.
const DefaultPollInterval = 5 * time.Second

var secretsGVR = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}

// crossplane creates one Claim (namespaced) or Composite resource
// (cluster-scoped) per tenant from a YAML template.
type crossplane struct {
	p        *Plugin
	client   dynamic.Interface
	mapper   meta.RESTMapper
	resource string
	tmpl     *template.Template
	wait     bool
	poll     time.Duration
	health   func(ctx context.Context) error
}

func newCrossplane(_ context.Context, p *Plugin) (*crossplane, error) {
	c := p.cfg.Crossplane
	e := &crossplane{p: p, client: p.dyn, resource: c.Resource, wait: true, poll: DefaultPollInterval}
	if c.Wait != nil {
		e.wait = *c.Wait
	}
	if c.PollInterval != "" {
		d, err := time.ParseDuration(c.PollInterval)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("crossplane.poll_interval: invalid duration %q", c.PollInterval)
		}
		e.poll = d
	}
	if c.QPS < 0 || c.Burst < 0 {
		return nil, errors.New("crossplane: qps and burst must not be negative")
	}
	src := c.Manifest
	switch {
	case c.Manifest != "" && c.ManifestFile != "":
		return nil, errors.New("crossplane: set only one of manifest and manifest_file")
	case c.ManifestFile != "":
		b, err := os.ReadFile(c.ManifestFile)
		if err != nil {
			return nil, fmt.Errorf("crossplane.manifest_file: %w", err)
		}
		src = string(b)
	case c.Manifest == "":
		return nil, errors.New("crossplane: manifest or manifest_file is required")
	}
	var err error
	if e.tmpl, err = parseTemplate("crossplane.manifest", src); err != nil {
		return nil, err
	}
	// Both sample tenants must render a valid object, with distinct
	// identities, or tenants would share (and delete) one resource.
	a, err := e.object(sampleInputs[0])
	if err != nil {
		return nil, err
	}
	b, err := e.object(sampleInputs[1])
	if err != nil {
		return nil, err
	}
	if a.GetName() == b.GetName() && a.GetNamespace() == b.GetNamespace() {
		return nil, errors.New("crossplane.manifest: metadata.name (or namespace) must depend on the tenant, e.g. tenant-{{.Slug}}")
	}

	if e.client == nil {
		rc, err := restConfig(c)
		if err != nil {
			return nil, err
		}
		if e.client, err = dynamic.NewForConfig(rc); err != nil {
			return nil, err
		}
		dc, err := discovery.NewDiscoveryClientForConfig(rc)
		if err != nil {
			return nil, err
		}
		e.health = func(context.Context) error {
			_, err := dc.ServerVersion()
			return err
		}
		if e.resource == "" {
			e.mapper = restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))
		}
	} else if e.resource == "" {
		return nil, errors.New("crossplane.resource is required with an injected client")
	}
	if e.health == nil {
		e.health = func(ctx context.Context) error {
			// Injected clients (tests): any request proves reachability.
			_, err := e.client.Resource(secretsGVR).Namespace("default").List(ctx, metav1.ListOptions{Limit: 1})
			return err
		}
	}
	return e, nil
}

func restConfig(c *CrossplaneConfig) (*rest.Config, error) {
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
	return rc, nil
}

func (e *crossplane) Name() string { return EngineCrossplane }

func (e *crossplane) Health(ctx context.Context) error { return e.health(ctx) }

// object renders the manifest for a tenant and labels it.
func (e *crossplane) object(in Input) (*unstructured.Unstructured, error) {
	s, err := render(e.tmpl, templateData(in))
	if err != nil {
		return nil, err
	}
	var doc any
	if err := yaml.Unmarshal([]byte(s), &doc); err != nil {
		return nil, fmt.Errorf("crossplane.manifest: invalid YAML: %w", err)
	}
	if _, ok := doc.(map[string]any); !ok {
		return nil, errors.New("crossplane.manifest must render one YAML object")
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("crossplane.manifest: %w", err)
	}
	u := &unstructured.Unstructured{}
	if err := u.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("crossplane.manifest: %w", err)
	}
	if u.GetAPIVersion() == "" || u.GetKind() == "" {
		return nil, errors.New("crossplane.manifest: apiVersion and kind are required")
	}
	if u.GetName() == "" {
		return nil, errors.New("crossplane.manifest: metadata.name is required")
	}
	if u.GetGenerateName() != "" {
		return nil, errors.New("crossplane.manifest: metadata.generateName is not supported (the name must be stable)")
	}
	labels := u.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	labels[LabelManagedBy] = managedByValue
	labels[LabelTenantID] = in.Tenant.ID
	labels[LabelTenantSlug] = labelValue(in.Tenant.Slug)
	u.SetLabels(labels)
	delete(u.Object, "status")
	return u, nil
}

// resourceFor returns the client for obj's kind and namespace.
func (e *crossplane) resourceFor(obj *unstructured.Unstructured) (dynamic.ResourceInterface, error) {
	gvk := obj.GroupVersionKind()
	var gvr schema.GroupVersionResource
	if e.resource != "" {
		gvr = gvk.GroupVersion().WithResource(e.resource)
	} else {
		m, err := e.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", gvk, err)
		}
		gvr = m.Resource
	}
	if ns := obj.GetNamespace(); ns != "" {
		return e.client.Resource(gvr).Namespace(ns), nil
	}
	return e.client.Resource(gvr), nil
}

func describe(u *unstructured.Unstructured) string {
	if ns := u.GetNamespace(); ns != "" {
		return fmt.Sprintf("%s %s/%s", u.GetKind(), ns, u.GetName())
	}
	return fmt.Sprintf("%s %s", u.GetKind(), u.GetName())
}

// errNotOwned means an object of that name exists for another tenant (or
// was not created by Tenarium).
var errNotOwned = errors.New("exists and does not belong to the tenant")

func owned(u *unstructured.Unstructured, t sdk.Tenant) bool {
	return u.GetLabels()[LabelTenantID] == t.ID
}

func (e *crossplane) Apply(ctx context.Context, in Input) (*Result, error) {
	want, err := e.object(in)
	if err != nil {
		return nil, err
	}
	ri, err := e.resourceFor(want)
	if err != nil {
		return nil, err
	}
	cur, err := ri.Get(ctx, want.GetName(), metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if cur, err = ri.Create(ctx, want, metav1.CreateOptions{FieldManager: "tenarium"}); err != nil {
			return nil, fmt.Errorf("create %s: %w", describe(want), err)
		}
	case err != nil:
		return nil, fmt.Errorf("get %s: %w", describe(want), err)
	case !owned(cur, in.Tenant):
		// Never adopt: a name clash must not hand a resource to another tenant.
		return nil, fmt.Errorf("%s %w", describe(want), errNotOwned)
	case cur.GetDeletionTimestamp() != nil:
		return nil, fmt.Errorf("%s is being deleted; retry once it is gone", describe(want))
	default:
		next := cur.DeepCopy()
		// Replace everything but metadata and status from the template;
		// merge labels and annotations so other controllers' keys stay.
		for k := range next.Object {
			if k != "metadata" && k != "status" {
				delete(next.Object, k)
			}
		}
		for k, v := range want.Object {
			if k != "metadata" && k != "status" {
				next.Object[k] = v
			}
		}
		labels := next.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		maps.Copy(labels, want.GetLabels())
		next.SetLabels(labels)
		if a := want.GetAnnotations(); len(a) > 0 {
			ann := next.GetAnnotations()
			if ann == nil {
				ann = map[string]string{}
			}
			maps.Copy(ann, a)
			next.SetAnnotations(ann)
		}
		if cur, err = ri.Update(ctx, next, metav1.UpdateOptions{FieldManager: "tenarium"}); err != nil {
			return nil, fmt.Errorf("update %s: %w", describe(want), err)
		}
	}
	if e.wait {
		if cur, err = e.waitReady(ctx, ri, want); err != nil {
			return nil, err
		}
	}
	return e.result(ctx, cur)
}

// waitReady polls until the Ready condition is True or ctx is done.
func (e *crossplane) waitReady(ctx context.Context, ri dynamic.ResourceInterface, want *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	ticker := time.NewTicker(e.poll)
	defer ticker.Stop()
	var last string
	for {
		cur, err := ri.Get(ctx, want.GetName(), metav1.GetOptions{})
		if err != nil && ctx.Err() == nil {
			return nil, fmt.Errorf("get %s: %w", describe(want), err)
		}
		if err == nil {
			ready, msg := condition(cur, "Ready")
			if ready {
				return cur, nil
			}
			last = msg
			if synced, smsg := condition(cur, "Synced"); !synced && smsg != "" {
				last = "Synced: " + smsg
			}
		}
		select {
		case <-ctx.Done():
			if last != "" {
				return nil, fmt.Errorf("%s is not ready (%s): %w", describe(want), last, ctx.Err())
			}
			return nil, fmt.Errorf("%s is not ready: %w", describe(want), ctx.Err())
		case <-ticker.C:
		}
	}
}

// condition returns whether the condition is True and its reason/message.
func condition(u *unstructured.Unstructured, typ string) (bool, string) {
	conds, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if !ok || m["type"] != typ {
			continue
		}
		msg := fmt.Sprint(m["reason"])
		if s, _ := m["message"].(string); s != "" {
			msg += ": " + s
		}
		return m["status"] == "True", msg
	}
	return false, ""
}

func (e *crossplane) Destroy(ctx context.Context, in Input) error {
	want, err := e.object(in)
	if err != nil {
		return err
	}
	ri, err := e.resourceFor(want)
	if err != nil {
		return err
	}
	cur, err := ri.Get(ctx, want.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("get %s: %w", describe(want), err)
	}
	if !owned(cur, in.Tenant) {
		e.p.log.Warn("not deleting a resource owned by another tenant", "resource", describe(want),
			"tenant_id", in.Tenant.ID, "owner", cur.GetLabels()[LabelTenantID])
		return nil
	}
	if cur.GetDeletionTimestamp() == nil {
		uid := cur.GetUID()
		opts := metav1.DeleteOptions{}
		if uid != "" {
			opts.Preconditions = &metav1.Preconditions{UID: &uid}
		}
		if err := ri.Delete(ctx, want.GetName(), opts); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete %s: %w", describe(want), err)
		}
	}
	if !e.wait {
		return nil
	}
	ticker := time.NewTicker(e.poll)
	defer ticker.Stop()
	for {
		_, err := ri.Get(ctx, want.GetName(), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		} else if err != nil && ctx.Err() == nil {
			return fmt.Errorf("get %s: %w", describe(want), err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s is still being deleted: %w", describe(want), ctx.Err())
		case <-ticker.C:
		}
	}
}

func (e *crossplane) Outputs(ctx context.Context, in Input) (*Result, error) {
	want, err := e.object(in)
	if err != nil {
		return nil, err
	}
	ri, err := e.resourceFor(want)
	if err != nil {
		return nil, err
	}
	cur, err := ri.Get(ctx, want.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, ErrNoOutputs
	} else if err != nil {
		return nil, fmt.Errorf("get %s: %w", describe(want), err)
	}
	if !owned(cur, in.Tenant) {
		return nil, ErrNoOutputs
	}
	return e.result(ctx, cur)
}

// result builds the outputs of a resource: the fields of its status
// (except conditions) and the key names of its connection secret.
func (e *crossplane) result(ctx context.Context, u *unstructured.Unstructured) (*Result, error) {
	res := &Result{Outputs: map[string]Output{}}
	status, _, _ := unstructured.NestedMap(u.Object, "status")
	for k, v := range status {
		if k == "conditions" || k == "connectionDetails" {
			continue
		}
		res.Outputs[k] = Output{Value: v}
	}
	ready, _ := condition(u, "Ready")
	res.Ready = &ready
	if ts := latestTransition(u); !ts.IsZero() {
		res.UpdatedAt = ts
	}

	ref, ok, _ := unstructured.NestedStringMap(u.Object, "spec", "writeConnectionSecretToRef")
	if ok && ref["name"] != "" {
		ns := ref["namespace"]
		if ns == "" {
			ns = u.GetNamespace() // claims write the secret to their namespace
		}
		cs := &ConnectionSecret{Name: ref["name"], Namespace: ns}
		var ri dynamic.ResourceInterface = e.client.Resource(secretsGVR)
		if ns != "" {
			ri = e.client.Resource(secretsGVR).Namespace(ns)
		}
		secret, err := ri.Get(ctx, cs.Name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
		case err != nil:
			return nil, fmt.Errorf("get connection secret %s/%s: %w", ns, cs.Name, err)
		default:
			// Key names only: values never leave the cluster.
			data, _, _ := unstructured.NestedMap(secret.Object, "data")
			cs.Keys = slices.Sorted(maps.Keys(data))
		}
		res.ConnectionSecret = cs
	}
	return res, nil
}

func latestTransition(u *unstructured.Unstructured) time.Time {
	conds, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	var latest time.Time
	for _, c := range conds {
		m, _ := c.(map[string]any)
		s, _ := m["lastTransitionTime"].(string)
		if ts, err := time.Parse(time.RFC3339, s); err == nil && ts.After(latest) {
			latest = ts.UTC()
		}
	}
	return latest
}

// labelValue makes s a valid label value (at most 63 characters).
func labelValue(s string) string {
	s = sanitizeDNS(s)
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	return s
}
