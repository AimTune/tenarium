package k8stenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/AimTune/tenarium/pkg/sdk"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

// lifecycle handles tenant.suspended/resumed (scaling) and
// tenant.updated/plan_changed (re-syncing labels and quota).
//
// Events are delivered at least once and may be replayed, so the handler
// acts on the tenant's current state from the host rather than on the event
// payload: a replayed "suspended" after a resume does not scale down again.
func (p *Plugin) lifecycle(ctx context.Context, e sdk.Event) error {
	var data sdk.TenantEventData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return fmt.Errorf("decode %s event: %w", e.Type, err)
	}
	id := data.Tenant.ID
	if id == "" {
		id = e.TenantID
	}
	t, err := p.host.GetTenant(ctx, id)
	if errors.Is(err, sdk.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if !t.IsLive() {
		return nil
	}
	ns, ok, err := p.ownedNamespace(ctx, t)
	if err != nil || !ok {
		return err
	}
	switch e.Type {
	case sdk.EventTenantSuspended:
		if p.cfg.SuspendScaleToZero && t.Status == sdk.StatusSuspended {
			return p.scale(ctx, ns, suspendReplicas)
		}
	case sdk.EventTenantResumed:
		if p.cfg.SuspendScaleToZero && t.Status != sdk.StatusSuspended {
			return p.scale(ctx, ns, p.resumeReplicas)
		}
	case sdk.EventTenantUpdated, sdk.EventTenantPlanChanged:
		if _, err := p.ensureNamespace(ctx, t); err != nil {
			return err
		}
		return p.converge(ctx, t, ns)
	}
	return nil
}

// ownedNamespace returns the tenant's namespace if it exists and belongs to
// the tenant. A missing namespace is left to the provisioner.
func (p *Plugin) ownedNamespace(ctx context.Context, t sdk.Tenant) (string, bool, error) {
	name, err := p.namespaceName(t)
	if err != nil {
		return "", false, err
	}
	ns, err := p.client.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", false, nil
	} else if err != nil {
		return "", false, fmt.Errorf("namespace %s: %w", name, err)
	}
	if o := owner(ns); o != t.ID {
		p.log.Warn("ignoring a namespace owned by another tenant", "namespace", name, "tenant_id", t.ID, "owner", o)
		return "", false, nil
	}
	if ns.DeletionTimestamp != nil {
		return "", false, nil
	}
	return name, true, nil
}

// replicaFunc changes a workload's replicas and annotations and reports
// whether it changed anything.
type replicaFunc func(meta *metav1.ObjectMeta, replicas **int32) bool

// suspendReplicas scales to zero, recording the previous replica count.
// An existing record is kept, so suspending twice does not lose it.
func suspendReplicas(meta *metav1.ObjectMeta, replicas **int32) bool {
	cur := int32(1) // the API default for an unset replicas field
	if *replicas != nil {
		cur = **replicas
	}
	if _, recorded := meta.Annotations[AnnotationReplicasBeforeSuspend]; !recorded {
		if cur == 0 {
			return false
		}
		if meta.Annotations == nil {
			meta.Annotations = map[string]string{}
		}
		meta.Annotations[AnnotationReplicasBeforeSuspend] = strconv.FormatInt(int64(cur), 10)
	} else if cur == 0 {
		return false
	}
	zero := int32(0)
	*replicas = &zero
	return true
}

// resumeReplicas restores the recorded replica count and drops the record.
// Workloads without a record are left alone.
func (p *Plugin) resumeReplicas(meta *metav1.ObjectMeta, replicas **int32) bool {
	v, ok := meta.Annotations[AnnotationReplicasBeforeSuspend]
	if !ok {
		return false
	}
	delete(meta.Annotations, AnnotationReplicasBeforeSuspend)
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil || n < 0 {
		p.log.Warn("ignoring an invalid replica record", "namespace", meta.Namespace, "name", meta.Name, "value", v)
		return true
	}
	r := int32(n)
	*replicas = &r
	return true
}

// scale applies fn to every Deployment and StatefulSet in namespace ns.
func (p *Plugin) scale(ctx context.Context, ns string, fn replicaFunc) error {
	deploys := p.client.AppsV1().Deployments(ns)
	dl, err := deploys.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list deployments in %s: %w", ns, err)
	}
	for _, item := range dl.Items {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			d, err := deploys.Get(ctx, item.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return nil
			} else if err != nil {
				return err
			}
			if !fn(&d.ObjectMeta, &d.Spec.Replicas) {
				return nil
			}
			_, err = deploys.Update(ctx, d, metav1.UpdateOptions{})
			return err
		})
		if err != nil {
			return fmt.Errorf("scale deployment %s/%s: %w", ns, item.Name, err)
		}
	}

	sets := p.client.AppsV1().StatefulSets(ns)
	sl, err := sets.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list statefulsets in %s: %w", ns, err)
	}
	for _, item := range sl.Items {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			s, err := sets.Get(ctx, item.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return nil
			} else if err != nil {
				return err
			}
			if !fn(&s.ObjectMeta, &s.Spec.Replicas) {
				return nil
			}
			_, err = sets.Update(ctx, s, metav1.UpdateOptions{})
			return err
		})
		if err != nil {
			return fmt.Errorf("scale statefulset %s/%s: %w", ns, item.Name, err)
		}
	}
	return nil
}

var (
	_ sdk.Plugin        = (*Plugin)(nil)
	_ sdk.Provisioner   = (*Plugin)(nil)
	_ sdk.HealthChecker = (*Plugin)(nil)
)
