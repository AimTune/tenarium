package controller

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

// PlanReconciler reconciles Plan resources with Tenarium plans.
type PlanReconciler struct {
	ctrlclient.Client
	Connections             *Connections
	Recorder                Recorder
	ResyncPeriod            time.Duration
	MaxBackoff              time.Duration
	MaxConcurrentReconciles int
}

// +kubebuilder:rbac:groups=tenarium.io,resources=plans,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=tenarium.io,resources=plans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tenarium.io,resources=plans/finalizers,verbs=update

// Reconcile brings one Tenarium plan in line with a Plan resource.
func (r *PlanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var p tenariumv1.Plan
	if err := r.Get(ctx, req.NamespacedName, &p); err != nil {
		return ctrl.Result{}, ctrlclient.IgnoreNotFound(err)
	}
	if !p.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &p)
	}
	if !controllerutil.ContainsFinalizer(&p, tenariumv1.Finalizer) {
		controllerutil.AddFinalizer(&p, tenariumv1.Finalizer)
		if err := r.Update(ctx, &p); err != nil {
			return ctrl.Result{}, err
		}
	}

	orig := p.DeepCopy()
	res, err := r.sync(ctx, &p)
	p.Status.ObservedGeneration = p.Generation
	now := metav1.Now()
	p.Status.LastSyncTime = &now
	if perr := r.Status().Patch(ctx, &p, ctrlclient.MergeFrom(orig)); perr != nil {
		if apierrors.IsNotFound(perr) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Join(err, perr)
	}
	return res, err
}

func (r *PlanReconciler) sync(ctx context.Context, p *tenariumv1.Plan) (ctrl.Result, error) {
	gen := p.Generation
	fail := func(reason string, err error) (ctrl.Result, error) {
		setCondition(&p.Status.Conditions, gen, tenariumv1.ConditionSynced, false, reason, err.Error())
		if !meta.IsStatusConditionTrue(p.Status.Conditions, tenariumv1.ConditionReady) {
			setCondition(&p.Status.Conditions, gen, tenariumv1.ConditionReady, false, reason, err.Error())
		}
		r.Recorder.Eventf(p, nil, corev1.EventTypeWarning, EventSyncFailed, "Sync", "%s", truncate(err.Error(), 512))
		return ctrl.Result{}, err
	}
	c, err := r.Connections.For(ctx, p.Namespace, p.Spec.ConnectionRef)
	if err != nil {
		return fail(ReasonConnectionError, err)
	}
	id := p.PlanID()
	createKey := client.WithIdempotencyKey(idempotencyKey(p.UID, p.Generation, "create-plan"))
	createReq := client.CreatePlanRequest{
		ID: id, Name: planName(p), Description: p.Spec.Description, Features: p.Spec.Features, Limits: p.Spec.Limits,
	}

	remote, err := c.Plans.Get(ctx, id)
	switch {
	case client.IsNotFound(err):
		if p.Status.ID != "" {
			r.Recorder.Eventf(p, nil, corev1.EventTypeWarning, EventRemoteMissing, "Sync", "plan %s was deleted outside Kubernetes; recreating it", id)
			// The original create must not be replayed: derive a new key
			// from the last version seen.
			var seen int64
			if p.Status.LastSyncTime != nil {
				seen = p.Status.LastSyncTime.UnixNano()
			}
			createKey = client.WithIdempotencyKey(idempotencyKey(p.UID, p.Generation, fmt.Sprintf("recreate-plan/%d/%d", p.Status.Version, seen)))
		}
		remote, err = c.Plans.Create(ctx, createReq, createKey)
		if err != nil {
			return fail(apiReason(err), err)
		}
		r.Recorder.Eventf(p, nil, corev1.EventTypeNormal, EventCreated, "Create", "created plan %s", id)
	case err != nil:
		return fail(apiReason(err), err)
	case p.Status.ID == id:
		// Ours.
	case adoptRequested(p):
		r.Recorder.Eventf(p, nil, corev1.EventTypeNormal, EventAdopted, "Adopt", "adopted existing plan %s", id)
	default:
		// The plan exists but the status does not claim it. If this resource
		// created it and the status update was lost, repeating the create
		// with the same Idempotency-Key replays the original response.
		if _, rerr := c.Plans.Create(ctx, createReq, createKey); rerr != nil {
			msg := fmt.Sprintf("plan %q already exists in Tenarium; annotate the resource with %s=true to adopt it", id, tenariumv1.AnnotationAdopt)
			setCondition(&p.Status.Conditions, gen, tenariumv1.ConditionSynced, false, ReasonAlreadyExists, msg)
			setCondition(&p.Status.Conditions, gen, tenariumv1.ConditionReady, false, ReasonAlreadyExists, msg)
			r.Recorder.Eventf(p, nil, corev1.EventTypeWarning, EventAlreadyExists, "Adopt", "%s", msg)
			return ctrl.Result{RequeueAfter: r.resync()}, nil
		}
	}
	p.Status.ID = id

	remote, err = r.update(ctx, c, p, remote)
	if err != nil {
		if client.IsVersionConflict(err) {
			setCondition(&p.Status.Conditions, gen, tenariumv1.ConditionSynced, false, ReasonVersionConflict, err.Error())
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		return fail(apiReason(err), err)
	}
	p.Status.Version = remote.Version
	setCondition(&p.Status.Conditions, gen, tenariumv1.ConditionSynced, true, ReasonSynced, "plan matches the spec")
	setCondition(&p.Status.Conditions, gen, tenariumv1.ConditionReady, true, ReasonAvailable, "plan exists in Tenarium")
	return ctrl.Result{RequeueAfter: r.resync()}, nil
}

func (r *PlanReconciler) update(ctx context.Context, c *client.Client, p *tenariumv1.Plan, remote sdk.Plan) (sdk.Plan, error) {
	var req client.UpdatePlanRequest
	var changed []string
	if name := planName(p); name != remote.Name {
		req.Name = &name
		changed = append(changed, "name")
	}
	if p.Spec.Description != remote.Description {
		d := p.Spec.Description
		req.Description = &d
		changed = append(changed, "description")
	}
	if p.Spec.Features != nil && !maps.Equal(p.Spec.Features, remote.Features) {
		f := p.Spec.Features
		req.Features = &f
		changed = append(changed, "features")
	}
	if p.Spec.Limits != nil && !maps.Equal(p.Spec.Limits, remote.Limits) {
		l := p.Spec.Limits
		req.Limits = &l
		changed = append(changed, "limits")
	}
	if len(changed) == 0 {
		return remote, nil
	}
	updated, err := c.Plans.Update(ctx, remote.ID, req, client.IfMatch(remote.Version))
	if err != nil {
		return remote, err
	}
	reason, verb := EventUpdated, "updated"
	if p.Status.ObservedGeneration == p.Generation {
		reason, verb = EventDriftRepaired, "repaired drift in"
	}
	r.Recorder.Eventf(p, nil, corev1.EventTypeNormal, reason, "Update", "%s %s of plan %s", verb, strings.Join(changed, ", "), remote.ID)
	return updated, nil
}

func planName(p *tenariumv1.Plan) string {
	if p.Spec.Name != "" {
		return p.Spec.Name
	}
	return p.PlanID()
}

func (r *PlanReconciler) resync() time.Duration {
	if r.ResyncPeriod > 0 {
		return r.ResyncPeriod
	}
	return DefaultResyncPeriod
}

func (r *PlanReconciler) finalize(ctx context.Context, p *tenariumv1.Plan) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(p, tenariumv1.Finalizer) {
		return ctrl.Result{}, nil
	}
	if p.Spec.DeletionPolicy != tenariumv1.DeletionPolicyOrphan && p.Status.ID != "" {
		orig := p.DeepCopy()
		gen := p.Generation
		requeue, err := func() (bool, error) {
			c, err := r.Connections.For(ctx, p.Namespace, p.Spec.ConnectionRef)
			if err != nil {
				setCondition(&p.Status.Conditions, gen, tenariumv1.ConditionSynced, false, ReasonConnectionError, err.Error())
				return false, err
			}
			err = c.Plans.Delete(ctx, p.Status.ID)
			switch {
			case err == nil || client.IsNotFound(err):
				r.Recorder.Eventf(p, nil, corev1.EventTypeNormal, EventDeleted, "Delete", "deleted plan %s", p.Status.ID)
				return false, nil
			case client.IsConflict(err):
				// Typically: tenants still use the plan.
				msg := err.Error()
				if e, ok := client.AsError(err); ok {
					msg = e.Message
				}
				setCondition(&p.Status.Conditions, gen, tenariumv1.ConditionSynced, false, ReasonDeleteBlocked, msg)
				r.Recorder.Eventf(p, nil, corev1.EventTypeWarning, EventDeleteBlocked, "Delete", "cannot delete plan %s yet: %s", p.Status.ID, msg)
				return true, nil
			default:
				setCondition(&p.Status.Conditions, gen, tenariumv1.ConditionSynced, false, apiReason(err), err.Error())
				return false, err
			}
		}()
		if requeue || err != nil {
			if perr := r.Status().Patch(ctx, p, ctrlclient.MergeFrom(orig)); perr != nil && !apierrors.IsNotFound(perr) {
				log.FromContext(ctx).Error(perr, "patch status")
			}
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: waitRequeue}, nil
		}
	} else if p.Spec.DeletionPolicy == tenariumv1.DeletionPolicyOrphan {
		r.Recorder.Eventf(p, nil, corev1.EventTypeNormal, EventOrphaned, "Delete", "left plan %s in Tenarium (deletionPolicy Orphan)", p.PlanID())
	}
	controllerutil.RemoveFinalizer(p, tenariumv1.Finalizer)
	return ctrl.Result{}, ctrlclient.IgnoreNotFound(r.Update(ctx, p))
}

// SetupWithManager registers the reconciler and its watches.
func (r *PlanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &tenariumv1.Plan{}, indexConnection, func(o ctrlclient.Object) []string {
		return connectionRefName(o.(*tenariumv1.Plan).Spec.ConnectionRef)
	}); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("plan").
		For(&tenariumv1.Plan{}, builder.WithPredicates(specChanged())).
		Watches(&tenariumv1.TenariumConnection{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o ctrlclient.Object) []reconcile.Request {
			var l tenariumv1.PlanList
			if err := r.List(ctx, &l, ctrlclient.InNamespace(o.GetNamespace()), ctrlclient.MatchingFields{indexConnection: o.GetName()}); err != nil {
				log.FromContext(ctx).Error(err, "list plans by connection")
				return nil
			}
			return requests(l.Items)
		}), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: max(r.MaxConcurrentReconciles, 1),
			RateLimiter:             NewRateLimiter(r.MaxBackoff),
		}).
		Complete(r)
}
