package controller

import (
	"context"
	"errors"
	"maps"
	"slices"
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

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

// RolloutReconciler reconciles Rollout resources with Tenarium feature
// rollouts (platform-only: the API key needs plans:write).
type RolloutReconciler struct {
	ctrlclient.Client
	Connections             *Connections
	Recorder                Recorder
	ResyncPeriod            time.Duration
	MaxBackoff              time.Duration
	MaxConcurrentReconciles int
}

// +kubebuilder:rbac:groups=tenarium.io,resources=rollouts,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=tenarium.io,resources=rollouts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tenarium.io,resources=rollouts/finalizers,verbs=update

// Reconcile brings one Tenarium rollout in line with a Rollout resource.
func (r *RolloutReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ro tenariumv1.Rollout
	if err := r.Get(ctx, req.NamespacedName, &ro); err != nil {
		return ctrl.Result{}, ctrlclient.IgnoreNotFound(err)
	}
	if !ro.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &ro)
	}
	if !controllerutil.ContainsFinalizer(&ro, tenariumv1.Finalizer) {
		controllerutil.AddFinalizer(&ro, tenariumv1.Finalizer)
		if err := r.Update(ctx, &ro); err != nil {
			return ctrl.Result{}, err
		}
	}

	orig := ro.DeepCopy()
	res, err := r.sync(ctx, &ro)
	ro.Status.ObservedGeneration = ro.Generation
	now := metav1.Now()
	ro.Status.LastSyncTime = &now
	if perr := r.Status().Patch(ctx, &ro, ctrlclient.MergeFrom(orig)); perr != nil {
		if apierrors.IsNotFound(perr) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Join(err, perr)
	}
	return res, err
}

func (r *RolloutReconciler) sync(ctx context.Context, ro *tenariumv1.Rollout) (ctrl.Result, error) {
	gen := ro.Generation
	fail := func(reason string, err error) (ctrl.Result, error) {
		setCondition(&ro.Status.Conditions, gen, tenariumv1.ConditionSynced, false, reason, err.Error())
		if !meta.IsStatusConditionTrue(ro.Status.Conditions, tenariumv1.ConditionReady) {
			setCondition(&ro.Status.Conditions, gen, tenariumv1.ConditionReady, false, reason, err.Error())
		}
		r.Recorder.Eventf(ro, nil, corev1.EventTypeWarning, EventSyncFailed, "Sync", "%s", truncate(err.Error(), 512))
		return ctrl.Result{}, err
	}
	c, err := r.Connections.For(ctx, ro.Namespace, ro.Spec.ConnectionRef)
	if err != nil {
		return fail(ReasonConnectionError, err)
	}
	feature := ro.FeatureName()
	want := desiredRollout(ro)

	remote, err := c.Rollouts.Get(ctx, feature)
	switch {
	case client.IsNotFound(err):
		if ro.Status.Feature != "" {
			r.Recorder.Eventf(ro, nil, corev1.EventTypeWarning, EventRemoteMissing, "Sync", "rollout %s was deleted outside Kubernetes; recreating it", feature)
		}
		if _, err := c.Rollouts.Put(ctx, feature, want); err != nil {
			return fail(apiReason(err), err)
		}
		r.Recorder.Eventf(ro, nil, corev1.EventTypeNormal, EventCreated, "Create", "created rollout %s", feature)
	case err != nil:
		return fail(apiReason(err), err)
	// A rollout identical to the spec is safe to take over: it is most likely
	// the one this resource created before its status could be saved.
	case ro.Status.Feature == feature || adoptRequested(ro) || rolloutEqual(want, remote):
		if ro.Status.Feature != feature {
			r.Recorder.Eventf(ro, nil, corev1.EventTypeNormal, EventAdopted, "Adopt", "adopted existing rollout %s", feature)
		}
		if !rolloutEqual(want, remote) {
			if _, err := c.Rollouts.Put(ctx, feature, want); err != nil {
				return fail(apiReason(err), err)
			}
			reason, verb := EventUpdated, "updated"
			if ro.Status.ObservedGeneration == ro.Generation && ro.Status.Feature == feature {
				reason, verb = EventDriftRepaired, "repaired drift in"
			}
			r.Recorder.Eventf(ro, nil, corev1.EventTypeNormal, reason, "Update", "%s rollout %s", verb, feature)
		}
	default:
		// A different rollout of the same feature belongs to someone else:
		// adoption must be explicit.
		msg := "rollout " + feature + " already exists in Tenarium; annotate the resource with " + tenariumv1.AnnotationAdopt + "=true to adopt it"
		setCondition(&ro.Status.Conditions, gen, tenariumv1.ConditionSynced, false, ReasonAlreadyExists, msg)
		setCondition(&ro.Status.Conditions, gen, tenariumv1.ConditionReady, false, ReasonAlreadyExists, msg)
		r.Recorder.Eventf(ro, nil, corev1.EventTypeWarning, EventAlreadyExists, "Adopt", "%s", msg)
		return ctrl.Result{RequeueAfter: r.resync()}, nil
	}
	ro.Status.Feature = feature
	setCondition(&ro.Status.Conditions, gen, tenariumv1.ConditionSynced, true, ReasonSynced, "rollout matches the spec")
	setCondition(&ro.Status.Conditions, gen, tenariumv1.ConditionReady, true, ReasonAvailable, "rollout exists in Tenarium")
	return ctrl.Result{RequeueAfter: r.resync()}, nil
}

// desiredRollout converts the spec to the API representation.
func desiredRollout(ro *tenariumv1.Rollout) client.Rollout {
	return client.Rollout{
		Feature:    ro.FeatureName(),
		Percentage: ro.Spec.Percentage,
		Plans:      slices.Clone(ro.Spec.Plans),
		Labels:     maps.Clone(ro.Spec.Labels),
		Regions:    slices.Clone(ro.Spec.Regions),
		Include:    slices.Clone(ro.Spec.Include),
		Exclude:    slices.Clone(ro.Spec.Exclude),
		Enabled:    ro.Spec.Enabled,
	}
}

// rolloutEqual compares the managed fields of two rollouts; nil and empty
// lists and maps are equal.
func rolloutEqual(a, b client.Rollout) bool {
	return a.Percentage == b.Percentage && a.Enabled == b.Enabled &&
		slices.Equal(a.Plans, b.Plans) && maps.Equal(a.Labels, b.Labels) &&
		slices.Equal(a.Regions, b.Regions) && slices.Equal(a.Include, b.Include) &&
		slices.Equal(a.Exclude, b.Exclude)
}

func (r *RolloutReconciler) resync() time.Duration {
	if r.ResyncPeriod > 0 {
		return r.ResyncPeriod
	}
	return DefaultResyncPeriod
}

func (r *RolloutReconciler) finalize(ctx context.Context, ro *tenariumv1.Rollout) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(ro, tenariumv1.Finalizer) {
		return ctrl.Result{}, nil
	}
	if ro.Spec.DeletionPolicy != tenariumv1.DeletionPolicyOrphan && ro.Status.Feature != "" {
		orig := ro.DeepCopy()
		requeue, err := deletePlatformObject(ctx, r.Connections, r.Recorder, ro, &ro.Status.Conditions, ro.Spec.ConnectionRef, "rollout", ro.Status.Feature,
			func(c *client.Client) error { return c.Rollouts.Delete(ctx, ro.Status.Feature) })
		if requeue || err != nil {
			if perr := r.Status().Patch(ctx, ro, ctrlclient.MergeFrom(orig)); perr != nil && !apierrors.IsNotFound(perr) {
				log.FromContext(ctx).Error(perr, "patch status")
			}
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: waitRequeue}, nil
		}
	} else if ro.Spec.DeletionPolicy == tenariumv1.DeletionPolicyOrphan {
		r.Recorder.Eventf(ro, nil, corev1.EventTypeNormal, EventOrphaned, "Delete", "left rollout %s in Tenarium (deletionPolicy Orphan)", ro.FeatureName())
	}
	controllerutil.RemoveFinalizer(ro, tenariumv1.Finalizer)
	return ctrl.Result{}, ctrlclient.IgnoreNotFound(r.Update(ctx, ro))
}

// SetupWithManager registers the reconciler and its watches.
func (r *RolloutReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &tenariumv1.Rollout{}, indexConnection, func(o ctrlclient.Object) []string {
		return connectionRefName(o.(*tenariumv1.Rollout).Spec.ConnectionRef)
	}); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("rollout").
		For(&tenariumv1.Rollout{}, builder.WithPredicates(specChanged())).
		Watches(&tenariumv1.TenariumConnection{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o ctrlclient.Object) []reconcile.Request {
			var l tenariumv1.RolloutList
			if err := r.List(ctx, &l, ctrlclient.InNamespace(o.GetNamespace()), ctrlclient.MatchingFields{indexConnection: o.GetName()}); err != nil {
				log.FromContext(ctx).Error(err, "list rollouts by connection")
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
