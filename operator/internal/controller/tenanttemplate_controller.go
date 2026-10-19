package controller

import (
	"context"
	"errors"
	"maps"
	"reflect"
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
	"github.com/AimTune/tenarium/pkg/sdk"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

// TenantTemplateReconciler reconciles TenantTemplate resources with
// Tenarium tenant templates (platform-only: the API key needs plans:write).
type TenantTemplateReconciler struct {
	ctrlclient.Client
	Connections             *Connections
	Recorder                Recorder
	ResyncPeriod            time.Duration
	MaxBackoff              time.Duration
	MaxConcurrentReconciles int
}

// +kubebuilder:rbac:groups=tenarium.io,resources=tenanttemplates,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=tenarium.io,resources=tenanttemplates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tenarium.io,resources=tenanttemplates/finalizers,verbs=update

// Reconcile brings one Tenarium tenant template in line with a
// TenantTemplate resource.
func (r *TenantTemplateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var tpl tenariumv1.TenantTemplate
	if err := r.Get(ctx, req.NamespacedName, &tpl); err != nil {
		return ctrl.Result{}, ctrlclient.IgnoreNotFound(err)
	}
	if !tpl.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &tpl)
	}
	if !controllerutil.ContainsFinalizer(&tpl, tenariumv1.Finalizer) {
		controllerutil.AddFinalizer(&tpl, tenariumv1.Finalizer)
		if err := r.Update(ctx, &tpl); err != nil {
			return ctrl.Result{}, err
		}
	}

	orig := tpl.DeepCopy()
	res, err := r.sync(ctx, &tpl)
	tpl.Status.ObservedGeneration = tpl.Generation
	now := metav1.Now()
	tpl.Status.LastSyncTime = &now
	if perr := r.Status().Patch(ctx, &tpl, ctrlclient.MergeFrom(orig)); perr != nil {
		if apierrors.IsNotFound(perr) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Join(err, perr)
	}
	return res, err
}

func (r *TenantTemplateReconciler) sync(ctx context.Context, tpl *tenariumv1.TenantTemplate) (ctrl.Result, error) {
	gen := tpl.Generation
	fail := func(reason string, err error) (ctrl.Result, error) {
		setCondition(&tpl.Status.Conditions, gen, tenariumv1.ConditionSynced, false, reason, err.Error())
		if !meta.IsStatusConditionTrue(tpl.Status.Conditions, tenariumv1.ConditionReady) {
			setCondition(&tpl.Status.Conditions, gen, tenariumv1.ConditionReady, false, reason, err.Error())
		}
		r.Recorder.Eventf(tpl, nil, corev1.EventTypeWarning, EventSyncFailed, "Sync", "%s", truncate(err.Error(), 512))
		return ctrl.Result{}, err
	}
	c, err := r.Connections.For(ctx, tpl.Namespace, tpl.Spec.ConnectionRef)
	if err != nil {
		return fail(ReasonConnectionError, err)
	}
	id := tpl.TemplateID()
	want, err := desiredTemplate(tpl)
	if err != nil {
		return fail(ReasonInvalidSpec, err)
	}

	remote, err := c.Templates.Get(ctx, id)
	switch {
	case client.IsNotFound(err):
		if tpl.Status.ID != "" {
			r.Recorder.Eventf(tpl, nil, corev1.EventTypeWarning, EventRemoteMissing, "Sync", "template %s was deleted outside Kubernetes; recreating it", id)
		}
		if _, err := c.Templates.Put(ctx, id, want); err != nil {
			return fail(apiReason(err), err)
		}
		r.Recorder.Eventf(tpl, nil, corev1.EventTypeNormal, EventCreated, "Create", "created template %s", id)
	case err != nil:
		return fail(apiReason(err), err)
	// A template identical to the spec is safe to take over: it is most likely
	// the one this resource created before its status could be saved.
	case tpl.Status.ID == id || adoptRequested(tpl) || templateEqual(want, remote):
		if tpl.Status.ID != id {
			r.Recorder.Eventf(tpl, nil, corev1.EventTypeNormal, EventAdopted, "Adopt", "adopted existing template %s", id)
		}
		if !templateEqual(want, remote) {
			if _, err := c.Templates.Put(ctx, id, want); err != nil {
				return fail(apiReason(err), err)
			}
			reason, verb := EventUpdated, "updated"
			if tpl.Status.ObservedGeneration == tpl.Generation && tpl.Status.ID == id {
				reason, verb = EventDriftRepaired, "repaired drift in"
			}
			r.Recorder.Eventf(tpl, nil, corev1.EventTypeNormal, reason, "Update", "%s template %s", verb, id)
		}
	default:
		// A different template with the same ID belongs to someone else:
		// adoption must be explicit.
		msg := "template " + id + " already exists in Tenarium; annotate the resource with " + tenariumv1.AnnotationAdopt + "=true to adopt it"
		setCondition(&tpl.Status.Conditions, gen, tenariumv1.ConditionSynced, false, ReasonAlreadyExists, msg)
		setCondition(&tpl.Status.Conditions, gen, tenariumv1.ConditionReady, false, ReasonAlreadyExists, msg)
		r.Recorder.Eventf(tpl, nil, corev1.EventTypeWarning, EventAlreadyExists, "Adopt", "%s", msg)
		return ctrl.Result{RequeueAfter: r.resync()}, nil
	}
	tpl.Status.ID = id
	setCondition(&tpl.Status.Conditions, gen, tenariumv1.ConditionSynced, true, ReasonSynced, "template matches the spec")
	setCondition(&tpl.Status.Conditions, gen, tenariumv1.ConditionReady, true, ReasonAvailable, "template exists in Tenarium")
	return ctrl.Result{RequeueAfter: r.resync()}, nil
}

// desiredTemplate converts the spec to the API representation.
func desiredTemplate(tpl *tenariumv1.TenantTemplate) (client.TenantTemplate, error) {
	settings, err := rawObject(tpl.Spec.Settings, "spec.settings")
	if err != nil {
		return client.TenantTemplate{}, err
	}
	name := tpl.Spec.Name
	if name == "" {
		name = tpl.TemplateID()
	}
	out := client.TenantTemplate{
		ID:          tpl.TemplateID(),
		Name:        name,
		Description: tpl.Spec.Description,
		Plan:        tpl.Spec.Plan,
		AddOns:      slices.Clone(tpl.Spec.AddOns),
		Region:      tpl.Spec.Region,
		Labels:      maps.Clone(tpl.Spec.Labels),
		Settings:    settings,
		Features:    maps.Clone(tpl.Spec.Features),
		Limits:      maps.Clone(tpl.Spec.Limits),
	}
	if b := toSDKBranding(tpl.Spec.Branding); b != nil && *b != (sdk.Branding{}) {
		out.Branding = b
	}
	for _, role := range tpl.Spec.Roles {
		out.Roles = append(out.Roles, client.TemplateRole{Name: role.Name, Description: role.Description, Actions: slices.Clone(role.Actions)})
	}
	return out, nil
}

// templateEqual compares the managed fields of two templates; nil and
// empty lists and maps are equal.
func templateEqual(a, b client.TenantTemplate) bool {
	var ab, bb sdk.Branding
	if a.Branding != nil {
		ab = *a.Branding
	}
	if b.Branding != nil {
		bb = *b.Branding
	}
	return a.Name == b.Name && a.Description == b.Description && a.Plan == b.Plan && a.Region == b.Region &&
		slices.Equal(a.AddOns, b.AddOns) && maps.Equal(a.Labels, b.Labels) &&
		maps.Equal(a.Features, b.Features) && maps.Equal(a.Limits, b.Limits) &&
		(len(a.Settings) == 0 && len(b.Settings) == 0 || reflect.DeepEqual(a.Settings, b.Settings)) &&
		ab == bb &&
		slices.EqualFunc(a.Roles, b.Roles, func(x, y client.TemplateRole) bool {
			return x.Name == y.Name && x.Description == y.Description && slices.Equal(x.Actions, y.Actions)
		})
}

func (r *TenantTemplateReconciler) resync() time.Duration {
	if r.ResyncPeriod > 0 {
		return r.ResyncPeriod
	}
	return DefaultResyncPeriod
}

func (r *TenantTemplateReconciler) finalize(ctx context.Context, tpl *tenariumv1.TenantTemplate) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(tpl, tenariumv1.Finalizer) {
		return ctrl.Result{}, nil
	}
	if tpl.Spec.DeletionPolicy != tenariumv1.DeletionPolicyOrphan && tpl.Status.ID != "" {
		orig := tpl.DeepCopy()
		requeue, err := deletePlatformObject(ctx, r.Connections, r.Recorder, tpl, &tpl.Status.Conditions, tpl.Spec.ConnectionRef, "template", tpl.Status.ID,
			func(c *client.Client) error { return c.Templates.Delete(ctx, tpl.Status.ID) })
		if requeue || err != nil {
			if perr := r.Status().Patch(ctx, tpl, ctrlclient.MergeFrom(orig)); perr != nil && !apierrors.IsNotFound(perr) {
				log.FromContext(ctx).Error(perr, "patch status")
			}
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: waitRequeue}, nil
		}
	} else if tpl.Spec.DeletionPolicy == tenariumv1.DeletionPolicyOrphan {
		r.Recorder.Eventf(tpl, nil, corev1.EventTypeNormal, EventOrphaned, "Delete", "left template %s in Tenarium (deletionPolicy Orphan)", tpl.TemplateID())
	}
	controllerutil.RemoveFinalizer(tpl, tenariumv1.Finalizer)
	return ctrl.Result{}, ctrlclient.IgnoreNotFound(r.Update(ctx, tpl))
}

// SetupWithManager registers the reconciler and its watches.
func (r *TenantTemplateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &tenariumv1.TenantTemplate{}, indexConnection, func(o ctrlclient.Object) []string {
		return connectionRefName(o.(*tenariumv1.TenantTemplate).Spec.ConnectionRef)
	}); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("tenanttemplate").
		For(&tenariumv1.TenantTemplate{}, builder.WithPredicates(specChanged())).
		Watches(&tenariumv1.TenariumConnection{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o ctrlclient.Object) []reconcile.Request {
			var l tenariumv1.TenantTemplateList
			if err := r.List(ctx, &l, ctrlclient.InNamespace(o.GetNamespace()), ctrlclient.MatchingFields{indexConnection: o.GetName()}); err != nil {
				log.FromContext(ctx).Error(err, "list templates by connection")
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
