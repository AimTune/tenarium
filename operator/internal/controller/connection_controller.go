package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"github.com/AimTune/tenarium/pkg/sdk"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

// ConnectionReconciler checks that a TenariumConnection's server accepts
// its credentials and reports the result in the Ready condition.
type ConnectionReconciler struct {
	ctrlclient.Client
	Connections  *Connections
	Recorder     Recorder
	ResyncPeriod time.Duration
	MaxBackoff   time.Duration
}

// +kubebuilder:rbac:groups=tenarium.io,resources=tenariumconnections,verbs=get;list;watch
// +kubebuilder:rbac:groups=tenarium.io,resources=tenariumconnections/status,verbs=get;update;patch

// Reconcile verifies one TenariumConnection.
func (r *ConnectionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var conn tenariumv1.TenariumConnection
	if err := r.Get(ctx, req.NamespacedName, &conn); err != nil {
		return ctrl.Result{}, ctrlclient.IgnoreNotFound(err)
	}
	if !conn.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	orig := conn.DeepCopy()
	gen := conn.Generation
	wasReady := meta.IsStatusConditionTrue(conn.Status.Conditions, tenariumv1.ConditionReady)

	var checkErr error
	c, err := r.Connections.ForConnection(ctx, &conn)
	if err == nil {
		var p sdk.Principal
		if p, err = c.Me(ctx); err == nil {
			conn.Status.Principal = p.Kind + ":" + p.Subject
		}
	}
	if err != nil {
		checkErr = err
		setCondition(&conn.Status.Conditions, gen, tenariumv1.ConditionReady, false, ReasonConnectionError, err.Error())
		if wasReady || len(orig.Status.Conditions) == 0 {
			r.Recorder.Eventf(&conn, nil, corev1.EventTypeWarning, EventConnection, "Connect", "%s", truncate(err.Error(), 512))
		}
	} else {
		setCondition(&conn.Status.Conditions, gen, tenariumv1.ConditionReady, true, ReasonAvailable, "server accepted the credentials")
	}
	conn.Status.ObservedGeneration = gen
	if perr := r.Status().Patch(ctx, &conn, ctrlclient.MergeFrom(orig)); perr != nil && !apierrors.IsNotFound(perr) {
		return ctrl.Result{}, perr
	}
	if checkErr != nil {
		return ctrl.Result{}, checkErr
	}
	resync := r.ResyncPeriod
	if resync <= 0 {
		resync = DefaultResyncPeriod
	}
	return ctrl.Result{RequeueAfter: resync}, nil
}

// SetupWithManager registers the reconciler.
func (r *ConnectionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("tenariumconnection").
		For(&tenariumv1.TenariumConnection{}, builder.WithPredicates(specChanged())).
		WithOptions(controller.Options{RateLimiter: NewRateLimiter(r.MaxBackoff)}).
		Complete(r)
}
