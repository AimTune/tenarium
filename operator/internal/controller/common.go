// Package controller contains the reconcilers of the Tenarium operator.
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/AimTune/tenarium/pkg/client"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

// Defaults for the reconcilers' timing.
const (
	// DefaultResyncPeriod is how often a synced object is compared with
	// Tenarium to detect and repair drift.
	DefaultResyncPeriod = 5 * time.Minute
)

// waitRequeue is used while waiting on something outside the operator's
// control (a parent tenant, provisioning, a blocked deletion). Tests
// shorten it.
var waitRequeue = 10 * time.Second

// Condition reasons.
const (
	ReasonSynced           = "Synced"
	ReasonConnectionError  = "ConnectionError"
	ReasonAPIError         = "APIError"
	ReasonAlreadyExists    = "AlreadyExists"
	ReasonOwnedByOther     = "OwnedByOtherResource"
	ReasonWaitingForParent = "WaitingForParent"
	ReasonParentMismatch   = "ParentMismatch"
	ReasonDeleteBlocked    = "DeleteBlocked"
	ReasonDeleting         = "Deleting"
	ReasonActive           = "Active"
	ReasonProvisioning     = "Provisioning"
	ReasonProvisioningFail = "ProvisioningFailed"
	ReasonSuspended        = "Suspended"
	ReasonNotFound         = "NotFound"
	ReasonAvailable        = "Available"
	ReasonVersionConflict  = "VersionConflict"
	ReasonInvalidSpec      = "InvalidSpec"
)

// Event reasons.
const (
	EventCreated       = "Created"
	EventAdopted       = "Adopted"
	EventUpdated       = "Updated"
	EventDeleted       = "Deleted"
	EventOrphaned      = "Orphaned"
	EventDriftRepaired = "DriftRepaired"
	EventRemoteMissing = "RemoteMissing"
	EventScheduled     = "Scheduled"
	EventUnscheduled   = "Unscheduled"
	EventSyncFailed    = "SyncFailed"
	EventAlreadyExists = "AlreadyExists"
	EventDeleteBlocked = "DeleteBlocked"
	EventConnection    = "ConnectionFailed"
	EventMoved         = "Moved"
)

// NewRateLimiter returns the per-object backoff used after failed
// reconciliations: exponential from 1s to max.
func NewRateLimiter(maxDelay time.Duration) workqueue.TypedRateLimiter[reconcile.Request] {
	if maxDelay <= 0 {
		maxDelay = 5 * time.Minute
	}
	return workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](time.Second, maxDelay)
}

func setCondition(conds *[]metav1.Condition, generation int64, typ string, ok bool, reason, msg string) {
	status := metav1.ConditionFalse
	if ok {
		status = metav1.ConditionTrue
	}
	meta.SetStatusCondition(conds, metav1.Condition{
		Type: typ, Status: status, Reason: reason, Message: truncate(msg, 1024), ObservedGeneration: generation,
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// idempotencyKey derives a stable Idempotency-Key from the object's UID,
// generation and a purpose, so a retried create (e.g. after a timeout or an
// operator restart) is replayed by the server instead of failing or
// creating a duplicate.
func idempotencyKey(uid types.UID, generation int64, purpose string) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s/%d/%s", uid, generation, purpose))
	return "tenarium-operator-" + hex.EncodeToString(sum[:16])
}

// apiReason maps an API error to a short condition reason.
func apiReason(err error) string {
	if e, ok := client.AsError(err); ok && e.Code != "" {
		return ReasonAPIError
	}
	return ReasonConnectionError
}

func adoptRequested(obj metav1.Object) bool {
	return obj.GetAnnotations()[tenariumv1.AnnotationAdopt] == "true"
}

// specChanged passes create and delete events, and updates that change the
// generation (spec), annotations, labels, finalizers or the deletion
// timestamp. Status-only updates, including the reconciler's own, are
// filtered out; drift is caught by the periodic resync instead.
func specChanged() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			o, n := e.ObjectOld, e.ObjectNew
			if o == nil || n == nil {
				return true
			}
			return o.GetGeneration() != n.GetGeneration() ||
				!maps.Equal(o.GetAnnotations(), n.GetAnnotations()) ||
				!maps.Equal(o.GetLabels(), n.GetLabels()) ||
				!reflect.DeepEqual(o.GetFinalizers(), n.GetFinalizers()) ||
				!reflect.DeepEqual(o.GetDeletionTimestamp(), n.GetDeletionTimestamp())
		},
	}
}

// Field index names.
const (
	indexConnection = "spec.connectionRef.name"
	indexParent     = "spec.parent.name"
)

func connectionRefName(ref *tenariumv1.ConnectionReference) []string {
	if ref == nil {
		return nil
	}
	return []string{ref.Name}
}

// errWait signals that the reconciler should requeue after waitRequeue
// without counting it as a failure.
var errWait = errors.New("waiting")

// deletePlatformObject deletes a remote object identified by kind and id
// (a rollout or template) for a resource being finalized, recording the
// outcome in conds. It reports requeue when the server refuses the delete
// for now (a conflict).
func deletePlatformObject(ctx context.Context, conns *Connections, rec Recorder, obj ctrlclient.Object, conds *[]metav1.Condition,
	ref *tenariumv1.ConnectionReference, kind, id string, del func(*client.Client) error) (bool, error) {
	gen := obj.GetGeneration()
	c, err := conns.For(ctx, obj.GetNamespace(), ref)
	if err != nil {
		setCondition(conds, gen, tenariumv1.ConditionSynced, false, ReasonConnectionError, err.Error())
		return false, err
	}
	err = del(c)
	switch {
	case err == nil || client.IsNotFound(err):
		rec.Eventf(obj, nil, corev1.EventTypeNormal, EventDeleted, "Delete", "deleted %s %s", kind, id)
		return false, nil
	case client.IsConflict(err):
		msg := err.Error()
		if e, ok := client.AsError(err); ok {
			msg = e.Message
		}
		setCondition(conds, gen, tenariumv1.ConditionSynced, false, ReasonDeleteBlocked, msg)
		rec.Eventf(obj, nil, corev1.EventTypeWarning, EventDeleteBlocked, "Delete", "cannot delete %s %s yet: %s", kind, id, msg)
		return true, nil
	default:
		setCondition(conds, gen, tenariumv1.ConditionSynced, false, apiReason(err), err.Error())
		return false, err
	}
}
