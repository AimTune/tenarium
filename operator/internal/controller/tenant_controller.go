package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

// Recorder emits Kubernetes events (events.k8s.io/v1).
type Recorder interface {
	Eventf(regarding, related runtime.Object, eventtype, reason, action, note string, args ...any)
}

// TenantReconciler reconciles Tenant resources with Tenarium tenants.
type TenantReconciler struct {
	ctrlclient.Client
	Connections *Connections
	Recorder    Recorder
	// ResyncPeriod is how often a synced tenant is checked for drift.
	ResyncPeriod time.Duration
	// MaxBackoff caps the retry delay after API errors.
	MaxBackoff time.Duration
	// MaxConcurrentReconciles defaults to 1.
	MaxConcurrentReconciles int
}

// +kubebuilder:rbac:groups=tenarium.io,resources=tenants,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=tenarium.io,resources=tenants/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tenarium.io,resources=tenants/finalizers,verbs=update
// +kubebuilder:rbac:groups=tenarium.io,resources=tenariumconnections,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile brings one Tenarium tenant in line with a Tenant resource.
func (r *TenantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var t tenariumv1.Tenant
	if err := r.Get(ctx, req.NamespacedName, &t); err != nil {
		return ctrl.Result{}, ctrlclient.IgnoreNotFound(err)
	}
	if !t.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &t)
	}
	if !controllerutil.ContainsFinalizer(&t, tenariumv1.Finalizer) {
		controllerutil.AddFinalizer(&t, tenariumv1.Finalizer)
		if err := r.Update(ctx, &t); err != nil {
			return ctrl.Result{}, err
		}
	}

	orig := t.DeepCopy()
	res, err := r.sync(ctx, &t)
	t.Status.ObservedGeneration = t.Generation
	now := metav1.Now()
	t.Status.LastSyncTime = &now
	if perr := r.Status().Patch(ctx, &t, ctrlclient.MergeFrom(orig)); perr != nil {
		if apierrors.IsNotFound(perr) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Join(err, perr)
	}
	if err != nil {
		if errors.Is(err, errWait) {
			return ctrl.Result{RequeueAfter: waitRequeue}, nil
		}
		return ctrl.Result{}, err
	}
	return res, nil
}

// sync does the work of Reconcile and records the outcome in t.Status.
// Errors are retried with backoff; errWait requeues after waitRequeue.
func (r *TenantReconciler) sync(ctx context.Context, t *tenariumv1.Tenant) (ctrl.Result, error) {
	gen := t.Generation
	fail := func(reason string, err error) (ctrl.Result, error) {
		setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionSynced, false, reason, err.Error())
		if !meta.IsStatusConditionPresentAndEqual(t.Status.Conditions, tenariumv1.ConditionReady, metav1.ConditionTrue) {
			setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionReady, false, reason, err.Error())
		}
		r.Recorder.Eventf(t, nil, corev1.EventTypeWarning, EventSyncFailed, "Sync", "%s", truncate(err.Error(), 512))
		return ctrl.Result{}, err
	}

	c, err := r.Connections.For(ctx, t.Namespace, t.Spec.ConnectionRef)
	if err != nil {
		return fail(ReasonConnectionError, err)
	}

	// Resolve the parent first: a child cannot be created before it.
	parentID, err := r.resolveParent(ctx, c, t)
	if err != nil {
		if errors.Is(err, errWait) {
			setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionReady, false, ReasonWaitingForParent, strings.TrimPrefix(err.Error(), "waiting: "))
			setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionSynced, false, ReasonWaitingForParent, strings.TrimPrefix(err.Error(), "waiting: "))
			return ctrl.Result{}, err
		}
		return fail(apiReason(err), err)
	}
	t.Status.ParentID = parentID

	prevID := t.Status.ID // a tenant deleted outside Kubernetes is recreated under a new key
	remote, found, err := r.findRemote(ctx, c, t)
	if err != nil {
		if errors.Is(err, errOwnership) {
			msg := strings.TrimPrefix(err.Error(), errOwnership.Error()+": ")
			reason := ReasonAlreadyExists
			if strings.Contains(msg, "managed by") {
				reason = ReasonOwnedByOther
			}
			setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionSynced, false, reason, msg)
			setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionReady, false, reason, msg)
			r.Recorder.Eventf(t, nil, corev1.EventTypeWarning, EventAlreadyExists, "Adopt", "%s", msg)
			// Not an error: retrying will not help until someone adds the
			// adopt annotation (which triggers a reconcile) or deletes the
			// remote tenant (caught by the resync).
			return ctrl.Result{RequeueAfter: r.resync()}, nil
		}
		return fail(apiReason(err), err)
	}

	if !found {
		remote, err = r.create(ctx, c, t, parentID, prevID)
		if err != nil {
			return fail(apiReason(err), err)
		}
	}
	// Also right after a create: some fields (billing anchor, plan revision)
	// can only be set by an update.
	remote, err = r.update(ctx, c, t, remote)
	if err == nil {
		remote, err = r.setPlanRevision(ctx, c, t, remote)
	}
	if err == nil {
		remote, err = r.move(ctx, c, t, remote)
	}
	if err != nil {
		if client.IsVersionConflict(err) {
			// Someone else changed the tenant: re-read and try again.
			setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionSynced, false, ReasonVersionConflict, err.Error())
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		return fail(apiReason(err), err)
	}
	t.Status.ID = remote.ID
	t.Status.Version = remote.Version
	t.Status.Phase = string(remote.Status)
	t.Status.StatusReason = remote.StatusReason
	t.Status.PlanRevision = remote.PlanRevision
	t.Status.Region = remote.Region
	t.Status.BrandingManaged = t.Spec.Branding != nil
	t.Status.BillingAnchorManaged = t.Spec.BillingAnchor != nil
	t.Status.Maintenance = maintenanceStatus(remote, time.Now())
	if remote.IsLive() {
		r.refreshHealth(ctx, c, t)
	} else {
		t.Status.Health = nil
	}

	if err := r.syncSchedule(ctx, c, t); err != nil {
		return fail(apiReason(err), err)
	}

	if remote.IsLive() {
		ent, err := c.Tenants.Entitlements(ctx, remote.ID)
		if err != nil {
			return fail(apiReason(err), err)
		}
		t.Status.Entitlements = summarize(ent)
	}

	synced, syncMsg := true, "tenant matches the spec"
	if parentID != "" && remote.ParentID != parentID {
		synced, syncMsg = false, fmt.Sprintf("tenant has parent %q, spec wants %q; the parent cannot change", remote.ParentID, parentID)
		r.Recorder.Eventf(t, nil, corev1.EventTypeWarning, ReasonParentMismatch, "Sync", "%s", syncMsg)
	}
	if synced {
		setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionSynced, true, ReasonSynced, syncMsg)
	} else {
		setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionSynced, false, ReasonParentMismatch, syncMsg)
	}

	requeue := r.resync()
	switch remote.Status {
	case sdk.StatusActive:
		setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionReady, true, ReasonActive, "tenant is active")
	case sdk.StatusProvisioning:
		setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionReady, false, ReasonProvisioning, "tenant is being provisioned")
		requeue = 5 * time.Second
	case sdk.StatusFailed:
		setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionReady, false, ReasonProvisioningFail, remote.StatusReason)
	case sdk.StatusSuspended:
		setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionReady, false, ReasonSuspended, remote.StatusReason)
	default:
		setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionReady, false, ReasonDeleting, "tenant is being deleted in Tenarium")
		requeue = waitRequeue
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func (r *TenantReconciler) resync() time.Duration {
	if r.ResyncPeriod > 0 {
		return r.ResyncPeriod
	}
	return DefaultResyncPeriod
}

// resolveParent returns the Tenarium ID of the parent tenant, "" for a root
// tenant, or errWait while a parent Tenant resource is not ready.
func (r *TenantReconciler) resolveParent(ctx context.Context, c *client.Client, t *tenariumv1.Tenant) (string, error) {
	p := t.Spec.Parent
	switch {
	case p == nil:
		return "", nil
	case p.Name != "":
		var parent tenariumv1.Tenant
		if err := r.Get(ctx, types.NamespacedName{Namespace: t.Namespace, Name: p.Name}, &parent); err != nil {
			if apierrors.IsNotFound(err) {
				return "", fmt.Errorf("%w: parent Tenant %q not found", errWait, p.Name)
			}
			return "", err
		}
		if parent.Status.ID == "" || !meta.IsStatusConditionTrue(parent.Status.Conditions, tenariumv1.ConditionReady) {
			return "", fmt.Errorf("%w: parent Tenant %q is not ready", errWait, p.Name)
		}
		return parent.Status.ID, nil
	default:
		pt, err := c.Tenants.Get(ctx, p.Slug)
		if err != nil {
			if client.IsNotFound(err) {
				return "", fmt.Errorf("%w: parent tenant %q not found in Tenarium", errWait, p.Slug)
			}
			return "", err
		}
		return pt.ID, nil
	}
}

var errOwnership = errors.New("ownership")

// findRemote returns the Tenarium tenant for t, if any. A tenant found by
// slug is only claimed when the operator created it (owner label) or the
// resource asks for adoption.
func (r *TenantReconciler) findRemote(ctx context.Context, c *client.Client, t *tenariumv1.Tenant) (sdk.Tenant, bool, error) {
	if t.Status.ID != "" {
		remote, err := c.Tenants.Get(ctx, t.Status.ID)
		switch {
		case err == nil && remote.Status != sdk.StatusDeleted:
			return remote, true, nil
		case err == nil || client.IsNotFound(err):
			r.Recorder.Eventf(t, nil, corev1.EventTypeWarning, EventRemoteMissing, "Sync",
				"tenant %s was deleted outside Kubernetes; recreating it", t.Status.ID)
			t.Status.ID, t.Status.Version, t.Status.Adopted = "", 0, false
			t.Status.ScheduledActions = nil
			t.Status.Entitlements = nil
			t.Status.Health, t.Status.Maintenance = nil, nil
		default:
			return sdk.Tenant{}, false, err
		}
	}

	remote, err := c.Tenants.Get(ctx, t.Spec.Slug)
	if err != nil {
		if client.IsNotFound(err) {
			return sdk.Tenant{}, false, nil
		}
		return sdk.Tenant{}, false, err
	}
	if remote.Status == sdk.StatusDeleted {
		return sdk.Tenant{}, false, nil
	}
	owner := remote.Labels[tenariumv1.OwnerLabel]
	switch {
	case owner == string(t.UID):
		// Created by this resource; the status update was lost.
		return remote, true, nil
	case owner != "":
		return sdk.Tenant{}, false, fmt.Errorf("%w: tenant %q is managed by another Tenant resource (uid %s)", errOwnership, t.Spec.Slug, owner)
	case adoptRequested(t):
		t.Status.Adopted = true
		r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, EventAdopted, "Adopt", "adopted existing tenant %s (%s)", remote.Slug, remote.ID)
		return remote, true, nil
	default:
		return sdk.Tenant{}, false, fmt.Errorf("%w: tenant %q already exists in Tenarium; annotate the resource with %s=true to adopt it",
			errOwnership, t.Spec.Slug, tenariumv1.AnnotationAdopt)
	}
}

func (r *TenantReconciler) create(ctx context.Context, c *client.Client, t *tenariumv1.Tenant, parentID, prevID string) (sdk.Tenant, error) {
	settings, err := desiredSettings(t)
	if err != nil {
		return sdk.Tenant{}, err
	}
	req := client.CreateTenantRequest{
		Slug:     t.Spec.Slug,
		Name:     tenantName(t),
		ParentID: parentID,
		Plan:     t.Spec.Plan,
		Labels:   desiredLabels(t, nil),
		Settings: settings,
		Features: t.Spec.Features,
		Limits:   t.Spec.Limits,
		AddOns:   t.Spec.AddOns,
		Region:   t.Spec.Region,
		Template: t.Spec.Template,
	}
	if b := toSDKBranding(t.Spec.Branding); b != nil && *b != (sdk.Branding{}) {
		req.Branding = b
	}
	remote, err := c.Tenants.Create(ctx, req, client.WithIdempotencyKey(idempotencyKey(t.UID, t.Generation, "create-tenant/"+prevID)))
	if err != nil {
		return sdk.Tenant{}, err
	}
	r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, EventCreated, "Create", "created tenant %s (%s)", remote.Slug, remote.ID)
	return remote, nil
}

// update sends the fields that differ between the spec and the remote
// tenant, conditional on the remote version.
func (r *TenantReconciler) update(ctx context.Context, c *client.Client, t *tenariumv1.Tenant, remote sdk.Tenant) (sdk.Tenant, error) {
	var req client.UpdateTenantRequest
	var changed []string
	if name := tenantName(t); name != remote.Name {
		req.Name = &name
		changed = append(changed, "name")
	}
	if t.Spec.Plan != "" && t.Spec.Plan != remote.Plan {
		req.Plan = &t.Spec.Plan
		changed = append(changed, "plan")
	}
	if labels := desiredLabels(t, remote.Labels); !maps.Equal(labels, remote.Labels) {
		req.Labels = &labels
		changed = append(changed, "labels")
	}
	if t.Spec.Features != nil && !maps.Equal(t.Spec.Features, remote.Features) {
		f := t.Spec.Features
		req.Features = &f
		changed = append(changed, "features")
	}
	if t.Spec.Limits != nil && !maps.Equal(t.Spec.Limits, remote.Limits) {
		l := t.Spec.Limits
		req.Limits = &l
		changed = append(changed, "limits")
	}
	if t.Spec.AddOns != nil && !slices.Equal(t.Spec.AddOns, remote.AddOns) {
		a := slices.Clone(t.Spec.AddOns)
		req.AddOns = &a
		changed = append(changed, "add-ons")
	}
	if a := t.Spec.BillingAnchor; a != nil && !sameTime(a.Time, remote.BillingAnchor) {
		at := a.UTC()
		req.BillingAnchor = &at
		changed = append(changed, "billing anchor")
	} else if a == nil && t.Status.BillingAnchorManaged && remote.BillingAnchor != nil {
		req.ClearBillingAnchor = true
		changed = append(changed, "billing anchor")
	}
	if b := brandingUpdate(t, remote.Branding); b != nil {
		req.Branding = b
		changed = append(changed, "branding")
	}
	if t.Spec.Settings != nil {
		want, err := desiredSettings(t)
		if err != nil {
			return remote, err
		}
		if patch := mergePatch(remote.Settings, want); len(patch) > 0 {
			req.Settings = patch
			changed = append(changed, "settings")
		}
	}
	if len(changed) == 0 {
		return remote, nil
	}
	updated, err := c.Tenants.Update(ctx, remote.ID, req, client.IfMatch(remote.Version))
	if err != nil {
		return remote, err
	}
	reason, verb := EventUpdated, "updated"
	if t.Status.ObservedGeneration == t.Generation && t.Status.ID != "" {
		// The spec did not change since the last sync: the remote drifted.
		reason, verb = EventDriftRepaired, "repaired drift in"
	}
	r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, reason, "Update", "%s %s of tenant %s", verb, strings.Join(changed, ", "), remote.Slug)
	return updated, nil
}

func tenantName(t *tenariumv1.Tenant) string {
	if t.Spec.Name != "" {
		return t.Spec.Name
	}
	return t.Spec.Slug
}

// desiredLabels returns the spec's labels plus the owner label. Without
// spec.labels the remote labels are kept.
func desiredLabels(t *tenariumv1.Tenant, remote map[string]string) map[string]string {
	src := t.Spec.Labels
	if src == nil {
		src = remote
	}
	out := maps.Clone(src)
	if out == nil {
		out = map[string]string{}
	}
	out[tenariumv1.OwnerLabel] = string(t.UID)
	return out
}

func desiredSettings(t *tenariumv1.Tenant) (map[string]any, error) {
	return rawObject(t.Spec.Settings, "spec.settings")
}

// rawObject decodes a free-form JSON object field; nil when it is unset.
func rawObject(raw *runtime.RawExtension, field string) (map[string]any, error) {
	if raw == nil || len(raw.Raw) == 0 {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw.Raw, &m); err != nil {
		return nil, fmt.Errorf("%s must be a JSON object: %w", field, err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// mergePatch returns the RFC 7386 merge patch that turns from into to, or
// nil when they are equal.
func mergePatch(from, to map[string]any) map[string]any {
	patch := map[string]any{}
	for k := range from {
		if _, ok := to[k]; !ok {
			patch[k] = nil
		}
	}
	for k, tv := range to {
		fv, ok := from[k]
		if ok && reflect.DeepEqual(fv, tv) {
			continue
		}
		fm, fok := fv.(map[string]any)
		tm, tok := tv.(map[string]any)
		if ok && fok && tok {
			if sub := mergePatch(fm, tm); len(sub) > 0 {
				patch[k] = sub
			}
			continue
		}
		patch[k] = tv
	}
	if len(patch) == 0 {
		return nil
	}
	return patch
}

func summarize(e sdk.Entitlements) *tenariumv1.EntitlementsSummary {
	s := &tenariumv1.EntitlementsSummary{Plan: e.Plan}
	for f, on := range e.Features {
		if on {
			s.EnabledFeatures = append(s.EnabledFeatures, f)
		}
	}
	sort.Strings(s.EnabledFeatures)
	if len(e.Limits) > 0 {
		s.Limits = maps.Clone(e.Limits)
	}
	return s
}

// --- scheduled actions -------------------------------------------------------

type scheduleInput struct {
	Action string     `json:"action"`
	At     *time.Time `json:"at,omitempty"`
	After  string     `json:"after,omitempty"`
	Plan   string     `json:"plan,omitempty"`
	Reason string     `json:"reason,omitempty"`
}

type scheduledAction struct {
	ID     string     `json:"id"`
	Action string     `json:"action"`
	RunAt  *time.Time `json:"run_at,omitempty"`
	Status string     `json:"status"`
	Error  string     `json:"error,omitempty"`
}

func scheduleKey(a tenariumv1.ScheduledAction) string {
	in := toScheduleInput(a)
	raw, _ := json.Marshal(in)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

func toScheduleInput(a tenariumv1.ScheduledAction) scheduleInput {
	in := scheduleInput{Action: a.Action, After: a.After, Plan: a.Plan, Reason: a.Reason}
	if a.At != nil {
		at := a.At.UTC()
		in.At = &at
	}
	return in
}

// syncSchedule schedules each spec.schedule entry once, cancels pending
// actions whose entry was removed, and refreshes their states.
func (r *TenantReconciler) syncSchedule(ctx context.Context, c *client.Client, t *tenariumv1.Tenant) error {
	if len(t.Spec.Schedule) == 0 && len(t.Status.ScheduledActions) == 0 {
		return nil
	}
	base := "/v1/tenants/" + t.Status.ID + "/schedule"
	wanted := map[string]tenariumv1.ScheduledAction{}
	var order []string
	for _, a := range t.Spec.Schedule {
		k := scheduleKey(a)
		if _, dup := wanted[k]; !dup {
			order = append(order, k)
		}
		wanted[k] = a
	}

	// Cancel actions whose spec entry is gone.
	var kept []tenariumv1.ScheduledActionStatus
	for _, s := range t.Status.ScheduledActions {
		if _, ok := wanted[s.Key]; ok {
			kept = append(kept, s)
			continue
		}
		if s.State == "pending" || s.State == "" {
			var out scheduledAction
			err := c.Do(ctx, http.MethodDelete, base+"/"+s.ID, nil, nil, &out)
			if err != nil && !client.IsNotFound(err) && !client.IsConflict(err) {
				return fmt.Errorf("cancel scheduled %s: %w", s.Action, err)
			}
			r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, EventUnscheduled, "Unschedule", "canceled scheduled %s (%s)", s.Action, s.ID)
		}
	}
	t.Status.ScheduledActions = kept

	// Schedule new entries.
	have := map[string]bool{}
	for _, s := range kept {
		have[s.Key] = true
	}
	for _, k := range order {
		if have[k] {
			continue
		}
		a := wanted[k]
		var out scheduledAction
		err := c.Do(ctx, http.MethodPost, base, nil, toScheduleInput(a), &out,
			client.WithIdempotencyKey(idempotencyKey(t.UID, 0, t.Status.ID+"/schedule/"+k)))
		if err != nil {
			return fmt.Errorf("schedule %s: %w", a.Action, err)
		}
		t.Status.ScheduledActions = append(t.Status.ScheduledActions, statusOf(k, out))
		r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, EventScheduled, "Schedule", "scheduled %s at %s", out.Action, fmtTime(out.RunAt))
	}

	// Refresh states.
	if len(t.Status.ScheduledActions) == 0 {
		t.Status.ScheduledActions = nil
		return nil
	}
	var list struct {
		Items []scheduledAction `json:"items"`
	}
	if err := c.Do(ctx, http.MethodGet, base, nil, nil, &list); err != nil {
		return fmt.Errorf("list scheduled actions: %w", err)
	}
	byID := map[string]scheduledAction{}
	for _, a := range list.Items {
		byID[a.ID] = a
	}
	for i, s := range t.Status.ScheduledActions {
		if a, ok := byID[s.ID]; ok {
			t.Status.ScheduledActions[i] = statusOf(s.Key, a)
		}
	}
	return nil
}

func statusOf(key string, a scheduledAction) tenariumv1.ScheduledActionStatus {
	s := tenariumv1.ScheduledActionStatus{Key: key, ID: a.ID, Action: a.Action, State: a.Status, Error: a.Error}
	if a.RunAt != nil {
		rt := metav1.NewTime(*a.RunAt)
		s.RunAt = &rt
	}
	return s
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "?"
	}
	return t.UTC().Format(time.RFC3339)
}

// --- deletion ----------------------------------------------------------------

func (r *TenantReconciler) finalize(ctx context.Context, t *tenariumv1.Tenant) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(t, tenariumv1.Finalizer) {
		return ctrl.Result{}, nil
	}
	orig := t.DeepCopy()
	if err := r.deleteRemote(ctx, t); err != nil {
		if perr := r.Status().Patch(ctx, t, ctrlclient.MergeFrom(orig)); perr != nil && !apierrors.IsNotFound(perr) {
			log.FromContext(ctx).Error(perr, "patch status")
		}
		if errors.Is(err, errWait) {
			return ctrl.Result{RequeueAfter: waitRequeue}, nil
		}
		return ctrl.Result{}, err
	}
	controllerutil.RemoveFinalizer(t, tenariumv1.Finalizer)
	return ctrl.Result{}, ctrlclient.IgnoreNotFound(r.Update(ctx, t))
}

func (r *TenantReconciler) deleteRemote(ctx context.Context, t *tenariumv1.Tenant) error {
	gen := t.Generation
	c, err := r.Connections.For(ctx, t.Namespace, t.Spec.ConnectionRef)
	if err != nil {
		setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionSynced, false, ReasonConnectionError, err.Error())
		r.Recorder.Eventf(t, nil, corev1.EventTypeWarning, EventConnection, "Delete", "%s", err.Error())
		return err
	}
	id := t.Status.ID
	if id == "" {
		// The tenant may have been created without its ID being recorded.
		remote, err := c.Tenants.Get(ctx, t.Spec.Slug)
		switch {
		case client.IsNotFound(err):
			return nil
		case err != nil:
			return err
		case remote.Labels[tenariumv1.OwnerLabel] != string(t.UID):
			return nil // not ours
		}
		id = remote.ID
	}

	if t.Spec.DeletionPolicy == tenariumv1.DeletionPolicyOrphan {
		// Drop the owner label so another resource can adopt the tenant.
		remote, err := c.Tenants.Get(ctx, id)
		if err == nil && remote.Labels[tenariumv1.OwnerLabel] == string(t.UID) {
			labels := maps.Clone(remote.Labels)
			delete(labels, tenariumv1.OwnerLabel)
			_, err = c.Tenants.Update(ctx, id, client.UpdateTenantRequest{Labels: &labels}, client.IfMatch(remote.Version))
		}
		if err != nil && !client.IsNotFound(err) {
			return err
		}
		r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, EventOrphaned, "Delete", "left tenant %s in Tenarium (deletionPolicy Orphan)", t.Spec.Slug)
		return nil
	}

	remote, err := c.Tenants.Delete(ctx, id)
	switch {
	case client.IsNotFound(err):
		return nil
	case client.IsConflict(err):
		// Typically: the tenant still has live children.
		msg := err.Error()
		if e, ok := client.AsError(err); ok {
			msg = e.Message
		}
		setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionSynced, false, ReasonDeleteBlocked, msg)
		r.Recorder.Eventf(t, nil, corev1.EventTypeWarning, EventDeleteBlocked, "Delete", "cannot delete tenant %s yet: %s", t.Spec.Slug, msg)
		return fmt.Errorf("%w: %s", errWait, msg)
	case err != nil:
		setCondition(&t.Status.Conditions, gen, tenariumv1.ConditionSynced, false, apiReason(err), err.Error())
		return err
	}
	r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, EventDeleted, "Delete", "deleted tenant %s (status %s)", t.Spec.Slug, remote.Status)
	return nil
}

// --- setup -------------------------------------------------------------------

// SetupWithManager registers the reconciler, its watches and field indexes.
func (r *TenantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()
	idx := mgr.GetFieldIndexer()
	if err := idx.IndexField(ctx, &tenariumv1.Tenant{}, indexParent, tenantParentName); err != nil {
		return err
	}
	if err := idx.IndexField(ctx, &tenariumv1.Tenant{}, indexConnection, func(o ctrlclient.Object) []string {
		return connectionRefName(o.(*tenariumv1.Tenant).Spec.ConnectionRef)
	}); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("tenant").
		For(&tenariumv1.Tenant{}, builder.WithPredicates(specChanged())).
		// Children wait for their parent: wake them when it becomes ready.
		Watches(&tenariumv1.Tenant{}, handler.EnqueueRequestsFromMapFunc(r.childrenOf),
			builder.WithPredicates(parentReadinessChanged())).
		Watches(&tenariumv1.TenariumConnection{}, handler.EnqueueRequestsFromMapFunc(r.usersOfConnection),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: max(r.MaxConcurrentReconciles, 1),
			RateLimiter:             NewRateLimiter(r.MaxBackoff),
		}).
		Complete(r)
}

func tenantParentName(o ctrlclient.Object) []string {
	if p := o.(*tenariumv1.Tenant).Spec.Parent; p != nil && p.Name != "" {
		return []string{p.Name}
	}
	return nil
}

func (r *TenantReconciler) childrenOf(ctx context.Context, o ctrlclient.Object) []reconcile.Request {
	var l tenariumv1.TenantList
	if err := r.List(ctx, &l, ctrlclient.InNamespace(o.GetNamespace()), ctrlclient.MatchingFields{indexParent: o.GetName()}); err != nil {
		log.FromContext(ctx).Error(err, "list child tenants")
		return nil
	}
	return requests(l.Items)
}

func (r *TenantReconciler) usersOfConnection(ctx context.Context, o ctrlclient.Object) []reconcile.Request {
	var l tenariumv1.TenantList
	if err := r.List(ctx, &l, ctrlclient.InNamespace(o.GetNamespace()), ctrlclient.MatchingFields{indexConnection: o.GetName()}); err != nil {
		log.FromContext(ctx).Error(err, "list tenants by connection")
		return nil
	}
	return requests(l.Items)
}

func requests[T any, P interface {
	*T
	ctrlclient.Object
}](items []T) []reconcile.Request {
	out := make([]reconcile.Request, 0, len(items))
	for i := range items {
		o := P(&items[i])
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: o.GetNamespace(), Name: o.GetName()}})
	}
	return out
}

// parentReadinessChanged passes Tenant updates that change the Ready
// condition or the Tenarium ID, which is what children wait for.
func parentReadinessChanged() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return false },
		DeleteFunc:  func(event.DeleteEvent) bool { return false },
		GenericFunc: func(event.GenericEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			o, ok1 := e.ObjectOld.(*tenariumv1.Tenant)
			n, ok2 := e.ObjectNew.(*tenariumv1.Tenant)
			if !ok1 || !ok2 {
				return false
			}
			return o.Status.ID != n.Status.ID ||
				meta.IsStatusConditionTrue(o.Status.Conditions, tenariumv1.ConditionReady) !=
					meta.IsStatusConditionTrue(n.Status.Conditions, tenariumv1.ConditionReady)
		},
	}
}
