package tenant

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// Scheduled actions.
const (
	ScheduleSuspend = "suspend"
	ScheduleResume  = "resume"
	ScheduleSetPlan = "set_plan"
	ScheduleDelete  = "delete"
)

// Scheduled action event types. Executed actions emit the usual tenant
// events (tenant.suspended, tenant.plan_changed, ...).
const (
	EventActionScheduled = "tenant.action_scheduled"
	EventActionCanceled  = "tenant.action_canceled"
	EventActionFailed    = "tenant.action_failed"
)

// PendingDeletionReason is the status reason of tenants suspended while
// their deletion grace period runs.
const PendingDeletionReason = "pending deletion"

// staleClaim is how long a claimed action may run before another runner
// assumes its runner died and executes it again.
const staleClaim = 5 * time.Minute

// ScheduleInput describes an action to run later. Exactly one of At and
// After is required.
type ScheduleInput struct {
	Action string     `json:"action"`
	At     *time.Time `json:"at,omitempty"`
	// After is relative to now: a Go duration ("36h") or days ("14d").
	After  string `json:"after,omitempty"`
	Plan   string `json:"plan,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func parseAfter(s string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		return time.Duration(n) * 24 * time.Hour, err
	}
	return time.ParseDuration(s)
}

func (s *Service) newScheduled(ctx context.Context, tenantID string, in ScheduleInput) (store.ScheduledAction, error) {
	now := s.now()
	a := store.ScheduledAction{
		ID: uuid.Must(uuid.NewV7()).String(), TenantID: tenantID, Action: in.Action,
		Reason: in.Reason, Status: store.SchedulePending, CreatedBy: actor(ctx), CreatedAt: now,
	}
	switch in.Action {
	case ScheduleSuspend, ScheduleResume, ScheduleDelete:
		if in.Plan != "" {
			return a, invalid("plan", "only allowed for set_plan")
		}
	case ScheduleSetPlan:
		if in.Plan == "" {
			return a, invalid("plan", "required for set_plan")
		}
		if err := s.checkPlan(ctx, in.Plan); err != nil {
			return a, err
		}
		a.Plan = in.Plan
	default:
		return a, invalid("action", "must be one of suspend, resume, set_plan, delete")
	}
	switch {
	case in.At != nil && in.After != "":
		return a, invalid("at", "give either at or after")
	case in.At != nil:
		a.RunAt = in.At.UTC()
	case in.After != "":
		d, err := parseAfter(in.After)
		if err != nil || d < 0 {
			return a, invalid("after", "must be a duration such as 36h or 14d")
		}
		a.RunAt = now.Add(d)
	default:
		return a, invalid("at", "at or after is required")
	}
	if a.RunAt.Sub(now) > 10*365*24*time.Hour {
		return a, invalid("at", "too far in the future")
	}
	return a, nil
}

// Schedule adds an action to run against a live tenant later.
func (s *Service) Schedule(ctx context.Context, tenantRef string, in ScheduleInput) (store.ScheduledAction, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return store.ScheduledAction{}, err
	}
	if !t.IsLive() {
		return store.ScheduledAction{}, transitionErr("schedule actions for", t.Status)
	}
	a, err := s.newScheduled(ctx, t.ID, in)
	if err != nil {
		return store.ScheduledAction{}, err
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error { return s.createScheduled(ctx, tx, a) })
	if err != nil {
		return store.ScheduledAction{}, err
	}
	s.notify()
	return a, nil
}

func (s *Service) createScheduled(ctx context.Context, tx store.Tx, a store.ScheduledAction) error {
	if err := tx.CreateScheduledAction(ctx, a); err != nil {
		return err
	}
	return s.appendEvent(ctx, tx, EventActionScheduled, a.TenantID, scheduleSubject(a), a)
}

func scheduleSubject(a store.ScheduledAction) string {
	return "tenants/" + a.TenantID + "/schedule/" + a.ID
}

func (s *Service) ListSchedule(ctx context.Context, tenantRef string) ([]store.ScheduledAction, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return nil, err
	}
	return s.store.ListScheduledActions(ctx, t.ID)
}

// GetScheduled returns an action of the tenant.
func (s *Service) GetScheduled(ctx context.Context, tenantRef, id string) (store.ScheduledAction, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return store.ScheduledAction{}, err
	}
	a, err := s.store.GetScheduledAction(ctx, id)
	if err != nil || a.TenantID != t.ID {
		return store.ScheduledAction{}, store.ErrNotFound
	}
	return a, nil
}

// CancelScheduled cancels a pending action.
func (s *Service) CancelScheduled(ctx context.Context, tenantRef, id string) (store.ScheduledAction, error) {
	a, err := s.GetScheduled(ctx, tenantRef, id)
	if err != nil {
		return a, err
	}
	if err := s.cancelScheduled(ctx, &a); err != nil {
		return a, err
	}
	s.notify()
	return a, nil
}

func (s *Service) cancelScheduled(ctx context.Context, a *store.ScheduledAction) error {
	now := s.now()
	return s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.FinishScheduledAction(ctx, a.ID, store.ScheduleCanceled, "", now); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return stateErr("action is already %s", a.Status)
			}
			return err
		}
		a.Status, a.DoneAt = store.ScheduleCanceled, &now
		return s.appendEvent(ctx, tx, EventActionCanceled, a.TenantID, scheduleSubject(*a), a)
	})
}

// RequestDeletion deletes a tenant, or, with a deletion grace period
// configured and force unset, suspends it and schedules its deletion so it
// can be restored until then. It returns the scheduled deletion, if any.
func (s *Service) RequestDeletion(ctx context.Context, tenantRef string, force bool) (sdk.Tenant, *store.ScheduledAction, error) {
	if s.deletionGrace <= 0 || force {
		t, err := s.Delete(ctx, tenantRef)
		return t, nil, err
	}
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return t, nil, err
	}
	if !t.IsLive() {
		return t, nil, transitionErr("delete", t.Status)
	}
	if a, ok, err := s.pendingDeletion(ctx, t.ID); err != nil || ok {
		return t, &a, err
	}
	a, err := s.newScheduled(ctx, t.ID, ScheduleInput{Action: ScheduleDelete, After: s.deletionGrace.String()})
	if err != nil {
		return t, nil, err
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		if _, err := tx.GetTenant(ctx, t.ID); err != nil {
			return err
		}
		if n, err := tx.CountLiveChildren(ctx, t.ID); err != nil {
			return err
		} else if n > 0 {
			return stateErr("tenant has %d live child tenant(s); delete them first", n)
		}
		return s.createScheduled(ctx, tx, a)
	})
	if err != nil {
		return t, nil, err
	}
	if t.Status == sdk.StatusActive {
		t, err = s.suspend(ctx, t.ID, PendingDeletionReason)
		if err != nil {
			// A hook refused; the deletion must not run either.
			if cerr := s.cancelScheduled(ctx, &a); cerr != nil {
				return t, nil, errors.Join(err, cerr)
			}
			return t, nil, err
		}
	}
	s.notify()
	return t, &a, nil
}

func (s *Service) pendingDeletion(ctx context.Context, tenantID string) (store.ScheduledAction, bool, error) {
	all, err := s.store.ListScheduledActions(ctx, tenantID)
	if err != nil {
		return store.ScheduledAction{}, false, err
	}
	for _, a := range all {
		if a.Action == ScheduleDelete && (a.Status == store.SchedulePending || a.Status == store.ScheduleRunning) {
			return a, true, nil
		}
	}
	return store.ScheduledAction{}, false, nil
}

// Restore cancels a tenant's scheduled deletion and resumes it if it was
// suspended for the deletion.
func (s *Service) Restore(ctx context.Context, tenantRef string) (sdk.Tenant, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return t, err
	}
	a, ok, err := s.pendingDeletion(ctx, t.ID)
	if err != nil {
		return t, err
	}
	if !ok || !t.IsLive() {
		return t, stateErr("tenant is not pending deletion")
	}
	if err := s.cancelScheduled(ctx, &a); err != nil {
		return t, err
	}
	s.notify()
	if t.Status == sdk.StatusSuspended && t.StatusReason == PendingDeletionReason {
		return s.resume(ctx, t.ID, true)
	}
	return s.Get(ctx, t.ID)
}

// RunScheduled executes up to limit due actions and returns how many ran.
// Several instances may call it concurrently: each action is claimed once.
func (s *Service) RunScheduled(ctx context.Context, limit int) (int, error) {
	now := s.now()
	due, err := s.store.DueScheduledActions(ctx, now, now.Add(-staleClaim), limit)
	if err != nil {
		return 0, err
	}
	ran := 0
	ctx = sdk.WithPrincipal(ctx, &sdk.Principal{Subject: "scheduler", Kind: "service", Authenticator: "system"})
	for _, a := range due {
		err := s.store.InTx(ctx, func(tx store.Tx) error {
			return tx.ClaimScheduledAction(ctx, a.ID, now, now.Add(-staleClaim))
		})
		if errors.Is(err, store.ErrConflict) {
			continue // another instance got it
		} else if err != nil {
			return ran, err
		}
		status, msg := store.ScheduleDone, ""
		switch execErr := s.execute(ctx, a); {
		case execErr == nil:
		case errors.Is(execErr, errTenantGone):
			status, msg = store.ScheduleCanceled, execErr.Error()
		case permanent(execErr):
			status, msg = store.ScheduleFailed, execErr.Error()
		default:
			// Left claimed; retried once the claim goes stale.
			s.userOpts.Log.Warn("scheduled action failed; will retry",
				"id", a.ID, "action", a.Action, "tenant", a.TenantID, "err", execErr)
			continue
		}
		done := s.now()
		err = s.store.InTx(ctx, func(tx store.Tx) error {
			if err := tx.FinishScheduledAction(ctx, a.ID, status, msg, done); err != nil {
				return err
			}
			if status != store.ScheduleFailed {
				return nil
			}
			a.Status, a.Error, a.DoneAt = status, msg, &done
			return s.appendEvent(ctx, tx, EventActionFailed, a.TenantID, scheduleSubject(a), a)
		})
		if err != nil {
			return ran, err
		}
		ran++
	}
	if ran > 0 {
		s.notify()
	}
	return ran, nil
}

var errTenantGone = errors.New("tenant is deleted")

func (s *Service) execute(ctx context.Context, a store.ScheduledAction) error {
	t, err := s.store.GetTenant(ctx, a.TenantID)
	if err != nil {
		return err
	}
	if !t.IsLive() {
		return errTenantGone
	}
	switch a.Action {
	case ScheduleSuspend:
		if t.Status == sdk.StatusSuspended {
			return nil
		}
		reason := a.Reason
		if reason == "" {
			reason = "scheduled"
		}
		_, err = s.Suspend(ctx, t.ID, reason)
	case ScheduleResume:
		if t.Status == sdk.StatusActive {
			return nil
		}
		_, err = s.Resume(ctx, t.ID)
	case ScheduleSetPlan:
		if t.Plan == a.Plan {
			return nil
		}
		_, err = s.SetPlan(ctx, t.ID, a.Plan)
	case ScheduleDelete:
		_, err = s.Delete(ctx, t.ID)
	default:
		err = invalid("action", "unknown action %q", a.Action)
	}
	return err
}

// permanent reports whether retrying err cannot help (domain errors as
// opposed to e.g. a database outage).
func permanent(err error) bool {
	var (
		ve *ValidationError
		qe *QuotaError
	)
	_, rejected := sdk.IsReject(err)
	return rejected || errors.As(err, &ve) || errors.As(err, &qe) ||
		errors.Is(err, ErrInvalidTransition) || errors.Is(err, store.ErrNotFound) ||
		errors.Is(err, sdk.ErrForbidden)
}

// RunScheduler executes due actions and closes ended usage periods every
// interval until ctx ends.
func (s *Service) RunScheduler(ctx context.Context, interval time.Duration, log *slog.Logger) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		for {
			n, err := s.RunScheduled(ctx, 100)
			if err != nil && ctx.Err() == nil {
				log.Error("scheduler run failed", "err", err)
			}
			if n < 100 || err != nil {
				break
			}
		}
		if s.purgeAfter > 0 && time.Since(s.lastPurge) > time.Hour {
			s.lastPurge = time.Now()
			if n, err := s.PurgeDeletedTenants(ctx, s.purgeAfter); err != nil && ctx.Err() == nil {
				log.Error("purging deleted tenants failed", "err", err)
			} else if n > 0 {
				log.Info("purged deleted tenants", "count", n)
			}
		}
		if _, err := s.CloseEndedPeriods(ctx, 500); err != nil && ctx.Err() == nil {
			log.Error("closing usage periods failed", "err", err)
		}
		if _, err := s.PurgeExpiredGrants(ctx); err != nil && ctx.Err() == nil {
			log.Error("purging expired usage grants failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
