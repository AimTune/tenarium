package tenant

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/pkg/sdk"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newScheduledService(t *testing.T, opts Options) (*Service, *memory.Store, *clock) {
	t.Helper()
	s := memory.New()
	if opts.Users == nil {
		opts.Users = &UserOptions{Log: discard}
	}
	svc := NewService(s, opts)
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc.now = c.now
	ctx := context.Background()
	for _, p := range []string{"trial", "free", "pro"} {
		if _, err := svc.CreatePlan(ctx, PlanInput{ID: p, Name: p}); err != nil {
			t.Fatal(err)
		}
	}
	return svc, s, c
}

func runDue(t *testing.T, svc *Service) int {
	t.Helper()
	n, err := svc.RunScheduled(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTrialEndsWithScheduledPlanChange(t *testing.T) {
	ctx := context.Background()
	svc, s, c := newScheduledService(t, Options{RequireKnownPlans: true})
	tn, err := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme", Plan: "trial", Schedule: []ScheduleInput{
		{Action: ScheduleSetPlan, After: "14d", Plan: "free"},
		{Action: ScheduleSuspend, After: "30d", Reason: "trial expired"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	list, _ := svc.ListSchedule(ctx, tn.ID)
	if len(list) != 2 || !list[0].RunAt.Equal(c.t.Add(14*24*time.Hour)) || list[0].CreatedBy != "system" {
		t.Fatalf("schedule: %+v", list)
	}
	if n := runDue(t, svc); n != 0 {
		t.Fatalf("ran %d actions early", n)
	}
	c.advance(14*24*time.Hour + time.Second)
	if n := runDue(t, svc); n != 1 {
		t.Fatalf("ran %d", n)
	}
	got, _ := svc.Get(ctx, tn.ID)
	if got.Plan != "free" {
		t.Fatalf("plan: %s", got.Plan)
	}
	c.advance(20 * 24 * time.Hour)
	runDue(t, svc)
	got, _ = svc.Get(ctx, tn.ID)
	if got.Status != sdk.StatusSuspended || got.StatusReason != "trial expired" {
		t.Fatalf("not suspended: %+v", got)
	}
	list, _ = svc.ListSchedule(ctx, tn.ID)
	for _, a := range list {
		if a.Status != store.ScheduleDone || a.DoneAt == nil {
			t.Fatalf("not done: %+v", a)
		}
	}
	evts := eventTypes(t, s)
	for _, want := range []string{EventActionScheduled, sdk.EventTenantPlanChanged, sdk.EventTenantSuspended} {
		if !slices.Contains(evts, want) {
			t.Fatalf("missing %s in %v", want, evts)
		}
	}
	e, _ := s.ReadEvents(ctx, 0, 0)
	for _, ev := range e {
		if ev.Type == sdk.EventTenantSuspended && ev.Actor != "system:scheduler" {
			t.Fatalf("actor: %s", ev.Actor)
		}
	}
}

func TestScheduleValidation(t *testing.T) {
	ctx := context.Background()
	svc, _, c := newScheduledService(t, Options{RequireKnownPlans: true})
	tn, _ := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme"})
	at := c.t.Add(time.Hour)
	bad := map[string]ScheduleInput{
		"action": {Action: "explode", At: &at},
		"at":     {Action: ScheduleSuspend},
		"after":  {Action: ScheduleSuspend, After: "soon"},
		"plan":   {Action: ScheduleSetPlan, At: &at, Plan: "gold"},
	}
	for field, in := range bad {
		var ve *ValidationError
		if _, err := svc.Schedule(ctx, tn.ID, in); !errors.As(err, &ve) || ve.Field != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	if _, err := svc.Schedule(ctx, tn.ID, ScheduleInput{Action: ScheduleSuspend, At: &at, After: "1h"}); err == nil {
		t.Error("at and after accepted together")
	}
	_, err := svc.Create(ctx, CreateInput{Slug: "x", Name: "X", Schedule: []ScheduleInput{{Action: "nope", At: &at}}})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "schedule[0].action" {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.Get(ctx, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("tenant created despite invalid schedule")
	}
}

func TestCancelScheduled(t *testing.T) {
	ctx := context.Background()
	svc, s, c := newScheduledService(t, Options{})
	tn, _ := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme"})
	a, err := svc.Schedule(ctx, tn.ID, ScheduleInput{Action: ScheduleSuspend, After: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := svc.Create(ctx, CreateInput{Slug: "other", Name: "Other"})
	if _, err := svc.CancelScheduled(ctx, other.ID, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant cancel: %v", err)
	}
	if a, err = svc.CancelScheduled(ctx, tn.ID, a.ID); err != nil || a.Status != store.ScheduleCanceled {
		t.Fatalf("cancel: %+v %v", a, err)
	}
	if _, err := svc.CancelScheduled(ctx, tn.ID, a.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("cancel twice: %v", err)
	}
	c.advance(2 * time.Hour)
	runDue(t, svc)
	if got, _ := svc.Get(ctx, tn.ID); got.Status != sdk.StatusActive {
		t.Fatalf("canceled action ran: %s", got.Status)
	}
	if !slices.Contains(eventTypes(t, s), EventActionCanceled) {
		t.Fatal("no cancel event")
	}
}

func TestScheduledActionFailureIsRecorded(t *testing.T) {
	ctx := context.Background()
	svc, s, c := newScheduledService(t, Options{})
	tn, _ := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme"})
	svc.hooks = hookFunc(func(_ context.Context, req *sdk.HookRequest) error {
		if req.Point == sdk.HookBeforeTenantSuspend {
			return sdk.Reject("not today")
		}
		return nil
	})
	a, _ := svc.Schedule(ctx, tn.ID, ScheduleInput{Action: ScheduleSuspend, After: "1m"})
	c.advance(time.Hour)
	if n := runDue(t, svc); n != 1 {
		t.Fatalf("ran %d", n)
	}
	got, _ := svc.GetScheduled(ctx, tn.ID, a.ID)
	if got.Status != store.ScheduleFailed || got.Error == "" {
		t.Fatalf("not failed: %+v", got)
	}
	if !slices.Contains(eventTypes(t, s), EventActionFailed) {
		t.Fatal("no failure event")
	}
	if n := runDue(t, svc); n != 0 {
		t.Fatal("failed action retried")
	}
}

func TestSoftDeleteAndRestore(t *testing.T) {
	ctx := context.Background()
	svc, s, c := newScheduledService(t, Options{DeletionGracePeriod: 7 * 24 * time.Hour})
	tn, _ := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme"})

	got, a, err := svc.RequestDeletion(ctx, tn.ID, false)
	if err != nil || a == nil {
		t.Fatalf("request: %v %v", a, err)
	}
	if got.Status != sdk.StatusSuspended || got.StatusReason != PendingDeletionReason {
		t.Fatalf("not suspended: %+v", got)
	}
	if !a.RunAt.Equal(c.t.Add(7 * 24 * time.Hour)) {
		t.Fatalf("run at %v", a.RunAt)
	}
	// Repeating the request returns the same scheduled deletion.
	if _, again, err := svc.RequestDeletion(ctx, tn.ID, false); err != nil || again.ID != a.ID {
		t.Fatalf("repeat: %+v %v", again, err)
	}
	if _, err := svc.Resume(ctx, tn.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("plain resume of pending deletion: %v", err)
	}
	if _, err := svc.Suspend(ctx, tn.ID, PendingDeletionReason); err == nil {
		t.Fatal("reserved reason accepted")
	}

	got, err = svc.Restore(ctx, tn.ID)
	if err != nil || got.Status != sdk.StatusActive {
		t.Fatalf("restore: %+v %v", got, err)
	}
	if _, err := svc.Restore(ctx, tn.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("restore twice: %v", err)
	}
	c.advance(8 * 24 * time.Hour)
	runDue(t, svc)
	if got, _ := svc.Get(ctx, tn.ID); got.Status != sdk.StatusActive {
		t.Fatalf("restored tenant deleted: %s", got.Status)
	}

	// Without restore the grace period ends in deletion.
	if _, _, err := svc.RequestDeletion(ctx, tn.ID, false); err != nil {
		t.Fatal(err)
	}
	c.advance(7*24*time.Hour + time.Second)
	runDue(t, svc)
	if got, _ := svc.Get(ctx, tn.ID); got.Status != sdk.StatusDeleted {
		t.Fatalf("not deleted: %s", got.Status)
	}
	if !slices.Contains(eventTypes(t, s), sdk.EventTenantDeleted) {
		t.Fatal("no deleted event")
	}
}

func TestSoftDeleteKeepsEarlierSuspension(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newScheduledService(t, Options{DeletionGracePeriod: time.Hour})
	tn, _ := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme"})
	if _, err := svc.Suspend(ctx, tn.ID, "billing: unpaid"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RequestDeletion(ctx, tn.ID, false); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Restore(ctx, tn.ID)
	if err != nil || got.Status != sdk.StatusSuspended || got.StatusReason != "billing: unpaid" {
		t.Fatalf("restore changed earlier suspension: %+v %v", got, err)
	}
}

func TestForceDeleteAndPendingActionsOfDeletedTenant(t *testing.T) {
	ctx := context.Background()
	svc, _, c := newScheduledService(t, Options{DeletionGracePeriod: time.Hour})
	tn, _ := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme"})
	a, _ := svc.Schedule(ctx, tn.ID, ScheduleInput{Action: ScheduleSuspend, After: "1m"})
	got, sched, err := svc.RequestDeletion(ctx, tn.ID, true)
	if err != nil || sched != nil || got.Status != sdk.StatusDeleted {
		t.Fatalf("force: %+v %v %v", got, sched, err)
	}
	c.advance(time.Hour)
	runDue(t, svc)
	if a, _ = svc.GetScheduled(ctx, tn.ID, a.ID); a.Status != store.ScheduleCanceled {
		t.Fatalf("action of deleted tenant: %+v", a)
	}
}

func TestSoftDeleteRefusedWithLiveChildren(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newScheduledService(t, Options{DeletionGracePeriod: time.Hour})
	parent, _ := svc.Create(ctx, CreateInput{Slug: "org", Name: "Org"})
	if _, err := svc.Create(ctx, CreateInput{Slug: "ws", Name: "WS", ParentID: parent.ID}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RequestDeletion(ctx, parent.ID, false); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("want refusal, got %v", err)
	}
	if got, _ := svc.Get(ctx, parent.ID); got.Status != sdk.StatusActive {
		t.Fatalf("parent changed: %s", got.Status)
	}
}

func TestSoftDeleteHookRejectionCancelsSchedule(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newScheduledService(t, Options{DeletionGracePeriod: time.Hour})
	tn, _ := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme"})
	svc.hooks = hookFunc(func(_ context.Context, req *sdk.HookRequest) error {
		if req.Point == sdk.HookBeforeTenantSuspend {
			return sdk.Reject("no")
		}
		return nil
	})
	if _, _, err := svc.RequestDeletion(ctx, tn.ID, false); err == nil {
		t.Fatal("rejection ignored")
	}
	if _, ok, _ := svc.pendingDeletion(ctx, tn.ID); ok {
		t.Fatal("deletion still scheduled")
	}
}

func TestRunScheduledClaimsOnce(t *testing.T) {
	ctx := context.Background()
	svc, _, c := newScheduledService(t, Options{})
	for _, slug := range []string{"a", "b", "c", "d"} {
		tn, _ := svc.Create(ctx, CreateInput{Slug: slug, Name: slug})
		if _, err := svc.Schedule(ctx, tn.ID, ScheduleInput{Action: ScheduleSuspend, After: "1m"}); err != nil {
			t.Fatal(err)
		}
	}
	c.advance(time.Hour)
	results := make(chan int, 4)
	for range 4 {
		go func() {
			n, _ := svc.RunScheduled(ctx, 100)
			results <- n
		}()
	}
	total := 0
	for range 4 {
		total += <-results
	}
	if total != 4 {
		t.Fatalf("executed %d actions, want 4", total)
	}
}

func TestPurgeDeletedTenants(t *testing.T) {
	ctx := context.Background()
	svc, s, c := newScheduledService(t, Options{})
	keep, _ := svc.Create(ctx, CreateInput{Slug: "keep", Name: "Keep", Labels: map[string]string{"a": "b"}})
	gone, _ := svc.Create(ctx, CreateInput{Slug: "gone", Name: "Gone", Labels: map[string]string{"a": "b"}})
	_, _ = svc.AddMember(ctx, gone.ID, MemberInput{Email: "x@example.com", Role: "admin"})
	if _, err := svc.Delete(ctx, gone.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := svc.PurgeDeletedTenants(ctx, 24*time.Hour); n != 0 {
		t.Fatalf("purged too early: %d", n)
	}
	c.advance(25 * time.Hour)
	if n, err := svc.PurgeDeletedTenants(ctx, 24*time.Hour); err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if n, _ := svc.PurgeDeletedTenants(ctx, 24*time.Hour); n != 0 {
		t.Fatalf("purged twice: %d", n)
	}
	got, _ := s.GetTenant(ctx, gone.ID)
	if got.StatusReason != "purged" || got.Labels != nil {
		t.Fatalf("tombstone: %+v", got)
	}
	if ms, _ := s.ListMembers(ctx, gone.ID); len(ms) != 0 {
		t.Fatal("members survived purge")
	}
	if k, _ := s.GetTenant(ctx, keep.ID); k.Labels["a"] != "b" {
		t.Fatal("live tenant touched")
	}
	if !slices.Contains(eventTypes(t, s), EventTenantPurged) {
		t.Fatal("no purge event")
	}
}
