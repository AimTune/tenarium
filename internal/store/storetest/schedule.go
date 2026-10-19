package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func testSchedule(t *testing.T, s store.Store) {
	ctx := context.Background()
	tn := tenant("sched")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateTenant(ctx, tn) })
	now := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(action string, runAt time.Time) store.ScheduledAction {
		a := store.ScheduledAction{
			ID: newID(), TenantID: tn.ID, Action: action, Plan: "pro", Reason: "r",
			RunAt: runAt, Status: store.SchedulePending, CreatedBy: "test", CreatedAt: now,
		}
		mustTx(t, s, func(tx store.Tx) error { return tx.CreateScheduledAction(ctx, a) })
		return a
	}
	later := mk("delete", now.Add(time.Hour))
	due2 := mk("set_plan", now.Add(-time.Minute))
	due1 := mk("suspend", now.Add(-time.Hour))

	got, err := s.GetScheduledAction(ctx, due2.ID)
	if err != nil || got.Plan != "pro" || got.Reason != "r" || !got.RunAt.Equal(due2.RunAt) || got.CreatedBy != "test" {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := s.GetScheduledAction(ctx, newID()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	list, _ := s.ListScheduledActions(ctx, tn.ID)
	if len(list) != 3 || list[0].ID != due1.ID || list[2].ID != later.ID {
		t.Fatalf("list order: %+v", list)
	}

	stale := now.Add(-5 * time.Minute)
	due, _ := s.DueScheduledActions(ctx, now, stale, 10)
	if len(due) != 2 || due[0].ID != due1.ID || due[1].ID != due2.ID {
		t.Fatalf("due: %+v", due)
	}
	if d, _ := s.DueScheduledActions(ctx, now, stale, 1); len(d) != 1 {
		t.Fatalf("limit: %d", len(d))
	}
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.ClaimScheduledAction(ctx, later.ID, now, stale) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("claim future: %v", err)
	}
	mustTx(t, s, func(tx store.Tx) error { return tx.ClaimScheduledAction(ctx, due1.ID, now, stale) })
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.ClaimScheduledAction(ctx, due1.ID, now, stale) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("double claim: %v", err)
	}
	if d, _ := s.DueScheduledActions(ctx, now, stale, 10); len(d) != 1 || d[0].ID != due2.ID {
		t.Fatalf("due after claim: %+v", d)
	}
	// A claim older than staleBefore is due again (its runner died).
	if d, _ := s.DueScheduledActions(ctx, now, now.Add(time.Second), 10); len(d) != 2 {
		t.Fatalf("stale claim not due: %+v", d)
	}
	mustTx(t, s, func(tx store.Tx) error {
		return tx.FinishScheduledAction(ctx, due1.ID, store.ScheduleFailed, "boom", now)
	})
	got, _ = s.GetScheduledAction(ctx, due1.ID)
	if got.Status != store.ScheduleFailed || got.Error != "boom" || got.DoneAt == nil {
		t.Fatalf("finished: %+v", got)
	}
	if err := s.InTx(ctx, func(tx store.Tx) error {
		return tx.FinishScheduledAction(ctx, due1.ID, store.ScheduleDone, "", now)
	}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("finish twice: %v", err)
	}
	if err := s.InTx(ctx, func(tx store.Tx) error {
		return tx.FinishScheduledAction(ctx, newID(), store.ScheduleDone, "", now)
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("finish missing: %v", err)
	}
	// Pending actions can be canceled without being claimed.
	mustTx(t, s, func(tx store.Tx) error {
		return tx.FinishScheduledAction(ctx, later.ID, store.ScheduleCanceled, "", now)
	})
	if d, _ := s.DueScheduledActions(ctx, now.Add(2*time.Hour), stale, 10); len(d) != 1 || d[0].ID != due2.ID {
		t.Fatalf("canceled still due: %+v", d)
	}
}
