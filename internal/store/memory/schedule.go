package memory

import (
	"context"
	"slices"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func byRunAt(a, b store.ScheduledAction) int {
	if c := a.RunAt.Compare(b.RunAt); c != 0 {
		return c
	}
	return compareStrings(a.ID, b.ID)
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (s *Store) GetScheduledAction(_ context.Context, id string) (store.ScheduledAction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.schedule[id]
	if !ok {
		return store.ScheduledAction{}, store.ErrNotFound
	}
	return a, nil
}

func (s *Store) ListScheduledActions(_ context.Context, tenantID string) ([]store.ScheduledAction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.ScheduledAction
	for _, a := range s.schedule {
		if a.TenantID == tenantID {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, byRunAt)
	return out, nil
}

func (s *Store) DueScheduledActions(_ context.Context, now, staleBefore time.Time, limit int) ([]store.ScheduledAction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.ScheduledAction
	for _, a := range s.schedule {
		if due(a, now, staleBefore) {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, byRunAt)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func due(a store.ScheduledAction, now, staleBefore time.Time) bool {
	switch a.Status {
	case store.SchedulePending:
		return !a.RunAt.After(now)
	case store.ScheduleRunning:
		return a.ClaimedAt == nil || a.ClaimedAt.Before(staleBefore)
	}
	return false
}

func (t *tx) CreateScheduledAction(_ context.Context, a store.ScheduledAction) error {
	if _, ok := t.schedule[a.ID]; ok {
		return store.ErrAlreadyExists
	}
	t.schedule[a.ID] = a
	return nil
}

func (t *tx) ClaimScheduledAction(_ context.Context, id string, at, staleBefore time.Time) error {
	a, ok := t.schedule[id]
	if !ok {
		return store.ErrNotFound
	}
	if !due(a, at, staleBefore) {
		return store.ErrConflict
	}
	a.Status, a.ClaimedAt = store.ScheduleRunning, &at
	t.schedule[id] = a
	return nil
}

func (t *tx) FinishScheduledAction(_ context.Context, id, status, errMsg string, at time.Time) error {
	a, ok := t.schedule[id]
	if !ok {
		return store.ErrNotFound
	}
	if a.Status != store.SchedulePending && a.Status != store.ScheduleRunning {
		return store.ErrConflict
	}
	a.Status, a.Error, a.DoneAt = status, errMsg, &at
	t.schedule[id] = a
	return nil
}
