package memory

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func usageKey(tenantID, metric, period string) string {
	return tenantID + "\x00" + metric + "\x00" + period
}

func (s *Store) ListUsage(_ context.Context, q store.UsageQuery) ([]store.Usage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.Usage
	for _, u := range s.usage {
		if q.Match(u) {
			out = append(out, u)
		}
	}
	slices.SortFunc(out, func(a, b store.Usage) int {
		return cmp.Or(cmp.Compare(a.TenantID, b.TenantID), cmp.Compare(a.Metric, b.Metric), cmp.Compare(b.Period, a.Period))
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (s *Store) EndedUsage(_ context.Context, now time.Time, limit int) ([]store.Usage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.Usage
	for _, u := range s.usage {
		if u.PeriodEnd != nil && !u.PeriodEnd.After(now) && u.ClosedAt == nil {
			out = append(out, u)
		}
	}
	slices.SortFunc(out, func(a, b store.Usage) int { return a.PeriodEnd.Compare(*b.PeriodEnd) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) IncrementUsage(_ context.Context, key store.UsageKey, delta int64, limit *int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := usageKey(key.TenantID, key.Metric, key.Period)
	u, ok := s.usage[k]
	if !ok {
		u = store.Usage{TenantID: key.TenantID, Metric: key.Metric, Period: key.Period, PeriodEnd: key.PeriodEnd}
	}
	if limit != nil && delta > 0 && u.Value+delta > *limit {
		return u.Value, store.ErrQuotaExceeded
	}
	u.Value = max(u.Value+delta, 0)
	u.UpdatedAt = s.now().UTC()
	s.usage[k] = u
	return u.Value, nil
}

// CloseUsage stages the closure; it is applied when the transaction
// commits (the parent's write lock is held meanwhile).
func (t *tx) CloseUsage(_ context.Context, tenantID, metric, period string, at time.Time) error {
	k := usageKey(tenantID, metric, period)
	u, ok := t.s.usage[k]
	switch {
	case !ok:
		return store.ErrNotFound
	case u.ClosedAt != nil || slices.Contains(t.closedUsage, k):
		return store.ErrConflict
	}
	t.closedUsage = append(t.closedUsage, k)
	t.closedAt = at
	return nil
}

func (s *Store) applyUsageClosures(t *tx) {
	for _, k := range t.closedUsage {
		u := s.usage[k]
		at := t.closedAt
		u.ClosedAt = &at
		s.usage[k] = u
	}
}
