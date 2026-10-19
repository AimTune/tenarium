package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func testUsage(t *testing.T, s store.Store) {
	ctx := context.Background()
	tid := newID()
	limit := int64(10)
	seats := store.UsageKey{TenantID: tid, Metric: "seats"}
	if v, err := s.IncrementUsage(ctx, seats, 7, &limit); err != nil || v != 7 {
		t.Fatalf("inc: %d %v", v, err)
	}
	if v, err := s.IncrementUsage(ctx, seats, 4, &limit); !errors.Is(err, store.ErrQuotaExceeded) || v != 7 {
		t.Fatalf("over limit: %d %v", v, err)
	}
	if v, err := s.IncrementUsage(ctx, seats, -10, &limit); err != nil || v != 0 {
		t.Fatalf("decrement clamps at 0: %d %v", v, err)
	}

	// Concurrent increments never exceed the limit.
	oct := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	calls := store.UsageKey{TenantID: tid, Metric: "api_calls", Period: "2026-10", PeriodEnd: &oct}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { _, _ = s.IncrementUsage(ctx, calls, 1, &limit) })
	}
	wg.Wait()
	// A new period starts from zero; the old one is kept.
	nov := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	if v, err := s.IncrementUsage(ctx, store.UsageKey{TenantID: tid, Metric: "api_calls", Period: "2026-11", PeriodEnd: &nov}, 3, &limit); err != nil || v != 3 {
		t.Fatalf("new period: %d %v", v, err)
	}

	all, _ := s.ListUsage(ctx, store.UsageQuery{TenantID: tid})
	if len(all) != 3 || all[0].Metric != "api_calls" || all[0].Period != "2026-11" || all[1].Value != 10 || all[2].Metric != "seats" {
		t.Fatalf("list: %+v", all)
	}
	if all[1].PeriodEnd == nil || !all[1].PeriodEnd.Equal(oct) {
		t.Fatalf("period end: %+v", all[1])
	}
	cur, _ := s.ListUsage(ctx, store.UsageQuery{TenantID: tid, Periods: []string{"", "2026-11"}})
	if len(cur) != 2 {
		t.Fatalf("current periods: %+v", cur)
	}
	if one, _ := s.ListUsage(ctx, store.UsageQuery{TenantID: tid, Metric: "api_calls", Limit: 1}); len(one) != 1 || one[0].Period != "2026-11" {
		t.Fatalf("newest period: %+v", one)
	}

	// Ended periods are reported once.
	ended, _ := s.EndedUsage(ctx, oct.Add(time.Hour), 10)
	if len(ended) != 1 || ended[0].Period != "2026-10" {
		t.Fatalf("ended: %+v", ended)
	}
	at := oct.Add(time.Hour)
	mustTx(t, s, func(tx store.Tx) error { return tx.CloseUsage(ctx, tid, "api_calls", "2026-10", at) })
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.CloseUsage(ctx, tid, "api_calls", "2026-10", at) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("close twice: %v", err)
	}
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.CloseUsage(ctx, tid, "nope", "2026-10", at) }); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("close missing: %v", err)
	}
	if ended, _ := s.EndedUsage(ctx, nov.Add(time.Hour), 10); len(ended) != 1 || ended[0].Period != "2026-11" {
		t.Fatalf("ended after close: %+v", ended)
	}
	// A rolled-back close does not stick.
	_ = s.InTx(ctx, func(tx store.Tx) error {
		_ = tx.CloseUsage(ctx, tid, "api_calls", "2026-11", at)
		return errors.New("rollback")
	})
	if ended, _ := s.EndedUsage(ctx, nov.Add(time.Hour), 10); len(ended) != 1 {
		t.Fatalf("rolled-back close applied: %+v", ended)
	}
}
