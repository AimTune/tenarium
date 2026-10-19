package tenant

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store/memory"
)

func TestUsageGrants(t *testing.T) {
	ctx := context.Background()
	svc := NewService(memory.New(), Options{Metrics: map[string]MetricPolicy{"calls": {Period: PeriodMonth}}})
	now := time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	tn, _ := svc.Create(ctx, CreateInput{Slug: "a", Name: "A", Limits: map[string]int64{"calls": 100}})
	value := func() int64 {
		items, _ := svc.Usage(ctx, tn.ID)
		for _, it := range items {
			if it.Metric == "calls" {
				return it.Value
			}
		}
		return -1
	}

	eu, err := svc.ReserveUsage(ctx, tn.ID, "calls", GrantInput{Amount: 60, TTL: time.Hour, Holder: "eu"})
	if err != nil || value() != 60 {
		t.Fatalf("reserve: %+v %v (value %d)", eu, err, value())
	}
	var qe *QuotaError
	if _, err := svc.ReserveUsage(ctx, tn.ID, "calls", GrantInput{Amount: 50, TTL: time.Hour, Holder: "us"}); !errors.As(err, &qe) {
		t.Fatalf("over-reservation: %v", err)
	}
	us, _ := svc.ReserveUsage(ctx, tn.ID, "calls", GrantInput{Amount: 40, TTL: time.Hour, Holder: "us"})

	// eu used 25 of its 60: 35 come back.
	if _, err := svc.ReleaseUsage(ctx, tn.ID, eu.ID, 25); err != nil || value() != 65 {
		t.Fatalf("release: %v (value %d)", err, value())
	}
	if _, err := svc.ReleaseUsage(ctx, tn.ID, eu.ID, 0); !errors.Is(err, ErrGrantGone) {
		t.Fatalf("double release: %v", err)
	}
	var ve *ValidationError
	if _, err := svc.ReleaseUsage(ctx, tn.ID, us.ID, 41); !errors.As(err, &ve) {
		t.Fatalf("used more than granted: %v", err)
	}
	// An expired grant gives nothing back.
	now = now.Add(2 * time.Hour)
	if _, err := svc.ReleaseUsage(ctx, tn.ID, us.ID, 0); !errors.Is(err, ErrGrantGone) || value() != 65 {
		t.Fatalf("expired release: %v (value %d)", err, value())
	}
	stale, _ := svc.ReserveUsage(ctx, tn.ID, "calls", GrantInput{Amount: 1, TTL: time.Minute})
	now = now.Add(time.Hour)
	if n, err := svc.PurgeExpiredGrants(ctx); err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if _, err := svc.ReleaseUsage(ctx, tn.ID, stale.ID, 0); !errors.Is(err, ErrGrantGone) {
		t.Fatalf("purged grant: %v", err)
	}
}
