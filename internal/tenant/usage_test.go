package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func TestPeriodOf(t *testing.T) {
	at := time.Date(2026, 12, 31, 23, 59, 0, 0, time.UTC)
	for period, want := range map[string]string{
		PeriodDay: "2026-12-31", PeriodMonth: "2026-12", PeriodYear: "2026", PeriodNone: "",
	} {
		name, end := periodOf(period, sdk.Tenant{}, at)
		if name != want {
			t.Errorf("%s: %s", period, name)
		}
		if period != PeriodNone && !end.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("%s end: %v", period, end)
		}
	}
	if err := ValidateMetricPolicies(map[string]MetricPolicy{"x": {Period: "week"}}); err == nil {
		t.Error("bad period accepted")
	}
	if err := ValidateMetricPolicies(map[string]MetricPolicy{"x": {Overage: "maybe"}}); err == nil {
		t.Error("bad overage accepted")
	}
}

func usageEvents(t *testing.T, s store.Store, typ string) []sdk.UsagePeriodData {
	t.Helper()
	evts, _ := s.ReadEvents(context.Background(), 0, 0)
	var out []sdk.UsagePeriodData
	for _, e := range evts {
		if e.Type == typ {
			var d sdk.UsagePeriodData
			_ = json.Unmarshal(e.Data, &d)
			out = append(out, d)
		}
	}
	return out
}

func TestMonthlyUsageWithSoftLimit(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc := NewService(s, Options{Users: &UserOptions{Log: discard}, Metrics: map[string]MetricPolicy{
		"api_calls": {Period: PeriodMonth, Overage: OverageAllow, Thresholds: []int{80, 100}},
		"exports":   {Period: PeriodDay, Thresholds: []int{50}},
	}})
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	if _, err := svc.CreatePlan(ctx, PlanInput{ID: "pro", Name: "Pro", Limits: map[string]int64{"api_calls": 10, "exports": 2}}); err != nil {
		t.Fatal(err)
	}
	tn, _ := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme", Plan: "pro"})

	it, err := svc.RecordUsage(ctx, tn.ID, "api_calls", 8)
	if err != nil || it.Period != "2026-10" || it.Overage {
		t.Fatalf("record: %+v %v", it, err)
	}
	// Overage is allowed and reported; both thresholds fire once.
	if it, err = svc.RecordUsage(ctx, tn.ID, "api_calls", 5); err != nil || !it.Overage || it.Value != 13 {
		t.Fatalf("overage: %+v %v", it, err)
	}
	_, _ = svc.RecordUsage(ctx, tn.ID, "api_calls", 1)
	th := usageEvents(t, s, sdk.EventTenantUsageThreshold)
	if len(th) != 2 || th[0].Percent != 80 || th[1].Percent != 100 || th[1].Value != 13 {
		t.Fatalf("thresholds: %+v", th)
	}

	// Blocked metric: the daily limit is enforced.
	if _, err := svc.RecordUsage(ctx, tn.ID, "exports", 2); err != nil {
		t.Fatal(err)
	}
	var qe *QuotaError
	if _, err := svc.RecordUsage(ctx, tn.ID, "exports", 1); !errors.As(err, &qe) {
		t.Fatalf("daily limit not enforced: %v", err)
	}

	// Next month starts at zero; the old period is reported once.
	now = time.Date(2026, 11, 1, 0, 5, 0, 0, time.UTC)
	items, _ := svc.Usage(ctx, tn.ID)
	i := slices.IndexFunc(items, func(u UsageItem) bool { return u.Metric == "api_calls" })
	if items[i].Value != 0 || items[i].Period != "2026-11" || *items[i].Limit != 10 {
		t.Fatalf("new period: %+v", items[i])
	}
	if _, err := svc.RecordUsage(ctx, tn.ID, "exports", 1); err != nil {
		t.Fatalf("new day still blocked: %v", err)
	}
	n, err := svc.CloseEndedPeriods(ctx, 100)
	if err != nil || n != 2 { // api_calls 2026-10, exports 2026-10-30
		t.Fatalf("closed %d %v", n, err)
	}
	if n, _ := svc.CloseEndedPeriods(ctx, 100); n != 0 {
		t.Fatalf("closed twice: %d", n)
	}
	closed := usageEvents(t, s, sdk.EventTenantUsagePeriodClosed)
	j := slices.IndexFunc(closed, func(d sdk.UsagePeriodData) bool { return d.Metric == "api_calls" })
	if j < 0 || closed[j].Value != 14 || closed[j].Period != "2026-10" || *closed[j].Limit != 10 {
		t.Fatalf("closed events: %+v", closed)
	}
	hist, _ := svc.UsageHistory(ctx, tn.ID, "exports", 10)
	if len(hist) != 2 || hist[0].Period != "2026-11-01" || hist[1].ClosedAt == nil {
		t.Fatalf("history: %+v", hist)
	}
}

func TestBillingCycle(t *testing.T) {
	anchor := time.Date(2026, 1, 31, 10, 0, 0, 0, time.UTC)
	tn := sdk.Tenant{CreatedAt: time.Date(2025, 5, 5, 0, 0, 0, 0, time.UTC), BillingAnchor: &anchor}
	for _, c := range []struct{ now, start, end time.Time }{
		{time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC), anchor, time.Date(2026, 2, 28, 10, 0, 0, 0, time.UTC)},
		{time.Date(2026, 2, 28, 10, 0, 0, 0, time.UTC), time.Date(2026, 2, 28, 10, 0, 0, 0, time.UTC), time.Date(2026, 3, 31, 10, 0, 0, 0, time.UTC)},
		{time.Date(2026, 4, 30, 9, 59, 0, 0, time.UTC), time.Date(2026, 3, 31, 10, 0, 0, 0, time.UTC), time.Date(2026, 4, 30, 10, 0, 0, 0, time.UTC)},
		{time.Date(2027, 1, 31, 10, 0, 0, 0, time.UTC), time.Date(2027, 1, 31, 10, 0, 0, 0, time.UTC), time.Date(2027, 2, 28, 10, 0, 0, 0, time.UTC)},
	} {
		start, end := billingCycle(tn, c.now)
		if !start.Equal(c.start) || !end.Equal(c.end) {
			t.Errorf("%v: %v - %v, want %v - %v", c.now, start, end, c.start, c.end)
		}
	}
	// Without an anchor, cycles start at creation.
	tn.BillingAnchor = nil
	if start, _ := billingCycle(tn, time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)); !start.Equal(time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("created-at cycle: %v", start)
	}
	name, end := periodOf(PeriodCycle, tn, time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC))
	if name != "cycle:2026-03-05T00:00:00Z" || !end.Equal(time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("period: %s %v", name, end)
	}
}

func TestCycleUsage(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc := NewService(s, Options{Metrics: map[string]MetricPolicy{"calls": {Period: PeriodCycle}}})
	now := time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	tn, _ := svc.Create(ctx, CreateInput{Slug: "a", Name: "A", Limits: map[string]int64{"calls": 10}})
	anchor := time.Date(2026, 2, 20, 0, 0, 0, 0, time.UTC)
	if _, err := svc.Update(ctx, tn.ID, UpdateInput{BillingAnchor: &anchor}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RecordUsage(ctx, tn.ID, "calls", 4); err != nil {
		t.Fatal(err)
	}
	items, _ := svc.Usage(ctx, tn.ID)
	if len(items) != 1 || items[0].Value != 4 || items[0].Period != "cycle:2026-02-20T00:00:00Z" ||
		!items[0].PeriodEnd.Equal(time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("usage: %+v", items)
	}
	now = time.Date(2026, 3, 21, 0, 0, 0, 0, time.UTC)
	if items, _ := svc.Usage(ctx, tn.ID); items[0].Value != 0 {
		t.Fatalf("new cycle: %+v", items)
	}
}

func TestClearBillingAnchor(t *testing.T) {
	ctx := context.Background()
	svc := NewService(memory.New(), Options{})
	tn, _ := svc.Create(ctx, CreateInput{Slug: "a", Name: "A"})
	anchor := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if u, _ := svc.Update(ctx, tn.ID, UpdateInput{BillingAnchor: &anchor}, nil); u.BillingAnchor == nil {
		t.Fatal("anchor not set")
	}
	var ve *ValidationError
	if _, err := svc.Update(ctx, tn.ID, UpdateInput{BillingAnchor: &anchor, ClearBillingAnchor: true}, nil); !errors.As(err, &ve) {
		t.Fatalf("set and clear: %v", err)
	}
	if u, err := svc.Update(ctx, tn.ID, UpdateInput{ClearBillingAnchor: true}, nil); err != nil || u.BillingAnchor != nil {
		t.Fatalf("clear: %+v %v", u, err)
	}
}
