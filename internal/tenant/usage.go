package tenant

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// Usage periods.
const (
	PeriodNone  = ""
	PeriodDay   = "day"
	PeriodMonth = "month"
	PeriodYear  = "year"
	// PeriodCycle is the tenant's monthly billing cycle, starting at its
	// BillingAnchor (or creation time).
	PeriodCycle = "cycle"
)

// Overage policies.
const (
	OverageBlock = "block"
	OverageAllow = "allow"
)

// MetricPolicy says how a metered metric behaves. Metrics without a policy
// never reset and are blocked at their limit.
type MetricPolicy struct {
	// Period resets the counter every UTC day, month or year, every billing
	// cycle of the tenant ("cycle"), or never ("").
	Period string `json:"period,omitempty" yaml:"period"`
	// Overage "allow" records usage beyond the limit instead of refusing it
	// (soft limit; bill or warn for it). Default "block".
	Overage string `json:"overage,omitempty" yaml:"overage"`
	// Thresholds are percentages of the limit (e.g. 80, 100) whose crossing
	// emits tenant.usage_threshold_reached.
	Thresholds []int `json:"thresholds,omitempty" yaml:"thresholds"`
}

// ValidateMetricPolicies checks usage policies from configuration.
func ValidateMetricPolicies(p map[string]MetricPolicy) error {
	for m, pol := range p {
		if !slices.Contains([]string{PeriodNone, PeriodDay, PeriodMonth, PeriodYear, PeriodCycle}, pol.Period) {
			return fmt.Errorf("usage metric %s: period must be day, month, year, cycle or empty", m)
		}
		if !slices.Contains([]string{"", OverageBlock, OverageAllow}, pol.Overage) {
			return fmt.Errorf("usage metric %s: overage must be block or allow", m)
		}
		for _, t := range pol.Thresholds {
			if t <= 0 || t > 1000 {
				return fmt.Errorf("usage metric %s: thresholds are percentages between 1 and 1000", m)
			}
		}
	}
	return nil
}

// periodOf names the period of t containing now and returns its end.
func periodOf(period string, t sdk.Tenant, now time.Time) (string, *time.Time) {
	now = now.UTC()
	y, m, d := now.Date()
	var name string
	var end time.Time
	switch period {
	case PeriodDay:
		name, end = now.Format("2006-01-02"), time.Date(y, m, d+1, 0, 0, 0, 0, time.UTC)
	case PeriodMonth:
		name, end = now.Format("2006-01"), time.Date(y, m+1, 1, 0, 0, 0, 0, time.UTC)
	case PeriodYear:
		name, end = now.Format("2006"), time.Date(y+1, 1, 1, 0, 0, 0, 0, time.UTC)
	case PeriodCycle:
		start, next := billingCycle(t, now)
		// Prefixed so it never collides with a day period's name.
		name, end = "cycle:"+start.Format(time.RFC3339), next
	default:
		return "", nil
	}
	return name, &end
}

// UsageItem is a metric's value in its current period next to its limit
// (nil = unlimited).
type UsageItem struct {
	Metric    string     `json:"metric"`
	Period    string     `json:"period,omitempty"`
	PeriodEnd *time.Time `json:"period_end,omitempty"`
	Value     int64      `json:"value"`
	Limit     *int64     `json:"limit,omitempty"`
	// Overage is true when the value is above the limit (soft limits).
	Overage bool   `json:"overage,omitempty"`
	Policy  string `json:"overage_policy,omitempty"`
}

func (s *Service) policy(metric string) MetricPolicy {
	p := s.live.Load().metrics[metric]
	if p.Overage == "" {
		p.Overage = OverageBlock
	}
	return p
}

// Usage lists metered values (current periods) and limits for a tenant.
// Metrics that have a limit but no usage yet are included with value 0.
func (s *Service) Usage(ctx context.Context, tenantIDOrSlug string) ([]UsageItem, error) {
	t, err := s.Get(ctx, tenantIDOrSlug)
	if err != nil {
		return nil, err
	}
	ent, err := s.entitlementsOf(ctx, t)
	if err != nil {
		return nil, err
	}
	now := s.now()
	var periods []string
	for _, p := range []string{PeriodNone, PeriodDay, PeriodMonth, PeriodYear, PeriodCycle} {
		name, _ := periodOf(p, t, now)
		periods = append(periods, name)
	}
	rows, err := s.store.ListUsage(ctx, store.UsageQuery{TenantID: t.ID, Periods: periods})
	if err != nil {
		return nil, err
	}
	byMetric := map[string]*UsageItem{}
	item := func(m string) *UsageItem {
		if it, ok := byMetric[m]; ok {
			return it
		}
		pol := s.policy(m)
		name, end := periodOf(pol.Period, t, now)
		it := &UsageItem{Metric: m, Period: name, PeriodEnd: end, Policy: pol.Overage}
		byMetric[m] = it
		return it
	}
	for _, u := range rows {
		// Rows of another granularity are from a policy change; skip them.
		if it := item(u.Metric); it.Period == u.Period {
			it.Value = u.Value
		}
	}
	for m, l := range ent.Limits {
		if m == MetricMembers {
			continue // members are counted, not metered
		}
		it := item(m)
		it.Limit = &l
	}
	out := make([]UsageItem, 0, len(byMetric))
	for _, it := range byMetric {
		it.Overage = it.Limit != nil && it.Value > *it.Limit
		out = append(out, *it)
	}
	slices.SortFunc(out, func(a, b UsageItem) int { return cmp.Compare(a.Metric, b.Metric) })
	return out, nil
}

// UsageHistory returns a metric's counters, newest period first.
func (s *Service) UsageHistory(ctx context.Context, tenantIDOrSlug, metric string, limit int) ([]store.Usage, error) {
	t, err := s.Get(ctx, tenantIDOrSlug)
	if err != nil {
		return nil, err
	}
	return s.store.ListUsage(ctx, store.UsageQuery{TenantID: t.ID, Metric: metric, Limit: limit})
}

// RecordUsage adds delta (may be negative) to a metric's current period.
// With the default "block" policy, increments that would exceed the limit
// are refused (emitting tenant.quota_exceeded); with "allow" they are
// recorded as overage. Crossing a threshold emits
// tenant.usage_threshold_reached. Only active tenants can consume quota.
func (s *Service) RecordUsage(ctx context.Context, tenantIDOrSlug, metric string, delta int64) (UsageItem, error) {
	if !keyRe.MatchString(metric) || metric == MetricMembers {
		return UsageItem{}, invalid("metric", "invalid metric name %q", metric)
	}
	t, err := s.Get(ctx, tenantIDOrSlug)
	if err != nil {
		return UsageItem{}, err
	}
	if t.Status != sdk.StatusActive && delta > 0 {
		return UsageItem{}, transitionErr("record usage for", t.Status)
	}
	ent, err := s.entitlementsOf(ctx, t)
	if err != nil {
		return UsageItem{}, err
	}
	pol := s.policy(metric)
	var limit *int64
	if l, ok := ent.Limit(metric); ok {
		limit = &l
	}
	enforced := limit
	if pol.Overage == OverageAllow {
		enforced = nil
	}
	name, end := periodOf(pol.Period, t, s.now())
	key := store.UsageKey{TenantID: t.ID, Metric: metric, Period: name, PeriodEnd: end}
	value, err := s.store.IncrementUsage(ctx, key, delta, enforced)
	if errors.Is(err, store.ErrQuotaExceeded) {
		qe := &QuotaError{Metric: metric, Limit: *limit, Current: value}
		evErr := s.store.InTx(ctx, func(tx store.Tx) error {
			return s.appendEvent(ctx, tx, sdk.EventTenantQuotaExceeded, t.ID, "tenants/"+t.ID+"/usage/"+metric,
				sdk.UsageEventData{TenantID: t.ID, Metric: metric, Current: value, Requested: delta, Limit: *limit})
		})
		if evErr == nil {
			s.notify()
		}
		return UsageItem{}, qe
	}
	if err != nil {
		return UsageItem{}, err
	}
	it := UsageItem{Metric: metric, Period: name, PeriodEnd: end, Value: value, Limit: limit, Policy: pol.Overage,
		Overage: limit != nil && value > *limit}
	if limit != nil && delta > 0 {
		if err := s.thresholdEvents(ctx, t.ID, it, value-delta, pol.Thresholds); err != nil {
			s.userOpts.Log.Warn("usage threshold event failed", "tenant", t.ID, "metric", metric, "err", err)
		}
	}
	return it, nil
}

// thresholdEvents emits one event per threshold crossed by moving from
// prev to it.Value.
func (s *Service) thresholdEvents(ctx context.Context, tenantID string, it UsageItem, prev int64, thresholds []int) error {
	var crossed []int
	for _, pct := range thresholds {
		// Ceiling, so 80% of 5 is reached at 4.
		at := (*it.Limit*int64(pct) + 99) / 100
		if prev < at && it.Value >= at {
			crossed = append(crossed, pct)
		}
	}
	if len(crossed) == 0 {
		return nil
	}
	err := s.store.InTx(ctx, func(tx store.Tx) error {
		for _, pct := range crossed {
			if err := s.appendEvent(ctx, tx, sdk.EventTenantUsageThreshold, tenantID, "tenants/"+tenantID+"/usage/"+it.Metric,
				sdk.UsagePeriodData{TenantID: tenantID, Metric: it.Metric, Period: it.Period, PeriodEnd: it.PeriodEnd,
					Value: it.Value, Limit: it.Limit, Percent: pct}); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		s.notify()
	}
	return err
}

// CloseEndedPeriods emits tenant.usage_period_closed for counters whose
// period ended, each exactly once, and returns how many it closed.
func (s *Service) CloseEndedPeriods(ctx context.Context, limit int) (int, error) {
	now := s.now()
	ended, err := s.store.EndedUsage(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range ended {
		data := sdk.UsagePeriodData{TenantID: u.TenantID, Metric: u.Metric, Period: u.Period, PeriodEnd: u.PeriodEnd, Value: u.Value}
		if t, err := s.store.GetTenant(ctx, u.TenantID); err == nil {
			if ent, err := s.entitlementsOf(ctx, t); err == nil {
				if l, ok := ent.Limit(u.Metric); ok {
					data.Limit = &l
				}
			}
		}
		err := s.store.InTx(ctx, func(tx store.Tx) error {
			if err := tx.CloseUsage(ctx, u.TenantID, u.Metric, u.Period, now); err != nil {
				return err
			}
			return s.appendEvent(ctx, tx, sdk.EventTenantUsagePeriodClosed, u.TenantID,
				"tenants/"+u.TenantID+"/usage/"+u.Metric+"/"+u.Period, data)
		})
		switch {
		case errors.Is(err, store.ErrConflict):
			continue // another instance closed it
		case err != nil:
			return n, err
		}
		n++
	}
	if n > 0 {
		s.notify()
	}
	return n, nil
}

// billingCycle returns the monthly cycle of t containing now. Cycles start
// on the anchor's day of month, clamped to shorter months (an anchor on the
// 31st renews on Feb 28), at the anchor's time of day.
func billingCycle(t sdk.Tenant, now time.Time) (start, end time.Time) {
	anchor := t.CreatedAt
	if t.BillingAnchor != nil {
		anchor = *t.BillingAnchor
	}
	anchor, now = anchor.UTC(), now.UTC()
	at := func(months int) time.Time {
		y, m, _ := anchor.Date()
		first := time.Date(y, m+time.Month(months), 1, 0, 0, 0, 0, time.UTC)
		days := first.AddDate(0, 1, -1).Day()
		h, mi, s := anchor.Clock()
		return time.Date(first.Year(), first.Month(), min(anchor.Day(), days), h, mi, s, anchor.Nanosecond(), time.UTC)
	}
	k := (now.Year()-anchor.Year())*12 + int(now.Month()) - int(anchor.Month())
	for at(k).After(now) {
		k--
	}
	for !at(k + 1).After(now) {
		k++
	}
	return at(k), at(k + 1)
}
