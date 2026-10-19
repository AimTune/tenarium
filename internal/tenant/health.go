package tenant

import (
	"context"
	"fmt"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// Health is a tenant's health score: 100 minus the impact of each factor
// found, for customer-success dashboards and alerts.
type Health struct {
	TenantID string `json:"tenant_id"`
	Score    int    `json:"score"`
	// Grade is "healthy" (80+), "at_risk" (50-79) or "critical".
	Grade   string         `json:"grade"`
	Factors []HealthFactor `json:"factors"`
}

// HealthFactor explains one deduction.
type HealthFactor struct {
	Name   string `json:"name"`
	Impact int    `json:"impact"`
	Detail string `json:"detail"`
}

// TenantHealth scores a tenant from its lifecycle state, usage against
// limits, recent quota refusals and provisioning failures, undelivered
// events and member activity.
func (s *Service) TenantHealth(ctx context.Context, idOrSlug string) (Health, error) {
	t, err := s.Get(ctx, idOrSlug)
	if err != nil {
		return Health{}, err
	}
	now := s.now()
	h := Health{TenantID: t.ID, Factors: []HealthFactor{}}
	add := func(name string, impact int, format string, args ...any) {
		h.Factors = append(h.Factors, HealthFactor{Name: name, Impact: impact, Detail: fmt.Sprintf(format, args...)})
	}

	switch t.Status {
	case sdk.StatusSuspended:
		add("status", 40, "suspended: %s", t.StatusReason)
	case sdk.StatusFailed:
		add("status", 60, "provisioning failed: %s", t.StatusReason)
	case sdk.StatusProvisioning:
		add("status", 10, "still provisioning")
	case sdk.StatusDeleting, sdk.StatusDeleted:
		add("status", 100, "%s", t.Status)
	}
	if t.MaintenanceActive(now) {
		add("maintenance", 10, "in maintenance: %s", t.Maintenance.Message)
	}

	if items, err := s.Usage(ctx, t.ID); err == nil {
		impact, detail := 0, ""
		for _, it := range items {
			if it.Limit == nil || *it.Limit == 0 || it.Value*10 < *it.Limit*9 {
				continue
			}
			if it.Value >= *it.Limit {
				impact += 20
			} else {
				impact += 10
			}
			if detail != "" {
				detail += ", "
			}
			detail += fmt.Sprintf("%s %d/%d", it.Metric, it.Value, *it.Limit)
		}
		if impact > 0 {
			add("usage", min(impact, 40), "at or near limits: %s", detail)
		}
	}

	week, month := now.AddDate(0, 0, -7), now.AddDate(0, 0, -30)
	if evs, err := s.store.QueryEvents(ctx, store.EventQuery{TenantIDs: []string{t.ID},
		Types: []string{sdk.EventTenantQuotaExceeded}, Since: week, Limit: 100}); err == nil && len(evs) > 0 {
		add("quota_refusals", min(5*len(evs), 20), "%d usage increments refused in the last 7 days", len(evs))
	}
	if evs, err := s.store.QueryEvents(ctx, store.EventQuery{TenantIDs: []string{t.ID},
		Types: []string{sdk.EventTenantProvisioningFailed, sdk.EventTenantDeprovisioningFailed}, Since: month, Limit: 100}); err == nil && len(evs) > 0 {
		add("provisioning_failures", min(10*len(evs), 30), "%d provisioning failures in the last 30 days", len(evs))
	}
	if dls, err := s.store.ListDeadLetters(ctx, "", 1000); err == nil {
		n := 0
		for _, dl := range dls {
			if dl.Event.TenantID == t.ID {
				n++
			}
		}
		if n > 0 {
			add("dead_letters", min(5*n, 20), "%d events could not be delivered", n)
		}
	}

	if ms, err := s.store.ListMembers(ctx, t.ID); err == nil {
		active, recent := 0, 0
		for _, m := range ms {
			if m.Status != sdk.MemberActive || m.UserID == "" {
				continue
			}
			active++
			if u, err := s.store.GetUser(ctx, m.UserID); err == nil && u.LastLoginAt != nil && u.LastLoginAt.After(month) {
				recent++
			}
		}
		switch {
		case active == 0:
			add("members", 10, "no active members")
		case recent == 0 && t.CreatedAt.Before(month):
			add("activity", 15, "no member signed in during the last 30 days")
		}
	}

	h.Score = 100
	for _, f := range h.Factors {
		h.Score -= f.Impact
	}
	h.Score = max(h.Score, 0)
	switch {
	case h.Score >= 80:
		h.Grade = "healthy"
	case h.Score >= 50:
		h.Grade = "at_risk"
	default:
		h.Grade = "critical"
	}
	return h, nil
}
