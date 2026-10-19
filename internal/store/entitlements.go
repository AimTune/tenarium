package store

import (
	"context"
	"errors"
	"hash/fnv"
	"maps"
	"slices"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// EntitlementSource is what ResolveEntitlements reads.
type EntitlementSource interface {
	GetPlan(ctx context.Context, id string) (sdk.Plan, error)
	GetPlanRevision(ctx context.Context, planID string, revision int64) (PlanRevision, error)
	ListRollouts(ctx context.Context) ([]Rollout, error)
}

// ResolveEntitlements computes a tenant's effective features and limits,
// in this order:
//
//  1. its plan, or the plan revision it is pinned to (grandfathering);
//  2. its add-ons: features are OR-ed, limits the base plan sets are
//     raised by the add-on's (a limit the base leaves unset stays
//     unlimited);
//  3. enabled feature rollouts it falls into;
//  4. its own feature and limit overrides, which always win.
//
// Missing plans, revisions and add-ons are skipped.
func ResolveEntitlements(ctx context.Context, s EntitlementSource, t sdk.Tenant) (sdk.Entitlements, error) {
	var base *sdk.Plan
	if t.Plan != "" {
		p, err := s.GetPlan(ctx, t.Plan)
		switch {
		case err == nil:
			base = &p
		case !errors.Is(err, ErrNotFound):
			return sdk.Entitlements{}, err
		}
		if t.PlanRevision > 0 {
			r, err := s.GetPlanRevision(ctx, t.Plan, t.PlanRevision)
			switch {
			case err == nil:
				base = &sdk.Plan{ID: t.Plan, Features: r.Features, Limits: r.Limits}
			case !errors.Is(err, ErrNotFound):
				return sdk.Entitlements{}, err
			}
		}
	}
	e := sdk.Entitlements{TenantID: t.ID, Plan: t.Plan, PlanRevision: t.PlanRevision,
		AddOns: slices.Clone(t.AddOns), Features: map[string]bool{}, Limits: map[string]int64{}}
	if base != nil {
		maps.Copy(e.Features, base.Features)
		maps.Copy(e.Limits, base.Limits)
	}
	for _, id := range t.AddOns {
		a, err := s.GetPlan(ctx, id)
		if errors.Is(err, ErrNotFound) {
			continue
		} else if err != nil {
			return sdk.Entitlements{}, err
		}
		for k, v := range a.Features {
			e.Features[k] = e.Features[k] || v
		}
		for k, v := range a.Limits {
			if cur, ok := e.Limits[k]; ok {
				e.Limits[k] = cur + v
			}
		}
	}
	rollouts, err := s.ListRollouts(ctx)
	if err != nil {
		return sdk.Entitlements{}, err
	}
	for _, r := range rollouts {
		if r.Applies(t) {
			e.Features[r.Feature] = true
		}
	}
	maps.Copy(e.Features, t.Features)
	maps.Copy(e.Limits, t.Limits)
	return e, nil
}

// Applies reports whether the rollout turns its feature on for t (before
// t's own overrides, which win).
func (r Rollout) Applies(t sdk.Tenant) bool {
	if !r.Enabled || slices.Contains(r.Exclude, t.ID) {
		return false
	}
	if slices.Contains(r.Include, t.ID) {
		return true
	}
	if len(r.Plans) > 0 && !slices.Contains(r.Plans, t.Plan) {
		return false
	}
	if len(r.Regions) > 0 && !slices.Contains(r.Regions, t.Region) {
		return false
	}
	for k, v := range r.Labels {
		if t.Labels[k] != v {
			return false
		}
	}
	return RolloutBucket(r.Feature, t.ID) < r.Percentage
}

// RolloutBucket places a tenant in 0-99 for a feature. It is stable, so a
// rollout raised from 10% to 20% keeps the first 10%, and independent per
// feature, so the same tenants aren't always first.
func RolloutBucket(feature, tenantID string) int {
	h := fnv.New32a()
	h.Write([]byte(feature))
	h.Write([]byte{0})
	h.Write([]byte(tenantID))
	return int(h.Sum32() % 100)
}
