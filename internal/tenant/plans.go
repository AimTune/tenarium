package tenant

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

type PlanInput struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Features    map[string]bool  `json:"features,omitempty"`
	Limits      map[string]int64 `json:"limits,omitempty"`
}

// PlanUpdate is a partial plan update; Features and Limits replace the
// whole map when non-nil.
type PlanUpdate struct {
	Name        *string           `json:"name,omitempty"`
	Description *string           `json:"description,omitempty"`
	Features    *map[string]bool  `json:"features,omitempty"`
	Limits      *map[string]int64 `json:"limits,omitempty"`
	// Grandfather pins the tenants currently on the plan to its current
	// revision, so the change only applies to new subscribers (and to
	// tenants later migrated with SetPlanRevision).
	Grandfather bool `json:"grandfather,omitempty"`
}

func (s *Service) CreatePlan(ctx context.Context, in PlanInput) (sdk.Plan, error) {
	now := s.now()
	p := sdk.Plan{
		ID: in.ID, Name: in.Name, Description: in.Description,
		Features: maps.Clone(in.Features), Limits: maps.Clone(in.Limits),
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := validatePlan(&p); err != nil {
		return sdk.Plan{}, err
	}
	err := s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.CreatePlan(ctx, p); err != nil {
			return err
		}
		if err := tx.PutPlanRevision(ctx, revisionOf(p)); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, sdk.EventPlanCreated, "", "plans/"+p.ID, sdk.PlanEventData{Plan: p})
	})
	if err != nil {
		return sdk.Plan{}, err
	}
	s.notify()
	return p, nil
}

func (s *Service) GetPlan(ctx context.Context, id string) (sdk.Plan, error) {
	return s.store.GetPlan(ctx, id)
}

func (s *Service) ListPlans(ctx context.Context) ([]sdk.Plan, error) {
	return s.store.ListPlans(ctx)
}

func (s *Service) UpdatePlan(ctx context.Context, id string, in PlanUpdate, expectedVersion *int64) (sdk.Plan, error) {
	prev, err := s.store.GetPlan(ctx, id)
	if err != nil {
		return sdk.Plan{}, err
	}
	if expectedVersion != nil && *expectedVersion != prev.Version {
		return sdk.Plan{}, store.ErrConflict
	}
	next := prev.Clone()
	if in.Name != nil {
		next.Name = *in.Name
	}
	if in.Description != nil {
		next.Description = *in.Description
	}
	if in.Features != nil {
		next.Features = maps.Clone(*in.Features)
	}
	if in.Limits != nil {
		next.Limits = maps.Clone(*in.Limits)
	}
	if err := validatePlan(&next); err != nil {
		return sdk.Plan{}, err
	}
	next.Version = prev.Version + 1
	next.UpdatedAt = s.now()
	if in.Grandfather {
		if err := s.pinPlanTenants(ctx, prev); err != nil {
			return sdk.Plan{}, err
		}
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.UpdatePlan(ctx, next, prev.Version); err != nil {
			return err
		}
		// The previous revision is recorded too, for plans created before
		// revisions existed (idempotent otherwise).
		for _, r := range []sdk.Plan{prev, next} {
			if err := tx.PutPlanRevision(ctx, revisionOf(r)); err != nil {
				return err
			}
		}
		return s.appendEvent(ctx, tx, sdk.EventPlanUpdated, "", "plans/"+next.ID, sdk.PlanEventData{Plan: next, Previous: &prev})
	})
	if err != nil {
		return sdk.Plan{}, err
	}
	s.notify()
	return next, nil
}

// DeletePlan removes a plan no live tenant uses.
func (s *Service) DeletePlan(ctx context.Context, id string) error {
	prev, err := s.store.GetPlan(ctx, id)
	if err != nil {
		return err
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		n, err := tx.CountTenantsOnPlan(ctx, id)
		if err != nil {
			return err
		}
		if n > 0 {
			return stateErr("plan %q is used by %d tenant(s)", id, n)
		}
		if err := tx.DeletePlan(ctx, id); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, sdk.EventPlanDeleted, "", "plans/"+id, sdk.PlanEventData{Plan: prev})
	})
	if err != nil {
		return err
	}
	s.notify()
	return nil
}

func revisionOf(p sdk.Plan) store.PlanRevision {
	return store.PlanRevision{PlanID: p.ID, Revision: p.Version, Features: maps.Clone(p.Features),
		Limits: maps.Clone(p.Limits), CreatedAt: p.UpdatedAt}
}

// pinPlanTenants pins the unpinned live tenants on p to its revision. It
// runs before the plan changes, so a tenant pinned here sees no difference
// even if the plan update then fails.
func (s *Service) pinPlanTenants(ctx context.Context, p sdk.Plan) error {
	after := ""
	for {
		page, err := s.store.ListTenants(ctx, store.ListTenantsQuery{Plan: p.ID, After: after, Limit: 200})
		if err != nil {
			return err
		}
		for _, t := range page {
			if t.PlanRevision != 0 || !t.IsLive() {
				continue
			}
			_, err := s.mutate(ctx, t.ID, nil, "", sdk.EventTenantUpdated, func(t *sdk.Tenant) error {
				if t.Plan == p.ID && t.PlanRevision == 0 {
					t.PlanRevision = p.Version
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("pin tenant %s: %w", t.ID, err)
			}
		}
		if len(page) < 200 {
			return nil
		}
		after = page[len(page)-1].ID
	}
}

// ListPlanRevisions returns a plan's recorded revisions, newest first.
func (s *Service) ListPlanRevisions(ctx context.Context, planID string) ([]store.PlanRevision, error) {
	if _, err := s.store.GetPlan(ctx, planID); err != nil {
		return nil, err
	}
	return s.store.ListPlanRevisions(ctx, planID)
}

// SetPlanRevision pins a tenant to a revision of its plan, or unpins it
// (revision 0) so it follows the current plan.
func (s *Service) SetPlanRevision(ctx context.Context, idOrSlug string, revision int64) (sdk.Tenant, error) {
	t, err := s.Get(ctx, idOrSlug)
	if err != nil {
		return sdk.Tenant{}, err
	}
	if revision < 0 {
		return sdk.Tenant{}, invalid("revision", "must not be negative")
	}
	if revision > 0 {
		if t.Plan == "" {
			return sdk.Tenant{}, invalid("revision", "tenant has no plan")
		}
		if _, err := s.store.GetPlanRevision(ctx, t.Plan, revision); errors.Is(err, store.ErrNotFound) {
			return sdk.Tenant{}, invalid("revision", "plan %q has no revision %d", t.Plan, revision)
		} else if err != nil {
			return sdk.Tenant{}, err
		}
	}
	return s.mutate(ctx, t.ID, nil, "", sdk.EventTenantUpdated, func(n *sdk.Tenant) error {
		if !n.IsLive() {
			return transitionErr("update", n.Status)
		}
		if n.Plan != t.Plan {
			return store.ErrConflict
		}
		n.PlanRevision = revision
		return nil
	})
}
