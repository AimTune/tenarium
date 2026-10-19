package tenant

import (
	"context"
	"slices"

	"github.com/AimTune/tenarium/internal/store"
)

// Rollout changes are events, so caches of entitlements can refresh.
const (
	EventRolloutUpdated = "rollout.updated"
	EventRolloutDeleted = "rollout.deleted"
)

func (s *Service) ListRollouts(ctx context.Context) ([]store.Rollout, error) {
	return s.store.ListRollouts(ctx)
}

func (s *Service) GetRollout(ctx context.Context, feature string) (store.Rollout, error) {
	return s.store.GetRollout(ctx, feature)
}

// PutRollout creates or replaces the rollout of r.Feature.
func (s *Service) PutRollout(ctx context.Context, r store.Rollout) (store.Rollout, error) {
	if !keyRe.MatchString(r.Feature) {
		return store.Rollout{}, invalid("feature", "invalid feature name %q", r.Feature)
	}
	if r.Percentage < 0 || r.Percentage > 100 {
		return store.Rollout{}, invalid("percentage", "must be 0-100")
	}
	for _, p := range r.Plans {
		if !slugRe.MatchString(p) {
			return store.Rollout{}, invalid("plans", "invalid plan id %q", p)
		}
	}
	for k := range r.Labels {
		if !labelKeyRe.MatchString(k) {
			return store.Rollout{}, invalid("labels", "invalid key %q", k)
		}
	}
	if len(r.Include)+len(r.Exclude) > 1000 {
		return store.Rollout{}, invalid("include", "at most 1000 included and excluded tenants")
	}
	for _, id := range r.Include {
		if slices.Contains(r.Exclude, id) {
			return store.Rollout{}, invalid("include", "tenant %q is both included and excluded", id)
		}
	}
	r.UpdatedAt = s.now()
	if err := s.store.PutRollout(ctx, r); err != nil {
		return store.Rollout{}, err
	}
	return r, s.RecordEvent(ctx, EventRolloutUpdated, "", "rollouts/"+r.Feature, r)
}

func (s *Service) DeleteRollout(ctx context.Context, feature string) error {
	r, err := s.store.GetRollout(ctx, feature)
	if err != nil {
		return err
	}
	if err := s.store.DeleteRollout(ctx, feature); err != nil {
		return err
	}
	return s.RecordEvent(ctx, EventRolloutDeleted, "", "rollouts/"+feature, r)
}
