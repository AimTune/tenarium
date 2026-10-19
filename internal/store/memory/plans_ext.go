package memory

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/AimTune/tenarium/internal/store"
)

func revKey(planID string, rev int64) string { return fmt.Sprintf("%s\x00%020d", planID, rev) }

func cloneRev(r store.PlanRevision) store.PlanRevision {
	r.Features, r.Limits = maps.Clone(r.Features), maps.Clone(r.Limits)
	return r
}

func (s *Store) ListPlanRevisions(_ context.Context, planID string) ([]store.PlanRevision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.PlanRevision
	for _, r := range s.planRevs {
		if r.PlanID == planID {
			out = append(out, cloneRev(r))
		}
	}
	slices.SortFunc(out, func(a, b store.PlanRevision) int { return cmp.Compare(b.Revision, a.Revision) })
	return out, nil
}

func (s *Store) GetPlanRevision(_ context.Context, planID string, revision int64) (store.PlanRevision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.planRevs[revKey(planID, revision)]
	if !ok {
		return store.PlanRevision{}, store.ErrNotFound
	}
	return cloneRev(r), nil
}

// PutPlanRevision stages the revision in the tx; it commits with it.
func (t *tx) PutPlanRevision(_ context.Context, r store.PlanRevision) error {
	k := revKey(r.PlanID, r.Revision)
	if _, ok := t.planRevs[k]; !ok {
		t.planRevs[k] = cloneRev(r)
	}
	return nil
}

func cloneRollout(r store.Rollout) store.Rollout {
	r.Plans, r.Regions = slices.Clone(r.Plans), slices.Clone(r.Regions)
	r.Include, r.Exclude, r.Labels = slices.Clone(r.Include), slices.Clone(r.Exclude), maps.Clone(r.Labels)
	return r
}

func (s *Store) ListRollouts(_ context.Context) ([]store.Rollout, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]store.Rollout, 0, len(s.rollouts))
	for _, r := range s.rollouts {
		out = append(out, cloneRollout(r))
	}
	slices.SortFunc(out, func(a, b store.Rollout) int { return cmp.Compare(a.Feature, b.Feature) })
	return out, nil
}

func (s *Store) GetRollout(_ context.Context, feature string) (store.Rollout, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rollouts[feature]
	if !ok {
		return store.Rollout{}, store.ErrNotFound
	}
	return cloneRollout(r), nil
}

func (s *Store) PutRollout(_ context.Context, r store.Rollout) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollouts[r.Feature] = cloneRollout(r)
	return nil
}

func (s *Store) DeleteRollout(_ context.Context, feature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rollouts[feature]; !ok {
		return store.ErrNotFound
	}
	delete(s.rollouts, feature)
	return nil
}
