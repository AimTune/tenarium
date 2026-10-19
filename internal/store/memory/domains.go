package memory

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func (s *Store) GetDomain(_ context.Context, hostname string) (store.Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.domains[hostname]
	if !ok {
		return store.Domain{}, store.ErrNotFound
	}
	return d, nil
}

func (s *Store) ListDomains(_ context.Context, tenantID string) ([]store.Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.Domain
	for _, h := range slices.Sorted(maps.Keys(s.domains)) {
		if d := s.domains[h]; d.TenantID == tenantID {
			out = append(out, d)
		}
	}
	return out, nil
}

func (t *tx) CreateDomain(_ context.Context, d store.Domain) error {
	if _, ok := t.domains[d.Hostname]; ok {
		return store.ErrAlreadyExists
	}
	t.domains[d.Hostname] = d
	return nil
}

func (t *tx) MarkDomainVerified(_ context.Context, hostname string, at time.Time) error {
	d, ok := t.domains[hostname]
	if !ok {
		return store.ErrNotFound
	}
	d.Verified, d.VerifiedAt = true, &at
	t.domains[hostname] = d
	return nil
}

func (t *tx) DeleteDomain(_ context.Context, hostname string) error {
	if _, ok := t.domains[hostname]; !ok {
		return store.ErrNotFound
	}
	delete(t.domains, hostname)
	return nil
}
