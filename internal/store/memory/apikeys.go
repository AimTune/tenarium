package memory

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func cloneKey(k store.APIKey) store.APIKey {
	k.Roles = slices.Clone(k.Roles)
	return k
}

func (s *Store) GetAPIKeyByHash(_ context.Context, hash string) (store.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.apiKeys {
		if k.Hash == hash {
			return cloneKey(k), nil
		}
	}
	return store.APIKey{}, store.ErrNotFound
}

func (s *Store) ListAPIKeys(_ context.Context, tenantID string) ([]store.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.APIKey
	for _, id := range slices.Sorted(maps.Keys(s.apiKeys)) {
		if k := s.apiKeys[id]; k.TenantID == tenantID {
			out = append(out, cloneKey(k))
		}
	}
	return out, nil
}

func (s *Store) TouchAPIKey(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.apiKeys[id]
	if !ok {
		return store.ErrNotFound
	}
	k.LastUsedAt = &at
	s.apiKeys[id] = k
	return nil
}

func (t *tx) CreateAPIKey(_ context.Context, k store.APIKey) error {
	for _, e := range t.apiKeys {
		if e.ID == k.ID || e.Hash == k.Hash {
			return store.ErrAlreadyExists
		}
	}
	t.apiKeys[k.ID] = cloneKey(k)
	return nil
}

func (t *tx) RevokeAPIKey(_ context.Context, tenantID, id string, at time.Time) (store.APIKey, error) {
	k, ok := t.apiKeys[id]
	if !ok || k.TenantID != tenantID || k.RevokedAt != nil {
		return store.APIKey{}, store.ErrNotFound
	}
	k.RevokedAt = &at
	t.apiKeys[id] = k
	return cloneKey(k), nil
}
