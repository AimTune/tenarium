package memory

import (
	"cmp"
	"context"
	"encoding/json"
	"slices"

	"github.com/AimTune/tenarium/internal/store"
)

// Templates are kept as JSON, which also gives deep copies.
func (s *Store) ListTenantTemplates(context.Context) ([]store.TenantTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]store.TenantTemplate, 0, len(s.templates))
	for _, b := range s.templates {
		var t store.TenantTemplate
		if err := json.Unmarshal(b, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b store.TenantTemplate) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

func (s *Store) GetTenantTemplate(_ context.Context, id string) (store.TenantTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.templates[id]
	if !ok {
		return store.TenantTemplate{}, store.ErrNotFound
	}
	var t store.TenantTemplate
	return t, json.Unmarshal(b, &t)
}

func (s *Store) PutTenantTemplate(_ context.Context, t store.TenantTemplate) error {
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.templates[t.ID] = b
	return nil
}

func (s *Store) DeleteTenantTemplate(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.templates[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.templates, id)
	return nil
}
