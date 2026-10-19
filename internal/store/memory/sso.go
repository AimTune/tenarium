package memory

import (
	"context"
	"slices"

	"github.com/AimTune/tenarium/internal/store"
)

func cloneSSO(c store.SSOConnection) store.SSOConnection {
	c.Domains = slices.Clone(c.Domains)
	return c
}

func (s *Store) GetSSOConnection(_ context.Context, tenantID string) (store.SSOConnection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.sso[tenantID]
	if !ok {
		return store.SSOConnection{}, store.ErrNotFound
	}
	return cloneSSO(c), nil
}

func (s *Store) FindSSOConnection(_ context.Context, domain string) (store.SSOConnection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.sso {
		if slices.Contains(c.Domains, domain) {
			return cloneSSO(c), nil
		}
	}
	return store.SSOConnection{}, store.ErrNotFound
}

func (s *Store) PutSSOConnection(_ context.Context, c store.SSOConnection) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[c.TenantID]; !ok {
		return store.ErrNotFound
	}
	for tid, other := range s.sso {
		if tid != c.TenantID && slices.ContainsFunc(c.Domains, func(d string) bool { return slices.Contains(other.Domains, d) }) {
			return store.ErrAlreadyExists
		}
	}
	s.sso[c.TenantID] = cloneSSO(c)
	return nil
}

func (s *Store) DeleteSSOConnection(_ context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sso[tenantID]; !ok {
		return store.ErrNotFound
	}
	delete(s.sso, tenantID)
	return nil
}
