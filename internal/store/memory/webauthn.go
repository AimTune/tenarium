package memory

import (
	"context"
	"slices"

	"github.com/AimTune/tenarium/internal/store"
)

func (s *Store) ListWebAuthnCredentials(_ context.Context, userID string) ([]store.WebAuthnCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.WebAuthnCredential
	for _, c := range s.passkeys {
		if c.UserID == userID {
			c.Data = slices.Clone(c.Data)
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b store.WebAuthnCredential) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}

func (s *Store) GetWebAuthnCredential(_ context.Context, id string) (store.WebAuthnCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.passkeys[id]
	if !ok {
		return store.WebAuthnCredential{}, store.ErrNotFound
	}
	c.Data = slices.Clone(c.Data)
	return c, nil
}

func (s *Store) PutWebAuthnCredential(_ context.Context, c store.WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[c.UserID]; !ok {
		return store.ErrNotFound
	}
	if old, ok := s.passkeys[c.ID]; ok && old.UserID != c.UserID {
		return store.ErrAlreadyExists
	}
	c.Data = slices.Clone(c.Data)
	s.passkeys[c.ID] = c
	return nil
}

func (s *Store) DeleteWebAuthnCredential(_ context.Context, userID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.passkeys[id]
	if !ok || c.UserID != userID {
		return store.ErrNotFound
	}
	delete(s.passkeys, id)
	return nil
}
