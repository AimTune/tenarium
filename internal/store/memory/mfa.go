package memory

import (
	"context"
	"slices"

	"github.com/AimTune/tenarium/internal/store"
)

func (s *Store) GetMFA(_ context.Context, userID string) (store.MFA, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.mfa[userID]
	if !ok {
		return store.MFA{}, store.ErrNotFound
	}
	m.RecoveryHashes = slices.Clone(m.RecoveryHashes)
	return m, nil
}

func (s *Store) PutMFA(_ context.Context, m store.MFA) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[m.UserID]; !ok {
		return store.ErrNotFound
	}
	m.RecoveryHashes = slices.Clone(m.RecoveryHashes)
	s.mfa[m.UserID] = m
	return nil
}

func (s *Store) DeleteMFA(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.mfa[userID]; !ok {
		return store.ErrNotFound
	}
	delete(s.mfa, userID)
	return nil
}

func (s *Store) UseTOTPStep(_ context.Context, userID string, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mfa[userID]
	if !ok || m.LastStep >= step {
		return false, nil
	}
	m.LastStep = step
	s.mfa[userID] = m
	return true, nil
}

func (s *Store) UseRecoveryCode(_ context.Context, userID, hash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mfa[userID]
	if !ok {
		return false, nil
	}
	i := slices.Index(m.RecoveryHashes, hash)
	if i < 0 {
		return false, nil
	}
	m.RecoveryHashes = slices.Delete(slices.Clone(m.RecoveryHashes), i, i+1)
	s.mfa[userID] = m
	return true, nil
}
