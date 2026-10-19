package memory

import (
	"bytes"
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

type actionToken struct {
	store.ActionToken
	used bool
}

type refreshToken struct {
	store.RefreshToken
	rotated, revoked bool
}

func (s *Store) GetUser(_ context.Context, id string) (sdk.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return sdk.User{}, store.ErrNotFound
	}
	return u.Clone(), nil
}

func (s *Store) GetUserByEmail(_ context.Context, email string) (sdk.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if strings.EqualFold(u.Email, email) {
			return u.Clone(), nil
		}
	}
	return sdk.User{}, store.ErrNotFound
}

func (s *Store) GetUserByExternalID(_ context.Context, directory, externalID string) (sdk.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if externalID != "" && u.Directory == directory && u.ExternalID == externalID {
			return u.Clone(), nil
		}
	}
	return sdk.User{}, store.ErrNotFound
}

func (s *Store) ListUsers(_ context.Context, q store.ListUsersQuery) ([]sdk.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	search := strings.ToLower(q.Search)
	var out []sdk.User
	for _, id := range slices.Sorted(maps.Keys(s.users)) {
		u := s.users[id]
		switch {
		case q.After != "" && id <= q.After,
			q.Status != "" && u.Status != q.Status,
			search != "" && !strings.Contains(strings.ToLower(u.Email), search) &&
				!strings.Contains(strings.ToLower(u.Name), search):
			continue
		}
		out = append(out, u.Clone())
		if q.Limit > 0 && len(out) == q.Limit {
			break
		}
	}
	return out, nil
}

func (s *Store) ListMembershipsOfUser(_ context.Context, userID string) ([]sdk.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return membersOf(s.members, userID), nil
}

func membersOf(members map[string]sdk.Member, userID string) []sdk.Member {
	var out []sdk.Member
	for _, id := range slices.Sorted(maps.Keys(members)) {
		if m := members[id]; userID != "" && m.UserID == userID {
			out = append(out, m)
		}
	}
	return out
}

func (s *Store) GetCredentials(_ context.Context, userID string) (store.Credentials, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.users[userID]; !ok {
		return store.Credentials{}, store.ErrNotFound
	}
	return s.creds[userID], nil
}

func (s *Store) RecordLoginFailure(_ context.Context, userID string, maxFailures int, lockFor time.Duration, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return false, store.ErrNotFound
	}
	c := s.creds[userID]
	c.FailedLogins++
	locked := false
	if maxFailures > 0 && c.FailedLogins >= maxFailures {
		until := now.Add(lockFor)
		c.LockedUntil, c.FailedLogins, locked = &until, 0, true
	}
	s.creds[userID] = c
	return locked, nil
}

func (s *Store) RecordLoginSuccess(_ context.Context, userID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return store.ErrNotFound
	}
	c := s.creds[userID]
	c.FailedLogins, c.LockedUntil = 0, nil
	s.creds[userID] = c
	u.LastLoginAt = &now
	s.users[userID] = u
	return nil
}

func (s *Store) CreateActionToken(_ context.Context, t store.ActionToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.actions[t.Hash]; ok {
		return store.ErrAlreadyExists
	}
	s.actions[t.Hash] = actionToken{ActionToken: t}
	return nil
}

func (s *Store) ConsumeActionToken(_ context.Context, hash, kind string, now time.Time) (store.ActionToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.actions[hash]
	if !ok || t.used || t.Kind != kind || !now.Before(t.ExpiresAt) {
		return store.ActionToken{}, store.ErrNotFound
	}
	t.used = true
	s.actions[hash] = t
	return t.ActionToken, nil
}

func (s *Store) CreateRefreshToken(_ context.Context, t store.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.refresh[t.Hash]; ok {
		return store.ErrAlreadyExists
	}
	s.refresh[t.Hash] = refreshToken{RefreshToken: t}
	return nil
}

func (s *Store) RotateRefreshToken(_ context.Context, oldHash string, next store.RefreshToken, now time.Time) (store.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.refresh[oldHash]
	if !ok || old.revoked || !now.Before(old.ExpiresAt) {
		return store.RefreshToken{}, store.ErrNotFound
	}
	if old.rotated {
		s.revokeFamily(old.Family)
		return store.RefreshToken{}, store.ErrTokenReused
	}
	old.rotated = true
	s.refresh[oldHash] = old
	next.Family, next.UserID, next.TenantID, next.ClientID = old.Family, old.UserID, old.TenantID, old.ClientID
	next.UserAgent, next.IP = cmp.Or(next.UserAgent, old.UserAgent), cmp.Or(next.IP, old.IP)
	s.refresh[next.Hash] = refreshToken{RefreshToken: next}
	return old.RefreshToken, nil
}

func (s *Store) revokeFamily(family string) {
	for h, t := range s.refresh {
		if t.Family == family {
			t.revoked = true
			s.refresh[h] = t
		}
	}
}

func (s *Store) RevokeRefreshToken(_ context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.refresh[hash]; ok {
		s.revokeFamily(t.Family)
	}
	return nil
}

func (s *Store) RevokeUserRefreshTokens(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, t := range s.refresh {
		if t.UserID == userID {
			t.revoked = true
			s.refresh[h] = t
		}
	}
	return nil
}

func (s *Store) ListSigningKeys(context.Context) ([]store.SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.keys), nil
}

func (s *Store) AddSigningKey(_ context.Context, k store.SigningKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.keys {
		if e.ID == k.ID {
			return store.ErrAlreadyExists
		}
	}
	s.keys = append(s.keys, k)
	return nil
}

// forgetUsers drops tokens of deleted users; called on commit with the lock
// held.
func (s *Store) forgetUsers(ids []string) {
	for _, id := range ids {
		for h, t := range s.refresh {
			if t.UserID == id {
				delete(s.refresh, h)
			}
		}
		delete(s.mfa, id)
		for k, c := range s.consents {
			if c.UserID == id {
				delete(s.consents, k)
			}
		}
		for k, c := range s.passkeys {
			if c.UserID == id {
				delete(s.passkeys, k)
			}
		}
		for h, t := range s.actions {
			if t.UserID == id {
				delete(s.actions, h)
			}
		}
	}
}

func (t *tx) ListMembersOfUser(_ context.Context, userID string) ([]sdk.Member, error) {
	return membersOf(t.members, userID), nil
}

func (t *tx) GetUser(_ context.Context, id string) (sdk.User, error) {
	u, ok := t.users[id]
	if !ok {
		return sdk.User{}, store.ErrNotFound
	}
	return u.Clone(), nil
}

func (t *tx) CreateUser(_ context.Context, u sdk.User) error {
	for _, e := range t.users {
		if e.ID == u.ID || strings.EqualFold(e.Email, u.Email) {
			return store.ErrAlreadyExists
		}
	}
	t.users[u.ID] = u.Clone()
	return nil
}

func (t *tx) UpdateUser(_ context.Context, u sdk.User, expectedVersion int64) error {
	cur, ok := t.users[u.ID]
	if !ok {
		return store.ErrNotFound
	}
	if cur.Version != expectedVersion {
		return store.ErrConflict
	}
	for _, e := range t.users {
		if e.ID != u.ID && strings.EqualFold(e.Email, u.Email) {
			return store.ErrAlreadyExists
		}
	}
	t.users[u.ID] = u.Clone()
	return nil
}

func (t *tx) DeleteUser(_ context.Context, id string) error {
	if _, ok := t.users[id]; !ok {
		return store.ErrNotFound
	}
	delete(t.users, id)
	delete(t.creds, id)
	t.deletedUsers = append(t.deletedUsers, id)
	return nil
}

func (t *tx) SetPasswordHash(_ context.Context, userID, hash string) error {
	if _, ok := t.users[userID]; !ok {
		return store.ErrNotFound
	}
	t.creds[userID] = store.Credentials{PasswordHash: hash}
	return nil
}

func (s *Store) DeleteSigningKey(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.keys, func(k store.SigningKey) bool { return k.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	s.keys = slices.Delete(s.keys, i, i+1)
	return nil
}

func (s *Store) ListSessions(_ context.Context, userID string, now time.Time) ([]store.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	started := map[string]time.Time{}
	for _, t := range s.refresh {
		if c, ok := started[t.Family]; !ok || t.CreatedAt.Before(c) {
			started[t.Family] = t.CreatedAt
		}
	}
	var out []store.Session
	for _, t := range s.refresh {
		if t.UserID != userID || t.revoked || t.rotated || !now.Before(t.ExpiresAt) {
			continue
		}
		out = append(out, store.Session{ID: t.Family, UserID: t.UserID, TenantID: t.TenantID, UserAgent: t.UserAgent,
			IP: t.IP, CreatedAt: started[t.Family], LastUsedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt})
	}
	slices.SortFunc(out, func(a, b store.Session) int { return b.LastUsedAt.Compare(a.LastUsedAt) })
	return out, nil
}

func (s *Store) RevokeSession(_ context.Context, userID, sessionID string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, t := range s.refresh {
		found = found || (t.Family == sessionID && t.UserID == userID && !t.revoked)
	}
	if !found {
		return store.ErrNotFound
	}
	s.revokeFamily(sessionID)
	return nil
}

func (s *Store) ReplaceSigningKeyPEM(_ context.Context, id string, old, next []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.keys, func(k store.SigningKey) bool { return k.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	if !bytes.Equal(s.keys[i].PrivatePEM, old) {
		return store.ErrConflict
	}
	s.keys[i].PrivatePEM = slices.Clone(next)
	return nil
}
