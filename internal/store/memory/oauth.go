package memory

import (
	"cmp"
	"context"
	"slices"

	"github.com/AimTune/tenarium/internal/store"
)

func cloneClient(c store.OAuthClient) store.OAuthClient {
	c.RedirectURIs, c.PostLogoutRedirectURIs, c.Scopes = slices.Clone(c.RedirectURIs), slices.Clone(c.PostLogoutRedirectURIs), slices.Clone(c.Scopes)
	return c
}

func (s *Store) GetOAuthClient(_ context.Context, id string) (store.OAuthClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.oauthClients[id]
	if !ok {
		return store.OAuthClient{}, store.ErrNotFound
	}
	return cloneClient(c), nil
}

func (s *Store) ListOAuthClients(_ context.Context) ([]store.OAuthClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]store.OAuthClient, 0, len(s.oauthClients))
	for _, c := range s.oauthClients {
		out = append(out, cloneClient(c))
	}
	slices.SortFunc(out, func(a, b store.OAuthClient) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

func (s *Store) PutOAuthClient(_ context.Context, c store.OAuthClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oauthClients[c.ID] = cloneClient(c)
	return nil
}

func (s *Store) DeleteOAuthClient(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.oauthClients[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.oauthClients, id)
	for k, c := range s.consents {
		if c.ClientID == id {
			delete(s.consents, k)
		}
	}
	return nil
}

func consentKey(userID, clientID string) string { return userID + "\x00" + clientID }

func (s *Store) GetOAuthConsent(_ context.Context, userID, clientID string) (store.OAuthConsent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.consents[consentKey(userID, clientID)]
	if !ok {
		return store.OAuthConsent{}, store.ErrNotFound
	}
	c.Scopes = slices.Clone(c.Scopes)
	return c, nil
}

func (s *Store) PutOAuthConsent(_ context.Context, c store.OAuthConsent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[c.UserID]; !ok {
		return store.ErrNotFound
	}
	if _, ok := s.oauthClients[c.ClientID]; !ok {
		return store.ErrNotFound
	}
	c.Scopes = slices.Clone(c.Scopes)
	s.consents[consentKey(c.UserID, c.ClientID)] = c
	return nil
}
