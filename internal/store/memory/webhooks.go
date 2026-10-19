package memory

import (
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func cloneWebhook(w store.Webhook) store.Webhook {
	w.Types = slices.Clone(w.Types)
	return w
}

func (s *Store) GetWebhook(_ context.Context, id string) (store.Webhook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.webhooks[id]
	if !ok {
		return store.Webhook{}, store.ErrNotFound
	}
	return cloneWebhook(w), nil
}

func (s *Store) ListWebhooks(_ context.Context, tenantID string) ([]store.Webhook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.Webhook
	for _, id := range slices.Sorted(maps.Keys(s.webhooks)) {
		if w := s.webhooks[id]; w.TenantID == tenantID {
			out = append(out, cloneWebhook(w))
		}
	}
	return out, nil
}

func (s *Store) RecordWebhookResult(_ context.Context, id string, success bool, maxFailures int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.webhooks[id]
	if !ok {
		return false, store.ErrNotFound
	}
	disabled := false
	if success {
		w.Failures = 0
	} else {
		w.Failures++
		if maxFailures > 0 && w.Failures >= maxFailures && w.Enabled {
			w.Enabled, disabled = false, true
		}
	}
	s.webhooks[id] = w
	return disabled, nil
}

func (s *Store) AddWebhookDelivery(_ context.Context, d store.WebhookDelivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.webhooks[d.WebhookID]; !ok {
		return store.ErrNotFound
	}
	if _, ok := s.deliveries[d.ID]; ok {
		return store.ErrAlreadyExists
	}
	d.Payload = slices.Clone(d.Payload)
	s.deliveries[d.ID] = d
	return nil
}

func (s *Store) GetWebhookDelivery(_ context.Context, id string) (store.WebhookDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.deliveries[id]
	if !ok {
		return store.WebhookDelivery{}, store.ErrNotFound
	}
	return d, nil
}

func (s *Store) ListWebhookDeliveries(_ context.Context, webhookID, beforeID string, limit int) ([]store.WebhookDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.WebhookDelivery
	for _, d := range s.deliveries {
		if d.WebhookID == webhookID && (beforeID == "" || d.ID < beforeID) {
			out = append(out, d)
		}
	}
	slices.SortFunc(out, func(a, b store.WebhookDelivery) int { return strings.Compare(b.ID, a.ID) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) PruneWebhookDeliveries(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, d := range s.deliveries {
		if d.CreatedAt.Before(before) {
			delete(s.deliveries, id)
			n++
		}
	}
	return n, nil
}

func (t *tx) CreateWebhook(_ context.Context, w store.Webhook) error {
	if _, ok := t.webhooks[w.ID]; ok {
		return store.ErrAlreadyExists
	}
	t.webhooks[w.ID] = cloneWebhook(w)
	return nil
}

func (t *tx) UpdateWebhook(_ context.Context, w store.Webhook) error {
	if _, ok := t.webhooks[w.ID]; !ok {
		return store.ErrNotFound
	}
	t.webhooks[w.ID] = cloneWebhook(w)
	return nil
}

func (t *tx) DeleteWebhook(_ context.Context, id string) error {
	if _, ok := t.webhooks[id]; !ok {
		return store.ErrNotFound
	}
	delete(t.webhooks, id)
	t.webhookDeleted = true
	return nil
}

// dropOrphanDeliveries removes deliveries of deleted webhooks; called on
// commit with the lock held.
func (s *Store) dropOrphanDeliveries() {
	for id, d := range s.deliveries {
		if _, ok := s.webhooks[d.WebhookID]; !ok {
			delete(s.deliveries, id)
		}
	}
}
