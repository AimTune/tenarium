package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"strings"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func (t *tx) PurgeTenantData(_ context.Context, tenantID string) error {
	maps.DeleteFunc(t.members, func(_ string, m sdk.Member) bool { return m.TenantID == tenantID })
	maps.DeleteFunc(t.apiKeys, func(_ string, k store.APIKey) bool { return k.TenantID == tenantID })
	maps.DeleteFunc(t.domains, func(_ string, d store.Domain) bool { return d.TenantID == tenantID })
	maps.DeleteFunc(t.schedule, func(_ string, a store.ScheduledAction) bool { return a.TenantID == tenantID })
	maps.DeleteFunc(t.roles, func(_ string, r store.TenantRole) bool { return r.TenantID == tenantID })
	maps.DeleteFunc(t.groups, func(_ string, g store.Group) bool { return g.TenantID == tenantID })
	before := len(t.webhooks)
	maps.DeleteFunc(t.webhooks, func(_ string, w store.Webhook) bool { return w.TenantID == tenantID })
	if len(t.webhooks) != before {
		t.webhookDeleted = true
	}
	// Not staged by transactions; the parent's write lock is held.
	maps.DeleteFunc(t.s.usage, func(_ string, u store.Usage) bool { return u.TenantID == tenantID })
	delete(t.s.sso, tenantID)
	return nil
}

func (s *Store) RedactEvents(_ context.Context, needle, replacement string) (int64, error) {
	if needle == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Replace inside JSON strings, so the data stays valid JSON.
	quoted, _ := json.Marshal(needle)
	inner := strings.Trim(string(quoted), `"`)
	repl, _ := json.Marshal(replacement)
	replInner := strings.Trim(string(repl), `"`)
	var n int64
	for i, e := range s.events {
		if bytes.Contains(e.Data, []byte(inner)) {
			s.events[i].Data = bytes.ReplaceAll(e.Data, []byte(inner), []byte(replInner))
			n++
		}
	}
	return n, nil
}
