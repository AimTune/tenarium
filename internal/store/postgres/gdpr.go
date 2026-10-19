package postgres

import (
	"context"
	"encoding/json"
	"strings"
)

func (t *tx) PurgeTenantData(ctx context.Context, tenantID string) error {
	if !isUUID(tenantID) {
		return nil
	}
	// Children before parents (webhook deliveries and SSO domains cascade).
	for _, table := range []string{
		"members", "usage", "api_keys", "domains", "webhooks", "sso_connections",
		"tenant_groups", "tenant_roles", "scheduled_actions",
	} {
		if _, err := t.q.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = $1`, tenantID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) RedactEvents(ctx context.Context, needle, replacement string) (int64, error) {
	if needle == "" {
		return 0, nil
	}
	// Replace inside JSON strings, so the data stays valid JSON.
	q, _ := json.Marshal(needle)
	r, _ := json.Marshal(replacement)
	inner, replInner := strings.Trim(string(q), `"`), strings.Trim(string(r), `"`)
	tag, err := s.pool.Exec(ctx, `UPDATE events SET data = replace(data::text, $1, $2)::jsonb
		WHERE data IS NOT NULL AND strpos(data::text, $1) > 0`, inner, replInner)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
