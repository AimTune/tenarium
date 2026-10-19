package postgres

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/jackc/pgx/v5"
)

const webhookCols = `id::text, tenant_id::text, url, description, secret, types, enabled, failures, created_at, updated_at`

func scanWebhook(row pgx.Row) (store.Webhook, error) {
	var w store.Webhook
	if err := row.Scan(&w.ID, &w.TenantID, &w.URL, &w.Description, &w.Secret, &w.Types, &w.Enabled, &w.Failures,
		&w.CreatedAt, &w.UpdatedAt); err != nil {
		return store.Webhook{}, mapErr(err)
	}
	if len(w.Types) == 0 {
		w.Types = nil
	}
	w.CreatedAt, w.UpdatedAt = w.CreatedAt.UTC(), w.UpdatedAt.UTC()
	return w, nil
}

func (s *Store) GetWebhook(ctx context.Context, id string) (store.Webhook, error) {
	if !isUUID(id) {
		return store.Webhook{}, store.ErrNotFound
	}
	return scanWebhook(s.pool.QueryRow(ctx, `SELECT `+webhookCols+` FROM webhooks WHERE id = $1`, id))
}

func (s *Store) ListWebhooks(ctx context.Context, tenantID string) ([]store.Webhook, error) {
	if !isUUID(tenantID) {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+webhookCols+` FROM webhooks WHERE tenant_id = $1 ORDER BY id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Webhook
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) RecordWebhookResult(ctx context.Context, id string, success bool, maxFailures int) (bool, error) {
	if !isUUID(id) {
		return false, store.ErrNotFound
	}
	var wasEnabled, enabled bool
	err := s.pool.QueryRow(ctx, `
		WITH prev AS (SELECT enabled FROM webhooks WHERE id = $1 FOR UPDATE)
		UPDATE webhooks w SET
			failures = CASE WHEN $2 THEN 0 ELSE w.failures + 1 END,
			enabled = w.enabled AND ($2 OR $3 <= 0 OR w.failures + 1 < $3)
		FROM prev WHERE w.id = $1
		RETURNING prev.enabled, w.enabled`, id, success, maxFailures).Scan(&wasEnabled, &enabled)
	if err != nil {
		return false, mapErr(err)
	}
	return wasEnabled && !enabled, nil
}

func (s *Store) AddWebhookDelivery(ctx context.Context, d store.WebhookDelivery) error {
	var payload any
	if len(d.Payload) > 0 {
		payload = string(d.Payload)
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO webhook_deliveries
		(id, webhook_id, tenant_id, event_id, event_type, payload, attempts, status_code, error, success, duration_ms, created_at)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12)`,
		d.ID, d.WebhookID, d.TenantID, d.EventID, d.EventType, payload, d.Attempts, d.StatusCode, d.Error, d.Success, d.DurationMS, d.CreatedAt)
	if isFKViolation(err) {
		return store.ErrNotFound
	}
	return mapErr(err)
}

const deliveryCols = `id::text, webhook_id::text, tenant_id::text, event_id, event_type, payload, attempts, status_code, error, success, duration_ms, created_at`

func scanDelivery(row pgx.Row) (store.WebhookDelivery, error) {
	var (
		d       store.WebhookDelivery
		payload []byte
	)
	if err := row.Scan(&d.ID, &d.WebhookID, &d.TenantID, &d.EventID, &d.EventType, &payload, &d.Attempts, &d.StatusCode,
		&d.Error, &d.Success, &d.DurationMS, &d.CreatedAt); err != nil {
		return store.WebhookDelivery{}, mapErr(err)
	}
	if len(payload) > 0 {
		d.Payload = json.RawMessage(payload)
	}
	d.CreatedAt = d.CreatedAt.UTC()
	return d, nil
}

func (s *Store) GetWebhookDelivery(ctx context.Context, id string) (store.WebhookDelivery, error) {
	if !isUUID(id) {
		return store.WebhookDelivery{}, store.ErrNotFound
	}
	return scanDelivery(s.pool.QueryRow(ctx, `SELECT `+deliveryCols+` FROM webhook_deliveries WHERE id = $1`, id))
}

func (s *Store) ListWebhookDeliveries(ctx context.Context, webhookID, beforeID string, limit int) ([]store.WebhookDelivery, error) {
	if !isUUID(webhookID) || (beforeID != "" && !isUUID(beforeID)) {
		return nil, nil
	}
	q := `SELECT ` + deliveryCols + ` FROM webhook_deliveries WHERE webhook_id = $1`
	args := []any{webhookID}
	if beforeID != "" {
		q += ` AND id < $2`
		args = append(args, beforeID)
	}
	q += ` ORDER BY id DESC`
	if limit > 0 {
		args = append(args, limit)
		q += ` LIMIT $` + strconv.Itoa(len(args))
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.WebhookDelivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) PruneWebhookDeliveries(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM webhook_deliveries WHERE created_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (t *tx) CreateWebhook(ctx context.Context, w store.Webhook) error {
	types := w.Types
	if types == nil {
		types = []string{}
	}
	_, err := t.q.Exec(ctx, `INSERT INTO webhooks (id, tenant_id, url, description, secret, types, enabled, failures, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		w.ID, w.TenantID, w.URL, w.Description, w.Secret, types, w.Enabled, w.Failures, w.CreatedAt, w.UpdatedAt)
	return mapErr(err)
}

func (t *tx) UpdateWebhook(ctx context.Context, w store.Webhook) error {
	types := w.Types
	if types == nil {
		types = []string{}
	}
	tag, err := t.q.Exec(ctx, `UPDATE webhooks SET url = $2, description = $3, secret = $4, types = $5, enabled = $6,
		failures = $7, updated_at = $8 WHERE id = $1`,
		w.ID, w.URL, w.Description, w.Secret, types, w.Enabled, w.Failures, w.UpdatedAt)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (t *tx) DeleteWebhook(ctx context.Context, id string) error {
	if !isUUID(id) {
		return store.ErrNotFound
	}
	tag, err := t.q.Exec(ctx, `DELETE FROM webhooks WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}
