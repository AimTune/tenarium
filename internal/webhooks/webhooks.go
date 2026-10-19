// Package webhooks delivers a tenant's events to HTTP endpoints the tenant
// registered itself (self-service webhooks), with Standard Webhooks
// signatures, retries, a delivery log and automatic disabling of failing
// endpoints. Platform-wide delivery is the webhook plugin's job.
package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/events"
	"github.com/AimTune/tenarium/internal/netguard"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// Event types emitted about webhooks themselves.
const (
	EventCreated  = "webhook.created"
	EventUpdated  = "webhook.updated"
	EventDeleted  = "webhook.deleted"
	EventDisabled = "webhook.disabled"
	// EventTest is the type of test deliveries ("ping").
	EventTest = "webhook.test"
)

// SubscriptionName is the dispatcher subscription delivering tenant
// webhooks.
const SubscriptionName = "core/tenant-webhooks"

// Config tunes delivery.
type Config struct {
	// Timeout per HTTP request.
	Timeout time.Duration
	// Attempts per event and endpoint before the delivery counts as
	// failed.
	Attempts int
	// MaxFailures disables an endpoint after that many consecutive failed
	// events (0: never).
	MaxFailures int
	// MaxPerTenant caps the endpoints of one tenant.
	MaxPerTenant int
	// AllowHTTP permits plain-http URLs; AllowPrivateNetworks permits
	// endpoints on loopback/private addresses. Both are for development:
	// tenants must not reach the platform's internal network.
	AllowHTTP            bool
	AllowPrivateNetworks bool
	// DeliveryRetention is how long delivery logs are kept.
	DeliveryRetention time.Duration
}

func (c *Config) defaults() {
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Attempts <= 0 {
		c.Attempts = 3
	}
	if c.MaxPerTenant <= 0 {
		c.MaxPerTenant = 10
	}
	if c.DeliveryRetention <= 0 {
		c.DeliveryRetention = 30 * 24 * time.Hour
	}
}

// Recorder appends events (tenant.Service implements it).
type Recorder interface {
	RecordEvent(ctx context.Context, typ, tenantID, subject string, payload any) error
}

type Service struct {
	store   store.Store
	events  Recorder
	cfg     Config
	log     *slog.Logger
	sender  *sender
	now     func() time.Time
	backoff time.Duration
}

func New(s store.Store, rec Recorder, cfg Config, log *slog.Logger) *Service {
	cfg.defaults()
	return &Service{
		store: s, events: rec, cfg: cfg, log: log,
		sender:  newSender(cfg),
		now:     func() time.Time { return time.Now().UTC() },
		backoff: time.Second,
	}
}

// ValidationError reports invalid input (mapped to 400 by the API).
type ValidationError struct{ Field, Message string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Message }

// Input creates or updates a webhook; nil fields are left unchanged on
// update.
type Input struct {
	URL         *string   `json:"url,omitempty"`
	Description *string   `json:"description,omitempty"`
	Types       *[]string `json:"types,omitempty"`
	Enabled     *bool     `json:"enabled,omitempty"`
}

func (s *Service) validate(w store.Webhook) error {
	u, err := url.Parse(w.URL)
	switch {
	case err != nil || u.Host == "" || u.User != nil:
		return &ValidationError{"url", "must be an absolute URL without credentials"}
	case u.Scheme != "https" && !(u.Scheme == "http" && s.cfg.AllowHTTP):
		return &ValidationError{"url", "must use https"}
	case len(w.URL) > 2048:
		return &ValidationError{"url", "too long"}
	case len(w.Description) > 500:
		return &ValidationError{"description", "too long"}
	case len(w.Types) > 50:
		return &ValidationError{"types", "too many patterns"}
	}
	if !s.cfg.AllowPrivateNetworks {
		if err := netguard.CheckHost(u.Hostname()); err != nil {
			return &ValidationError{"url", err.Error()}
		}
	}
	for _, p := range w.Types {
		if _, err := path.Match(p, ""); err != nil || p == "" {
			return &ValidationError{"types", fmt.Sprintf("invalid pattern %q", p)}
		}
	}
	return nil
}

// NewSecret returns a Standard Webhooks secret ("whsec_" + base64).
func NewSecret() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "whsec_" + base64.StdEncoding.EncodeToString(b)
}

func secretBytes(s string) []byte {
	if b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "whsec_")); err == nil {
		return b
	}
	return []byte(s)
}

// Sign computes the Standard Webhooks signature over "id.timestamp.body".
func Sign(secret, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secretBytes(secret))
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Create registers a webhook and returns it with its secret, which is only
// shown now.
func (s *Service) Create(ctx context.Context, tenantID string, in Input) (store.Webhook, string, error) {
	existing, err := s.store.ListWebhooks(ctx, tenantID)
	if err != nil {
		return store.Webhook{}, "", err
	}
	if len(existing) >= s.cfg.MaxPerTenant {
		return store.Webhook{}, "", &ValidationError{"url", fmt.Sprintf("a tenant can have at most %d webhooks", s.cfg.MaxPerTenant)}
	}
	now := s.now()
	w := store.Webhook{ID: uuid.Must(uuid.NewV7()).String(), TenantID: tenantID, Secret: NewSecret(), Enabled: true, CreatedAt: now, UpdatedAt: now}
	if in.URL == nil {
		return store.Webhook{}, "", &ValidationError{"url", "required"}
	}
	apply(&w, in)
	if err := s.validate(w); err != nil {
		return store.Webhook{}, "", err
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error { return tx.CreateWebhook(ctx, w) })
	if err != nil {
		return store.Webhook{}, "", err
	}
	return w, w.Secret, s.record(ctx, EventCreated, w)
}

func apply(w *store.Webhook, in Input) {
	if in.URL != nil {
		w.URL = strings.TrimSpace(*in.URL)
	}
	if in.Description != nil {
		w.Description = *in.Description
	}
	if in.Types != nil {
		w.Types = slices.Clone(*in.Types)
		if len(w.Types) == 0 {
			w.Types = nil
		}
	}
	if in.Enabled != nil {
		w.Enabled = *in.Enabled
	}
}

// Get returns a webhook of the tenant.
func (s *Service) Get(ctx context.Context, tenantID, id string) (store.Webhook, error) {
	w, err := s.store.GetWebhook(ctx, id)
	if err != nil || w.TenantID != tenantID {
		return store.Webhook{}, store.ErrNotFound
	}
	return w, nil
}

func (s *Service) List(ctx context.Context, tenantID string) ([]store.Webhook, error) {
	return s.store.ListWebhooks(ctx, tenantID)
}

// Update changes a webhook. Re-enabling resets its failure counter.
func (s *Service) Update(ctx context.Context, tenantID, id string, in Input) (store.Webhook, error) {
	w, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return w, err
	}
	wasEnabled := w.Enabled
	apply(&w, in)
	if w.Enabled && !wasEnabled {
		w.Failures = 0
	}
	if err := s.validate(w); err != nil {
		return store.Webhook{}, err
	}
	w.UpdatedAt = s.now()
	if err := s.store.InTx(ctx, func(tx store.Tx) error { return tx.UpdateWebhook(ctx, w) }); err != nil {
		return store.Webhook{}, err
	}
	return w, s.record(ctx, EventUpdated, w)
}

// RotateSecret replaces the signing secret and returns the new one.
func (s *Service) RotateSecret(ctx context.Context, tenantID, id string) (string, error) {
	w, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return "", err
	}
	w.Secret, w.UpdatedAt = NewSecret(), s.now()
	if err := s.store.InTx(ctx, func(tx store.Tx) error { return tx.UpdateWebhook(ctx, w) }); err != nil {
		return "", err
	}
	return w.Secret, s.record(ctx, EventUpdated, w)
}

func (s *Service) Delete(ctx context.Context, tenantID, id string) error {
	w, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.store.InTx(ctx, func(tx store.Tx) error { return tx.DeleteWebhook(ctx, w.ID) }); err != nil {
		return err
	}
	return s.record(ctx, EventDeleted, w)
}

func (s *Service) record(ctx context.Context, typ string, w store.Webhook) error {
	return s.events.RecordEvent(ctx, typ, w.TenantID, "webhooks/"+w.ID, w)
}

// Deliveries lists a webhook's delivery log, newest first.
func (s *Service) Deliveries(ctx context.Context, tenantID, id, beforeID string, limit int) ([]store.WebhookDelivery, error) {
	if _, err := s.Get(ctx, tenantID, id); err != nil {
		return nil, err
	}
	return s.store.ListWebhookDeliveries(ctx, id, beforeID, limit)
}

// Redeliver sends a logged delivery's payload again (same webhook-id, so
// receivers can deduplicate) and logs the new attempt.
func (s *Service) Redeliver(ctx context.Context, tenantID, id, deliveryID string) (store.WebhookDelivery, error) {
	w, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return store.WebhookDelivery{}, err
	}
	d, err := s.store.GetWebhookDelivery(ctx, deliveryID)
	if err != nil || d.WebhookID != w.ID {
		return store.WebhookDelivery{}, store.ErrNotFound
	}
	return s.send(ctx, w, d.EventID, d.EventType, d.Payload, 1)
}

// Test sends a webhook.test event once, whether or not the webhook is
// enabled, and returns the logged result.
func (s *Service) Test(ctx context.Context, tenantID, id string) (store.WebhookDelivery, error) {
	w, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return store.WebhookDelivery{}, err
	}
	e := sdk.Event{
		ID: uuid.Must(uuid.NewV7()).String(), Type: EventTest, Source: "tenarium", TenantID: tenantID,
		Subject: "webhooks/" + w.ID, Time: s.now(), Data: json.RawMessage(`{"message":"test delivery"}`),
	}
	body, err := json.Marshal(e.CloudEvent())
	if err != nil {
		return store.WebhookDelivery{}, err
	}
	return s.send(ctx, w, e.ID, e.Type, body, 1)
}

// Subscription delivers committed events to the webhooks of their tenant.
func (s *Service) Subscription() events.Subscription {
	return events.Subscription{
		Name:    SubscriptionName,
		Handler: s.handle,
		// History before the feature was enabled is not sent.
		Options: sdk.SubscribeOptions{MaxAttempts: 5, StartAtEnd: true},
	}
}

func (s *Service) handle(ctx context.Context, e sdk.Event) error {
	if e.TenantID == "" {
		return nil
	}
	hooks, err := s.store.ListWebhooks(ctx, e.TenantID)
	if err != nil {
		return err
	}
	var targets []store.Webhook
	for _, w := range hooks {
		if w.Enabled && (sdk.EventFilter{Types: w.Types}).Match(e) {
			targets = append(targets, w)
		}
	}
	if len(targets) == 0 {
		return nil
	}
	body, err := json.Marshal(e.CloudEvent())
	if err != nil {
		return err
	}
	// Endpoints are independent: one slow or failing endpoint must not
	// delay or duplicate deliveries to the others, so failures are logged
	// rather than returned (which would make the dispatcher retry all).
	errs := make(chan error, len(targets))
	for _, w := range targets {
		go func() {
			d, err := s.send(ctx, w, e.ID, e.Type, body, s.cfg.Attempts)
			if err == nil {
				err = s.result(ctx, w, d.Success)
			}
			errs <- err
		}()
	}
	var all []error
	for range targets {
		all = append(all, <-errs)
	}
	return errors.Join(all...)
}

// result updates the failure counter and announces auto-disabling.
func (s *Service) result(ctx context.Context, w store.Webhook, ok bool) error {
	disabled, err := s.store.RecordWebhookResult(ctx, w.ID, ok, s.cfg.MaxFailures)
	if errors.Is(err, store.ErrNotFound) {
		return nil // deleted meanwhile
	}
	if err != nil || !disabled {
		return err
	}
	s.log.Warn("webhook disabled after repeated failures", "webhook", w.ID, "tenant", w.TenantID, "url", w.URL)
	w.Enabled = false
	return s.record(ctx, EventDisabled, w)
}

// send POSTs body up to attempts times and logs the outcome.
func (s *Service) send(ctx context.Context, w store.Webhook, eventID, eventType string, body []byte, attempts int) (store.WebhookDelivery, error) {
	d := store.WebhookDelivery{
		ID: uuid.Must(uuid.NewV7()).String(), WebhookID: w.ID, TenantID: w.TenantID,
		EventID: eventID, EventType: eventType, Payload: body, CreatedAt: s.now(),
	}
	start := time.Now()
	for d.Attempts < attempts {
		if d.Attempts > 0 {
			select {
			case <-ctx.Done():
				return d, ctx.Err()
			case <-time.After(s.backoff * time.Duration(1<<(d.Attempts-1))):
			}
		}
		d.Attempts++
		ts := fmt.Sprint(s.now().Unix())
		d.StatusCode, d.Error = s.sender.post(ctx, w.URL, map[string]string{
			"webhook-id":        eventID,
			"webhook-timestamp": ts,
			"webhook-signature": "v1," + Sign(w.Secret, eventID, ts, body),
		}, body)
		if d.Success = d.Error == ""; d.Success {
			break
		}
	}
	d.DurationMS = time.Since(start).Milliseconds()
	if err := s.store.AddWebhookDelivery(ctx, d); err != nil && !errors.Is(err, store.ErrNotFound) {
		return d, err
	}
	return d, nil
}

// PruneDeliveries drops delivery logs older than the retention.
func (s *Service) PruneDeliveries(ctx context.Context) (int64, error) {
	return s.store.PruneWebhookDeliveries(ctx, s.now().Add(-s.cfg.DeliveryRetention))
}

// RunPruner prunes delivery logs hourly until ctx ends.
func (s *Service) RunPruner(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		if _, err := s.PruneDeliveries(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("pruning webhook deliveries failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
