package paddle

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// SignatureTolerance is how old a notification timestamp may be.
const SignatureTolerance = 5 * time.Minute

// maxWebhookBody bounds notification payloads.
const maxWebhookBody = 1 << 20

// ReasonPrefix starts the status reason of tenants suspended by this
// plugin. Only such tenants are resumed on payment.
const ReasonPrefix = "billing: "

// Notification event types the plugin acts on.
const (
	evSubCanceled          = "subscription.canceled"
	evSubPaused            = "subscription.paused"
	evSubPastDue           = "subscription.past_due"
	evTransactionCompleted = "transaction.completed"
	subscriptionEv         = "subscription."
)

var (
	errBadSignature = errors.New("invalid signature")
	errExpired      = errors.New("timestamp outside the tolerance")
)

// Sign returns a Paddle-Signature header value for body, as Paddle
// computes it: h1 is the hex HMAC-SHA256 of "<timestamp>:<body>" keyed with
// the destination's secret key.
func Sign(secret string, t time.Time, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	return "ts=" + ts + ";h1=" + signature(secret, ts, body)
}

func signature(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte(":"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks a Paddle-Signature header against body. Any of
// several h1 signatures (sent while a secret key is being rotated) may
// match.
func VerifySignature(body []byte, header, secret string, now time.Time) error {
	var ts string
	var sigs []string
	for part := range strings.SplitSeq(header, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "ts":
			ts = v
		case "h1":
			sigs = append(sigs, v)
		}
	}
	if ts == "" || len(sigs) == 0 {
		return fmt.Errorf("%w: missing timestamp or h1 signature", errBadSignature)
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: bad timestamp", errBadSignature)
	}
	if age := now.Sub(time.Unix(sec, 0)); age > SignatureTolerance || age < -SignatureTolerance {
		return errExpired
	}
	want := []byte(signature(secret, ts, body))
	for _, s := range sigs {
		if hmac.Equal(want, []byte(s)) {
			return nil
		}
	}
	return errBadSignature
}

// notification is a Paddle webhook notification.
type notification struct {
	EventID        string          `json:"event_id"`
	EventType      string          `json:"event_type"`
	OccurredAt     string          `json:"occurred_at"`
	NotificationID string          `json:"notification_id"`
	Data           json.RawMessage `json:"data"`
}

func (p *Plugin) webhook(w http.ResponseWriter, r *http.Request) {
	if n := p.next.Load(); n != nil {
		n.webhook(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot read body: " + err.Error()})
		return
	}
	if err := VerifySignature(body, r.Header.Get("Paddle-Signature"), p.cfg.WebhookSecret, p.now()); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var n notification
	if err := json.Unmarshal(body, &n); err != nil || n.EventID == "" || n.EventType == "" || len(n.Data) == 0 || n.Data[0] != '{' {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid notification payload"})
		return
	}
	if p.seen.has(n.EventID) {
		writeJSON(w, http.StatusOK, map[string]any{"received": true, "duplicate": true})
		return
	}
	if err := p.handleEvent(r.Context(), n); err != nil {
		p.log.Error("paddle webhook failed", "event", n.EventID, "type", n.EventType, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	p.seen.add(n.EventID)
	writeJSON(w, http.StatusOK, map[string]any{"received": true})
}

// handleEvent applies one verified notification. Unknown types are ignored.
func (p *Plugin) handleEvent(ctx context.Context, n notification) error {
	switch {
	case strings.HasPrefix(n.EventType, subscriptionEv):
		return p.onSubscription(ctx, n)
	case p.suspendOn[n.EventType]:
		var obj struct {
			CustomData map[string]any `json:"custom_data"`
			CustomerID string         `json:"customer_id"`
		}
		if err := json.Unmarshal(n.Data, &obj); err != nil {
			return fmt.Errorf("decode %s: %w", n.EventType, err)
		}
		t, ok, err := p.tenantFor(ctx, obj.CustomData, obj.CustomerID)
		if !ok {
			return err
		}
		return p.suspend(ctx, t, ReasonPrefix+n.EventType)
	case n.EventType == evTransactionCompleted:
		return p.onTransactionCompleted(ctx, n)
	}
	return nil
}

func (p *Plugin) onSubscription(ctx context.Context, n notification) error {
	var s Subscription
	if err := json.Unmarshal(n.Data, &s); err != nil {
		return fmt.Errorf("decode subscription: %w", err)
	}
	if s.ID == "" {
		return nil
	}
	// Notifications arrive out of order; act on the subscription's current
	// state.
	if cur, err := p.getSubscription(ctx, s.ID); err == nil {
		s = *cur
	} else if !isNotFound(err) {
		return err
	}
	t, ok, err := p.tenantFor(ctx, s.CustomData, s.CustomerID)
	if !ok {
		return err
	}
	if !t.IsLive() {
		return nil
	}
	if p.mappedPlan(s) == "" && tenantIDOf(s.CustomData) != t.ID {
		return nil // not a plan subscription, e.g. an add-on
	}

	// Paddle notifications carry no previous values, so every live
	// subscription notification is checked; a change that came from
	// Tenarium already matches the tenant's plan.
	if enabled(p.cfg.SyncPlanFromPaddle) && s.live() {
		if t, err = p.syncPlan(ctx, t, s); err != nil {
			return err
		}
	}

	switch {
	case p.suspendOn[n.EventType]:
		if s.healthy() {
			return nil // recovered since the notification was sent
		}
		if n.EventType == evSubCanceled {
			if other, err := p.healthyPlanSubscription(ctx, t.ID, s); err != nil || other {
				return err
			}
		}
		return p.suspend(ctx, t, ReasonPrefix+n.EventType)
	case s.Status == "past_due":
		if p.cfg.SuspendOnPastDue {
			reason := ReasonPrefix + n.EventType
			if n.EventType != evSubPastDue {
				reason += " (past_due)"
			}
			return p.suspend(ctx, t, reason)
		}
	case s.healthy():
		if enabled(p.cfg.ResumeOnPayment) {
			return p.resume(ctx, t)
		}
	}
	return nil
}

// healthyPlanSubscription reports whether the subscription's customer has
// another active plan subscription, e.g. after switching via a checkout.
func (p *Plugin) healthyPlanSubscription(ctx context.Context, tenantID string, s Subscription) (bool, error) {
	if s.CustomerID == "" {
		return false, nil
	}
	subs, err := p.liveSubscriptions(ctx, s.CustomerID)
	if err != nil {
		return false, err
	}
	for _, o := range p.planSubscriptions(tenantID, subs) {
		if o.ID != s.ID && o.healthy() {
			return true, nil
		}
	}
	return false, nil
}

// syncPlan moves the tenant to the plan mapped to the subscription's price.
// When the change came from Tenarium the plans already match and nothing
// happens.
func (p *Plugin) syncPlan(ctx context.Context, t sdk.Tenant, s Subscription) (sdk.Tenant, error) {
	plan := p.mappedPlan(s)
	if plan == "" || plan == t.Plan {
		return t, nil
	}
	if _, err := p.host.GetPlan(ctx, plan); errors.Is(err, sdk.ErrNotFound) {
		p.log.Warn("plan mapped to a Paddle price does not exist", "plan", plan, "tenant", t.ID)
		return t, nil
	} else if err != nil {
		return t, err
	}
	nt, err := p.host.SetTenantPlan(ctx, t.ID, plan)
	if _, rejected := sdk.IsReject(err); rejected {
		p.log.Warn("plan change from Paddle rejected", "tenant", t.ID, "plan", plan, "err", err)
		return t, nil
	} else if err != nil {
		return t, err
	}
	p.log.Info("plan changed from Paddle", "tenant", t.ID, "from", t.Plan, "to", plan, "subscription", s.ID)
	return nt, nil
}

func (p *Plugin) onTransactionCompleted(ctx context.Context, n notification) error {
	if !enabled(p.cfg.ResumeOnPayment) {
		return nil
	}
	var tx struct {
		CustomerID     string         `json:"customer_id"`
		SubscriptionID string         `json:"subscription_id"`
		CustomData     map[string]any `json:"custom_data"`
	}
	if err := json.Unmarshal(n.Data, &tx); err != nil {
		return fmt.Errorf("decode transaction: %w", err)
	}
	var sub *Subscription
	if tx.SubscriptionID != "" {
		s, err := p.getSubscription(ctx, tx.SubscriptionID)
		if err != nil && !isNotFound(err) {
			return err
		}
		sub = s
	}
	cd := tx.CustomData
	if tenantIDOf(cd) == "" && sub != nil {
		cd = sub.CustomData
	}
	t, ok, err := p.tenantFor(ctx, cd, tx.CustomerID)
	if !ok {
		return err
	}
	// Paying one transaction does not end dunning if the subscription is
	// still past due.
	if sub != nil && !sub.healthy() {
		return nil
	}
	return p.resume(ctx, t)
}

// tenantFor resolves the tenant of a Paddle object from its custom_data or
// its customer's. ok is false when the object belongs to no (known) tenant.
func (p *Plugin) tenantFor(ctx context.Context, customData map[string]any, customerID string) (t sdk.Tenant, ok bool, err error) {
	id := tenantIDOf(customData)
	if id == "" {
		if customerID == "" {
			return t, false, nil
		}
		c, err := p.getCustomer(ctx, customerID)
		if isNotFound(err) {
			return t, false, nil
		} else if err != nil {
			return t, false, err
		}
		if id = tenantIDOf(c.CustomData); id == "" {
			return t, false, nil
		}
	}
	t, err = p.host.GetTenant(ctx, id)
	if errors.Is(err, sdk.ErrNotFound) {
		p.log.Warn("Paddle object refers to an unknown tenant", "tenant", id)
		return t, false, nil
	}
	return t, err == nil, err
}

// suspend suspends an active tenant on a billed plan for billing reasons.
func (p *Plugin) suspend(ctx context.Context, t sdk.Tenant, reason string) error {
	if t.Status != sdk.StatusActive {
		return nil
	}
	if p.priceFor(t.Plan) == "" {
		p.log.Info("not suspending a tenant on an unbilled plan", "tenant", t.ID, "plan", t.Plan, "reason", reason)
		return nil
	}
	_, err := p.host.SuspendTenant(ctx, t.ID, reason)
	if _, rejected := sdk.IsReject(err); rejected {
		p.log.Warn("billing suspension rejected", "tenant", t.ID, "err", err)
		return nil
	} else if err != nil {
		return err
	}
	p.log.Info("suspended tenant for billing", "tenant", t.ID, "reason", reason)
	return nil
}

// resume resumes a tenant this plugin suspended. Tenants suspended for
// other reasons stay suspended.
func (p *Plugin) resume(ctx context.Context, t sdk.Tenant) error {
	if t.Status != sdk.StatusSuspended || !strings.HasPrefix(t.StatusReason, ReasonPrefix) {
		return nil
	}
	_, err := p.host.ResumeTenant(ctx, t.ID)
	if _, rejected := sdk.IsReject(err); rejected {
		p.log.Warn("billing resume rejected", "tenant", t.ID, "err", err)
		return nil
	} else if err != nil {
		return err
	}
	p.log.Info("resumed tenant after payment", "tenant", t.ID)
	return nil
}

// seenSet remembers the last n notification event IDs, since Paddle may
// deliver a notification more than once.
type seenSet struct {
	mu   sync.Mutex
	ids  map[string]struct{}
	ring []string
	next int
}

func newSeenSet(n int) *seenSet {
	return &seenSet{ids: make(map[string]struct{}, n), ring: make([]string, n)}
}

func (s *seenSet) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.ids[id]
	return ok
}

func (s *seenSet) add(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ids[id]; ok {
		return
	}
	if old := s.ring[s.next]; old != "" {
		delete(s.ids, old)
	}
	s.ring[s.next] = id
	s.ids[id] = struct{}{}
	s.next = (s.next + 1) % len(s.ring)
}
