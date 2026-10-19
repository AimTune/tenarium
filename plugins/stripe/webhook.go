package stripe

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

// SignatureTolerance is how old a webhook timestamp may be.
const SignatureTolerance = 5 * time.Minute

// maxWebhookBody bounds webhook payloads.
const maxWebhookBody = 1 << 20

// ReasonPrefix starts the status reason of tenants suspended by this
// plugin. Only such tenants are resumed on payment.
const ReasonPrefix = "billing: "

// Webhook event types the plugin acts on.
const (
	evSubCreated   = "customer.subscription.created"
	evSubUpdated   = "customer.subscription.updated"
	evSubDeleted   = "customer.subscription.deleted"
	evInvoicePaid  = "invoice.paid"
	subscriptionEv = "customer.subscription."
)

var (
	errBadSignature = errors.New("invalid signature")
	errExpired      = errors.New("timestamp outside the tolerance")
)

// Sign returns a Stripe-Signature header value for payload, as Stripe
// computes it: v1 is the hex HMAC-SHA256 of "<timestamp>.<payload>" keyed
// with the whole signing secret.
func Sign(secret string, t time.Time, payload []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	return "t=" + ts + ",v1=" + signature(secret, ts, payload)
}

func signature(secret, ts string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks a Stripe-Signature header against payload. Any of
// several v1 signatures (sent while a secret is being rolled) may match.
func VerifySignature(payload []byte, header, secret string, now time.Time) error {
	var ts string
	var sigs []string
	for part := range strings.SplitSeq(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			ts = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	if ts == "" || len(sigs) == 0 {
		return fmt.Errorf("%w: missing timestamp or v1 signature", errBadSignature)
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: bad timestamp", errBadSignature)
	}
	if age := now.Sub(time.Unix(sec, 0)); age > SignatureTolerance || age < -SignatureTolerance {
		return errExpired
	}
	want := []byte(signature(secret, ts, payload))
	for _, s := range sigs {
		if hmac.Equal(want, []byte(s)) {
			return nil
		}
	}
	return errBadSignature
}

// event is a Stripe event.
type event struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Created int64  `json:"created"`
	Data    struct {
		Object             json.RawMessage            `json:"object"`
		PreviousAttributes map[string]json.RawMessage `json:"previous_attributes"`
	} `json:"data"`
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
	if err := VerifySignature(body, r.Header.Get("Stripe-Signature"), p.cfg.WebhookSecret, p.now()); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var ev event
	if err := json.Unmarshal(body, &ev); err != nil || ev.ID == "" || ev.Type == "" || len(ev.Data.Object) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid event payload"})
		return
	}
	if p.seen.has(ev.ID) {
		writeJSON(w, http.StatusOK, map[string]any{"received": true, "duplicate": true})
		return
	}
	if err := p.handleEvent(r.Context(), ev); err != nil {
		p.log.Error("stripe webhook failed", "event", ev.ID, "type", ev.Type, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	p.seen.add(ev.ID)
	writeJSON(w, http.StatusOK, map[string]any{"received": true})
}

// handleEvent applies one verified event. Unknown types are ignored.
func (p *Plugin) handleEvent(ctx context.Context, ev event) error {
	switch {
	case strings.HasPrefix(ev.Type, subscriptionEv):
		return p.onSubscription(ctx, ev)
	case p.suspendOn[ev.Type]:
		var obj struct {
			Metadata map[string]string `json:"metadata"`
			Customer json.RawMessage   `json:"customer"`
		}
		if err := json.Unmarshal(ev.Data.Object, &obj); err != nil {
			return fmt.Errorf("decode %s: %w", ev.Type, err)
		}
		t, ok, err := p.tenantFor(ctx, obj.Metadata, obj.Customer)
		if !ok {
			return err
		}
		return p.suspend(ctx, t, ReasonPrefix+ev.Type)
	case ev.Type == evInvoicePaid:
		return p.onInvoicePaid(ctx, ev)
	}
	return nil
}

func (p *Plugin) onSubscription(ctx context.Context, ev event) error {
	var s Subscription
	if err := json.Unmarshal(ev.Data.Object, &s); err != nil {
		return fmt.Errorf("decode subscription: %w", err)
	}
	if s.ID == "" {
		return nil
	}
	// Events arrive out of order; act on the subscription's current state.
	if cur, err := p.getSubscription(ctx, s.ID); err == nil {
		s = *cur
	} else if !isNotFound(err) {
		return err
	}
	t, ok, err := p.tenantFor(ctx, s.Metadata, s.Customer)
	if !ok {
		return err
	}
	if !t.IsLive() {
		return nil
	}
	_, mapped := p.planOf[s.price()]
	if !mapped && s.Metadata[MetadataTenantID] != t.ID {
		return nil // not a plan subscription, e.g. an add-on
	}

	priceChanged := ev.Type == evSubCreated || (ev.Type == evSubUpdated && hasAny(ev.Data.PreviousAttributes, "items", "plan"))
	if enabled(p.cfg.SyncPlanFromStripe) && priceChanged && s.live() {
		if t, err = p.syncPlan(ctx, t, s); err != nil {
			return err
		}
	}

	healthy := s.Status == "active" || s.Status == "trialing"
	switch {
	case p.suspendOn[ev.Type]:
		if healthy {
			return nil // recovered since the event was sent
		}
		if ev.Type == evSubDeleted {
			if other, err := p.healthyPlanSubscription(ctx, t.ID, s); err != nil || other {
				return err
			}
		}
		return p.suspend(ctx, t, ReasonPrefix+ev.Type)
	case s.Status == "past_due" || s.Status == "unpaid":
		if p.cfg.SuspendOnPastDue {
			return p.suspend(ctx, t, ReasonPrefix+ev.Type+" ("+s.Status+")")
		}
	case healthy:
		if enabled(p.cfg.ResumeOnPayment) {
			return p.resume(ctx, t)
		}
	}
	return nil
}

// healthyPlanSubscription reports whether the subscription's customer has
// another active plan subscription, e.g. after switching via Checkout.
func (p *Plugin) healthyPlanSubscription(ctx context.Context, tenantID string, s Subscription) (bool, error) {
	cid := idOf(s.Customer)
	if cid == "" {
		return false, nil
	}
	subs, err := p.liveSubscriptions(ctx, cid)
	if err != nil {
		return false, err
	}
	for _, o := range p.planSubscriptions(tenantID, subs) {
		if o.ID != s.ID && (o.Status == "active" || o.Status == "trialing") {
			return true, nil
		}
	}
	return false, nil
}

// syncPlan moves the tenant to the plan mapped to the subscription's price.
// When the change came from Tenarium the plans already match and nothing
// happens.
func (p *Plugin) syncPlan(ctx context.Context, t sdk.Tenant, s Subscription) (sdk.Tenant, error) {
	var plan string
	for _, it := range s.Items.Data {
		if plan = p.planOf[it.Price.ID]; plan != "" {
			break
		}
	}
	if plan == "" || plan == t.Plan {
		return t, nil
	}
	if _, err := p.host.GetPlan(ctx, plan); errors.Is(err, sdk.ErrNotFound) {
		p.log.Warn("plan mapped to a Stripe price does not exist", "plan", plan, "tenant", t.ID)
		return t, nil
	} else if err != nil {
		return t, err
	}
	nt, err := p.host.SetTenantPlan(ctx, t.ID, plan)
	if _, rejected := sdk.IsReject(err); rejected {
		p.log.Warn("plan change from Stripe rejected", "tenant", t.ID, "plan", plan, "err", err)
		return t, nil
	} else if err != nil {
		return t, err
	}
	p.log.Info("plan changed from Stripe", "tenant", t.ID, "from", t.Plan, "to", plan, "subscription", s.ID)
	return nt, nil
}

func (p *Plugin) onInvoicePaid(ctx context.Context, ev event) error {
	if !enabled(p.cfg.ResumeOnPayment) {
		return nil
	}
	var inv struct {
		Customer     json.RawMessage `json:"customer"`
		Subscription json.RawMessage `json:"subscription"`
		Parent       struct {
			SubscriptionDetails struct {
				Subscription json.RawMessage   `json:"subscription"`
				Metadata     map[string]string `json:"metadata"`
			} `json:"subscription_details"`
		} `json:"parent"`
	}
	if err := json.Unmarshal(ev.Data.Object, &inv); err != nil {
		return fmt.Errorf("decode invoice: %w", err)
	}
	t, ok, err := p.tenantFor(ctx, inv.Parent.SubscriptionDetails.Metadata, inv.Customer)
	if !ok {
		return err
	}
	if t.Status != sdk.StatusSuspended || !strings.HasPrefix(t.StatusReason, ReasonPrefix) {
		return nil
	}
	subID := idOf(inv.Subscription)
	if subID == "" {
		subID = idOf(inv.Parent.SubscriptionDetails.Subscription)
	}
	if subID != "" {
		// Paying one invoice does not end dunning if others are still open.
		s, err := p.getSubscription(ctx, subID)
		if err != nil && !isNotFound(err) {
			return err
		}
		if s != nil && s.Status != "active" && s.Status != "trialing" {
			return nil
		}
	}
	return p.resume(ctx, t)
}

// tenantFor resolves the tenant of a Stripe object from its metadata or its
// customer's. ok is false when the object belongs to no (known) tenant.
func (p *Plugin) tenantFor(ctx context.Context, meta map[string]string, customer json.RawMessage) (t sdk.Tenant, ok bool, err error) {
	id := meta[MetadataTenantID]
	if id == "" {
		cid := idOf(customer)
		if cid == "" {
			return t, false, nil
		}
		c, err := p.getCustomer(ctx, cid)
		if isNotFound(err) {
			return t, false, nil
		} else if err != nil {
			return t, false, err
		}
		if id = c.Metadata[MetadataTenantID]; id == "" {
			return t, false, nil
		}
	}
	t, err = p.host.GetTenant(ctx, id)
	if errors.Is(err, sdk.ErrNotFound) {
		p.log.Warn("Stripe object refers to an unknown tenant", "tenant", id)
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

// idOf returns the ID of a Stripe reference, which is either an ID string
// or an expanded object.
func idOf(raw json.RawMessage) string {
	var id string
	if json.Unmarshal(raw, &id) == nil {
		return id
	}
	var obj struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &obj)
	return obj.ID
}

func hasAny(m map[string]json.RawMessage, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// seenSet remembers the last n webhook event IDs, since Stripe may deliver
// an event more than once.
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
