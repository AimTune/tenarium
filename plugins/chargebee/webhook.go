package chargebee

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// maxWebhookBody bounds webhook payloads.
const maxWebhookBody = 1 << 20

// ReasonPrefix starts the status reason of tenants suspended by this
// plugin. Only such tenants are resumed on payment.
const ReasonPrefix = "billing: "

// Webhook event types the plugin acts on.
const (
	evSubCreated       = "subscription_created"
	evSubStarted       = "subscription_started"
	evSubActivated     = "subscription_activated"
	evSubChanged       = "subscription_changed"
	evSubCancelled     = "subscription_cancelled"
	evSubPaused        = "subscription_paused"
	evSubResumed       = "subscription_resumed"
	evSubReactivated   = "subscription_reactivated"
	evSubRenewed       = "subscription_renewed"
	evPaymentSucceeded = "payment_succeeded"
	evPaymentFailed    = "payment_failed"
	subscriptionEv     = "subscription_"
)

// resumeEvents are the subscription events after which a healthy, settled
// subscription resumes a billing-suspended tenant.
var resumeEvents = map[string]bool{
	evSubCreated: true, evSubStarted: true, evSubActivated: true, evSubChanged: true,
	evSubResumed: true, evSubReactivated: true, evSubRenewed: true,
}

// event is a Chargebee webhook event.
type event struct {
	ID         string   `json:"id"`
	EventType  string   `json:"event_type"`
	OccurredAt int64    `json:"occurred_at"`
	Content    *content `json:"content"`
}

type content struct {
	Subscription *Subscription `json:"subscription"`
	Customer     *Customer     `json:"customer"`
	Invoice      *billingRef   `json:"invoice"`
	Transaction  *billingRef   `json:"transaction"`
}

// billingRef is the part of an invoice or transaction the plugin uses.
type billingRef struct {
	SubscriptionID string `json:"subscription_id"`
	CustomerID     string `json:"customer_id"`
}

func (c *content) subscriptionID() string {
	switch {
	case c.Subscription != nil && c.Subscription.ID != "":
		return c.Subscription.ID
	case c.Invoice != nil && c.Invoice.SubscriptionID != "":
		return c.Invoice.SubscriptionID
	case c.Transaction != nil:
		return c.Transaction.SubscriptionID
	}
	return ""
}

func (c *content) customerID() string {
	switch {
	case c.Customer != nil && c.Customer.ID != "":
		return c.Customer.ID
	case c.Subscription != nil && c.Subscription.CustomerID != "":
		return c.Subscription.CustomerID
	case c.Invoice != nil && c.Invoice.CustomerID != "":
		return c.Invoice.CustomerID
	case c.Transaction != nil:
		return c.Transaction.CustomerID
	}
	return ""
}

// authorized checks the request's basic auth credentials in constant time.
// Both sides are hashed first so their lengths do not leak either.
func (p *Plugin) authorized(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	eq := func(a, b string) int {
		ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
		return subtle.ConstantTimeCompare(ha[:], hb[:])
	}
	userOK := eq(user, p.cfg.WebhookUsername)
	passOK := eq(pass, p.cfg.WebhookPassword)
	return ok && userOK&passOK == 1
}

func (p *Plugin) webhook(w http.ResponseWriter, r *http.Request) {
	if n := p.next.Load(); n != nil {
		n.webhook(w, r)
		return
	}
	if !p.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="tenarium-chargebee", charset="UTF-8"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot read body: " + err.Error()})
		return
	}
	var ev event
	if err := json.Unmarshal(body, &ev); err != nil || ev.ID == "" || ev.EventType == "" || ev.Content == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid event payload"})
		return
	}
	if p.seen.has(ev.ID) {
		writeJSON(w, http.StatusOK, map[string]any{"received": true, "duplicate": true})
		return
	}
	if err := p.handleEvent(r.Context(), ev); err != nil {
		p.log.Error("chargebee webhook failed", "event", ev.ID, "type", ev.EventType, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	p.seen.add(ev.ID)
	writeJSON(w, http.StatusOK, map[string]any{"received": true})
}

// handleEvent applies one authenticated event. Unknown types are ignored.
func (p *Plugin) handleEvent(ctx context.Context, ev event) error {
	c := ev.Content
	switch {
	case strings.HasPrefix(ev.EventType, subscriptionEv) && c.Subscription != nil && c.Subscription.ID != "":
		return p.onSubscription(ctx, ev)
	case p.suspendOn[ev.EventType] || (ev.EventType == evPaymentFailed && p.cfg.SuspendOnPaymentFailed):
		t, ok, err := p.tenantFor(ctx, c.Subscription, c.Customer, c.customerID())
		if !ok {
			return err
		}
		return p.suspend(ctx, t, ReasonPrefix+ev.EventType)
	case ev.EventType == evPaymentSucceeded:
		return p.onPaymentSucceeded(ctx, ev)
	}
	return nil
}

func (p *Plugin) onSubscription(ctx context.Context, ev event) error {
	s, cust := *ev.Content.Subscription, ev.Content.Customer
	// Events arrive out of order; act on the subscription's current state.
	if cur, curCust, err := p.getSubscription(ctx, s.ID); err == nil {
		s = *cur
		if curCust != nil {
			cust = curCust
		}
	} else if !isNotFound(err) {
		return err
	}
	customerID := s.CustomerID
	if customerID == "" && cust != nil {
		customerID = cust.ID
	}
	t, ok, err := p.tenantFor(ctx, &s, cust, customerID)
	if !ok {
		return err
	}
	if !t.IsLive() || !p.isPlanSubscription(t.ID, s) {
		return nil // e.g. a separately sold add-on subscription
	}

	typ := ev.EventType
	if enabled(p.cfg.SyncPlanFromChargebee) && (typ == evSubCreated || typ == evSubChanged) && s.live() {
		if t, err = p.syncPlan(ctx, t, s); err != nil {
			return err
		}
	}

	switch {
	case p.suspendOn[typ]:
		if s.healthy() {
			return nil // recovered since the event was sent
		}
		if other, err := p.healthyPlanSubscription(ctx, t.ID, customerID, s.ID); err != nil || other {
			return err
		}
		return p.suspend(ctx, t, ReasonPrefix+typ)
	case resumeEvents[typ] && s.settled():
		if enabled(p.cfg.ResumeOnPayment) {
			return p.resume(ctx, t)
		}
	}
	return nil
}

// healthyPlanSubscription reports whether the customer has another healthy
// plan subscription, e.g. after switching subscriptions in a checkout.
func (p *Plugin) healthyPlanSubscription(ctx context.Context, tenantID, customerID, except string) (bool, error) {
	if customerID == "" {
		return false, nil
	}
	subs, err := p.liveSubscriptions(ctx, customerID)
	if err != nil {
		return false, err
	}
	for _, o := range p.planSubscriptions(tenantID, subs) {
		if o.ID != except && o.healthy() {
			return true, nil
		}
	}
	return false, nil
}

// syncPlan moves the tenant to the plan mapped to the subscription's item
// price. When the change came from Tenarium the plans already match and
// nothing happens; this is what prevents sync loops.
func (p *Plugin) syncPlan(ctx context.Context, t sdk.Tenant, s Subscription) (sdk.Tenant, error) {
	plan := p.planOf[s.planPrice()]
	for _, it := range s.Items {
		if plan != "" {
			break
		}
		plan = p.planOf[it.ItemPriceID]
	}
	if plan == "" || plan == t.Plan {
		return t, nil
	}
	if _, err := p.host.GetPlan(ctx, plan); errors.Is(err, sdk.ErrNotFound) {
		p.log.Warn("plan mapped to a Chargebee item price does not exist", "plan", plan, "tenant", t.ID)
		return t, nil
	} else if err != nil {
		return t, err
	}
	nt, err := p.host.SetTenantPlan(ctx, t.ID, plan)
	if _, rejected := sdk.IsReject(err); rejected {
		p.log.Warn("plan change from Chargebee rejected", "tenant", t.ID, "plan", plan, "err", err)
		return t, nil
	} else if err != nil {
		return t, err
	}
	p.log.Info("plan changed from Chargebee", "tenant", t.ID, "from", t.Plan, "to", plan, "subscription", s.ID)
	return nt, nil
}

func (p *Plugin) onPaymentSucceeded(ctx context.Context, ev event) error {
	if !enabled(p.cfg.ResumeOnPayment) {
		return nil
	}
	c := ev.Content
	t, ok, err := p.tenantFor(ctx, c.Subscription, c.Customer, c.customerID())
	if !ok {
		return err
	}
	if t.Status != sdk.StatusSuspended || !strings.HasPrefix(t.StatusReason, ReasonPrefix) {
		return nil
	}
	if subID := c.subscriptionID(); subID != "" {
		// Paying one invoice does not end dunning if others are still due,
		// and a cancelled subscription stays cancelled.
		s, _, err := p.getSubscription(ctx, subID)
		if err != nil && !isNotFound(err) {
			return err
		}
		if s != nil && !s.settled() {
			return nil
		}
	}
	return p.resume(ctx, t)
}

// tenantFor resolves the tenant of a Chargebee subscription or customer: by
// the tenarium_tenant_id meta_data, then the tenant_id_field custom field,
// then by the customer ID being a tenant ID. ok is false when the objects
// belong to no (known) tenant.
func (p *Plugin) tenantFor(ctx context.Context, s *Subscription, c *Customer, customerID string) (t sdk.Tenant, ok bool, err error) {
	id := p.linkedTenant(s, c)
	if id == "" && c == nil && customerID != "" {
		cust, err := p.getCustomer(ctx, customerID)
		if err != nil && !isNotFound(err) {
			return t, false, err
		}
		id = p.linkedTenant(nil, cust)
	}
	if id == "" {
		if customerID == "" {
			return t, false, nil
		}
		// Customers created by this plugin have the tenant ID as their ID.
		t, err = p.host.GetTenant(ctx, customerID)
		if errors.Is(err, sdk.ErrNotFound) || (err == nil && t.ID != customerID) {
			return sdk.Tenant{}, false, nil // not a tenant (or only a slug match)
		}
		return t, err == nil, err
	}
	t, err = p.host.GetTenant(ctx, id)
	if errors.Is(err, sdk.ErrNotFound) {
		p.log.Warn("Chargebee object refers to an unknown tenant", "tenant", id)
		return t, false, nil
	}
	return t, err == nil, err
}

func (p *Plugin) linkedTenant(s *Subscription, c *Customer) string {
	f := p.cfg.TenantIDField
	if s != nil {
		if id := metaString(s.MetaData, MetadataTenantID); id != "" {
			return id
		}
	}
	if c != nil {
		if id := metaString(c.MetaData, MetadataTenantID); id != "" {
			return id
		}
	}
	if f == "" {
		return ""
	}
	if s != nil && s.Custom[f] != "" {
		return s.Custom[f]
	}
	if c != nil {
		return c.Custom[f]
	}
	return ""
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

// seenSet remembers the last n webhook event IDs, since Chargebee may
// deliver an event more than once.
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
