// Package stripe keeps Stripe customers and subscriptions in step with
// tenants and drives the tenant lifecycle from Stripe billing events. It
// talks to the Stripe REST API directly.
//
// Tenarium → Stripe (subscription "sync"):
//
//   - tenant.created finds or creates the tenant's customer and, when the
//     tenant's plan maps to a price in plans, a subscription to that price.
//   - tenant.plan_changed swaps the subscription's price (with prorations),
//     creates a subscription when there is none, or cancels it when the new
//     plan is not billed.
//   - tenant.updated renames the customer.
//   - tenant.deleted cancels the tenant's subscriptions. The customer is kept
//     for its billing history.
//
// Nothing is stored locally: customers and subscriptions carry the tenant ID
// in metadata["tenarium_tenant_id"]. Customers are found with the search API,
// which is eventually consistent, so creations use idempotency keys derived
// from the tenant (and event) ID; redelivered events converge on the same
// objects.
//
// Stripe → Tenarium: point a Stripe webhook endpoint at
// /v1/plugins/{instance}/public/webhook. Requests are verified with the
// endpoint's signing secret. Events listed in suspend_on suspend the tenant
// with the reason "billing: <event type>"; with suspend_on_past_due, so does
// a subscription turning past_due or unpaid. With resume_on_payment,
// invoice.paid and a subscription becoming active again resume the tenant,
// but only if it was suspended for billing (its status reason starts with
// "billing:"). With sync_plan_from_stripe, a subscription whose price changed
// in Stripe moves the tenant to the plan mapped to that price. Tenants on a
// plan without a price are never suspended for billing, so canceling the
// subscription after a downgrade to a free plan is harmless.
//
// GET /v1/plugins/{instance}/tenants/{tenant} returns the tenant's customer
// and subscription.
//
// Usage (subscription "meters"): with meters configured, the final value of
// every ended usage period (tenant.usage_period_closed) of a mapped metric is
// sent to Stripe as a billing meter event, timestamped inside the period and
// identified by tenant, metric and period so it is billed exactly once.
//
// Configuration:
//
//	plugins:
//	  - plugin: stripe
//	    config:
//	      api_key: sk_live_...
//	      webhook_secret: whsec_...
//	      plans:
//	        pro: price_1PxyzPro
//	        enterprise: price_1PxyzEnt
//	      trial_days: 14
//	      suspend_on_past_due: true
//	      meters:
//	        api_calls: api_requests   # Tenarium metric: Stripe meter event name
package stripe

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

const version = "0.1.0"

func init() {
	sdk.Register("stripe", func() sdk.Plugin { return &Plugin{} })
}

const (
	collectionChargeAutomatically = "charge_automatically"
	collectionSendInvoice         = "send_invoice"
)

// Config is the plugin configuration.
type Config struct {
	// APIKey is a secret (sk_...) or restricted (rk_...) API key.
	APIKey string `json:"api_key"`
	// WebhookSecret is the webhook endpoint's signing secret (whsec_...).
	WebhookSecret string `json:"webhook_secret"`
	// APIBase defaults to https://api.stripe.com.
	APIBase string `json:"api_base"`
	// Timeout per API request, e.g. "15s" (default).
	Timeout string `json:"timeout"`
	// Plans maps Tenarium plan IDs to Stripe price IDs. Tenants on other
	// plans have no subscription.
	Plans map[string]string `json:"plans"`
	// CreateCustomers creates missing customers (default true). When false,
	// only customers already tagged with the tenant ID are used.
	CreateCustomers *bool `json:"create_customers"`
	// TrialDays starts new subscriptions with a trial.
	TrialDays int `json:"trial_days"`
	// CollectionMethod is "charge_automatically" (default) or "send_invoice".
	CollectionMethod string `json:"collection_method"`
	// DaysUntilDue applies to send_invoice (default 30).
	DaysUntilDue int `json:"days_until_due"`
	// CancelAtPeriodEndOnDelete lets subscriptions of deleted tenants run
	// to the end of the paid period instead of canceling immediately.
	CancelAtPeriodEndOnDelete bool `json:"cancel_at_period_end_on_delete"`
	// SuspendOn lists Stripe event types that suspend the tenant. Default:
	// customer.subscription.deleted and customer.subscription.paused.
	SuspendOn []string `json:"suspend_on"`
	// SuspendOnPastDue also suspends when a subscription becomes past_due
	// or unpaid.
	SuspendOnPastDue bool `json:"suspend_on_past_due"`
	// ResumeOnPayment resumes billing-suspended tenants on invoice.paid or
	// when their subscription is active again (default true).
	ResumeOnPayment *bool `json:"resume_on_payment"`
	// SyncPlanFromStripe moves the tenant to the plan mapped to a price
	// changed in Stripe (default true).
	SyncPlanFromStripe *bool `json:"sync_plan_from_stripe"`
	// Meters maps Tenarium usage metrics to Stripe meter event names. Ended
	// periods (tenant.usage_period_closed) are reported as meter events.
	Meters map[string]string `json:"meters"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["api_key", "webhook_secret"],
  "additionalProperties": false,
  "properties": {
    "api_key": {"type": "string", "pattern": "^(sk|rk)_"},
    "webhook_secret": {"type": "string", "pattern": "^whsec_"},
    "api_base": {"type": "string", "pattern": "^https?://"},
    "timeout": {"type": "string"},
    "plans": {
      "type": "object",
      "additionalProperties": {"type": "string", "minLength": 1}
    },
    "create_customers": {"type": "boolean"},
    "trial_days": {"type": "integer", "minimum": 0},
    "collection_method": {"enum": ["charge_automatically", "send_invoice"]},
    "days_until_due": {"type": "integer", "minimum": 1},
    "cancel_at_period_end_on_delete": {"type": "boolean"},
    "suspend_on": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "suspend_on_past_due": {"type": "boolean"},
    "resume_on_payment": {"type": "boolean"},
    "sync_plan_from_stripe": {"type": "boolean"},
    "meters": {
      "type": "object",
      "additionalProperties": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,100}$"}
    }
  }
}`)

var defaultSuspendOn = []string{"customer.subscription.deleted", "customer.subscription.paused"}

// Plugin is the Stripe billing plugin.
type Plugin struct {
	cfg       Config
	base      string
	planOf    map[string]string // price ID → plan ID
	suspendOn map[string]bool
	client    *http.Client
	host      sdk.Host
	log       *slog.Logger
	now       func() time.Time
	seen      *seenSet
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "stripe",
		Name:         "Stripe",
		Version:      version,
		Description:  "Syncs tenants to Stripe customers and subscriptions and suspends or resumes tenants from billing events.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.applyConfig(); err != nil {
		return err
	}
	p.host = r.Host()
	p.log = r.Logger()
	if p.now == nil {
		p.now = time.Now
	}
	p.seen = newSeenSet(10000)

	r.Subscribe("sync", sdk.EventFilter{Types: []string{
		sdk.EventTenantCreated, sdk.EventTenantPlanChanged, sdk.EventTenantUpdated, sdk.EventTenantDeleted,
	}}, p.sync)
	if len(p.cfg.Meters) > 0 {
		r.Subscribe("meters", sdk.EventFilter{Types: []string{sdk.EventTenantUsagePeriodClosed}}, p.reportUsage)
	}
	r.PublicRoute("POST /webhook", http.HandlerFunc(p.webhook))
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.tenantBilling))
	return nil
}

// applyConfig validates the configuration and fills in defaults.
func (p *Plugin) applyConfig() error {
	c := &p.cfg
	switch {
	case c.APIKey == "":
		return errors.New("api_key is required")
	case !strings.HasPrefix(c.APIKey, "sk_") && !strings.HasPrefix(c.APIKey, "rk_"):
		return errors.New("api_key must be a secret (sk_) or restricted (rk_) key")
	case c.WebhookSecret == "":
		return errors.New("webhook_secret is required")
	case !strings.HasPrefix(c.WebhookSecret, "whsec_"):
		return errors.New("webhook_secret must start with whsec_")
	case c.TrialDays < 0:
		return errors.New("trial_days must not be negative")
	}
	c.APIBase = cmp.Or(c.APIBase, "https://api.stripe.com")
	u, err := url.Parse(c.APIBase)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("api_base must be an absolute http(s) URL, got %q", c.APIBase)
	}
	p.base = strings.TrimRight(c.APIBase, "/")

	timeout := 15 * time.Second
	if c.Timeout != "" {
		if timeout, err = time.ParseDuration(c.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
	}
	p.client = &http.Client{Timeout: timeout}

	c.CollectionMethod = cmp.Or(c.CollectionMethod, collectionChargeAutomatically)
	switch c.CollectionMethod {
	case collectionChargeAutomatically:
		if c.DaysUntilDue != 0 {
			return errors.New("days_until_due only applies to collection_method send_invoice")
		}
	case collectionSendInvoice:
		if c.DaysUntilDue < 0 {
			return errors.New("days_until_due must be positive")
		}
		c.DaysUntilDue = cmp.Or(c.DaysUntilDue, 30)
	default:
		return fmt.Errorf("collection_method must be charge_automatically or send_invoice, got %q", c.CollectionMethod)
	}

	p.planOf = make(map[string]string, len(c.Plans))
	for plan, price := range c.Plans {
		if plan == "" || price == "" {
			return fmt.Errorf("plans: plan and price IDs must not be empty (%q: %q)", plan, price)
		}
		if other, dup := p.planOf[price]; dup {
			return fmt.Errorf("plans: price %s is mapped to both %s and %s", price, other, plan)
		}
		p.planOf[price] = plan
	}

	if c.SuspendOn == nil {
		c.SuspendOn = defaultSuspendOn
	}
	p.suspendOn = make(map[string]bool, len(c.SuspendOn))
	for _, t := range c.SuspendOn {
		if t == "" {
			return errors.New("suspend_on: event types must not be empty")
		}
		p.suspendOn[t] = true
	}
	return nil
}

// Reconfigure applies new settings without a restart: API key and base,
// timeout, webhook signing secret (secret rotation), plans, customer and
// subscription options, suspend/resume rules and the meter mapping. Turning
// meters on or off takes effect after a restart.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{host: p.host, log: p.log, now: p.now, seen: p.seen}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if (len(n.cfg.Meters) > 0) != (len(p.cfg.Meters) > 0) {
		return errors.New("enabling or disabling meters takes effect after a restart")
	}
	if err := n.applyConfig(); err != nil {
		return err
	}
	p.next.Store(n)
	return nil
}

func enabled(b *bool) bool { return b == nil || *b }

// priceFor returns the Stripe price of a Tenarium plan, or "" if the plan is
// not billed.
func (p *Plugin) priceFor(plan string) string {
	if plan == "" {
		return ""
	}
	return p.cfg.Plans[plan]
}

// Health checks the API key with a cheap authenticated request.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	return p.call(ctx, http.MethodGet, "/v1/balance", nil, "", nil)
}

// BillingInfo is the response of GET /tenants/{tenant}.
type BillingInfo struct {
	CustomerID       string     `json:"customer_id"`
	SubscriptionID   string     `json:"subscription_id,omitempty"`
	Status           string     `json:"status,omitempty"`
	Price            string     `json:"price,omitempty"`
	CurrentPeriodEnd *time.Time `json:"current_period_end,omitempty"`
}

func (p *Plugin) tenantBilling(w http.ResponseWriter, r *http.Request) {
	if n := p.next.Load(); n != nil {
		n.tenantBilling(w, r)
		return
	}
	ctx := r.Context()
	t, err := p.host.GetTenant(ctx, r.PathValue("tenant"))
	if err == nil {
		err = p.host.Authorize(ctx, sdk.ActionTenantsRead, sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID})
		if errors.Is(err, sdk.ErrForbidden) {
			err = sdk.ErrNotFound // do not reveal other tenants
		}
	}
	if errors.Is(err, sdk.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
		return
	} else if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	cust, err := p.findCustomer(ctx, t.ID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if cust == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant has no Stripe customer"})
		return
	}
	info := BillingInfo{CustomerID: cust.ID}
	subs, err := p.liveSubscriptions(ctx, cust.ID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if len(subs) > 0 {
		s := subs[0]
		info.SubscriptionID, info.Status, info.Price = s.ID, s.Status, s.price()
		if end := s.periodEnd(); end > 0 {
			ts := time.Unix(end, 0).UTC()
			info.CurrentPeriodEnd = &ts
		}
	}
	writeJSON(w, http.StatusOK, info)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
