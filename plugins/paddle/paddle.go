// Package paddle keeps Paddle Billing customers and subscriptions in step
// with tenants and drives the tenant lifecycle from Paddle notifications. It
// talks to the Paddle Billing REST API directly.
//
// Paddle Billing has no API to create a subscription: subscriptions come
// into being when a customer completes a checkout (or a transaction is
// paid). The plugin therefore manages customers and existing subscriptions
// and leaves the first purchase to the application's checkout.
//
// Tenarium → Paddle (subscription "sync"):
//
//   - tenant.created finds or creates the tenant's customer. Paddle requires
//     an email for customers; it is rendered from customer_email_template
//     (by default the tenant label "billing_email"). Tenants without one get
//     no customer.
//   - tenant.plan_changed swaps the price of the tenant's subscription (with
//     proration_billing_mode) or cancels it when the new plan is not billed.
//     When a billed plan has no subscription yet, it only logs that the
//     customer has to check out.
//   - tenant.updated renames the customer and follows a changed billing
//     email.
//   - tenant.deleted cancels the tenant's subscriptions (cancel_on_delete).
//     The customer is kept for its billing history.
//
// Nothing is stored locally. Customers and subscriptions carry
// custom_data {"tenarium_tenant_id": ..., "tenarium_slug": ...}. Paddle
// cannot filter by custom_data, so a tenant's customer is looked up by its
// billing email (unique per Paddle account) and accepted only if its
// custom_data names the tenant or no tenant at all (it is then claimed).
// Because emails are unique, a redelivered tenant.created cannot create a
// second customer: Paddle answers with a conflict naming the existing one.
//
// Paddle → Tenarium: create a notification destination for
// /v1/plugins/{instance}/public/webhook. Requests are verified with the
// destination's secret key (Paddle-Signature). Notification types listed in
// suspend_on suspend the tenant with the reason "billing: <event type>";
// with suspend_on_past_due, so does a subscription turning past_due. With
// resume_on_payment, transaction.completed and a subscription becoming
// active again resume the tenant, but only if it was suspended for billing
// (its status reason starts with "billing:"). With sync_plan_from_paddle, a
// subscription whose price changed in Paddle moves the tenant to the plan
// mapped to that price. Tenants on a plan without a price are never
// suspended for billing.
//
// GET /v1/plugins/{instance}/tenants/{tenant} returns the tenant's customer
// and subscription.
//
// Configuration:
//
//	plugins:
//	  - plugin: paddle
//	    config:
//	      api_key: pdl_live_apikey_...
//	      webhook_secret: pdl_ntfset_...
//	      environment: production        # or sandbox
//	      plans:
//	        pro: pri_01h...pro
//	        enterprise: pri_01h...ent
//	      customer_email_template: '{{index .Labels "billing_email"}}'
//	      suspend_on_past_due: true
//	      cancel_on_delete: next_billing_period
package paddle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

const version = "0.1.0"

func init() {
	sdk.Register("paddle", func() sdk.Plugin { return &Plugin{} })
}

// API base URLs of the Paddle environments.
const (
	ProductionBase = "https://api.paddle.com"
	SandboxBase    = "https://sandbox-api.paddle.com"
)

const defaultEmailTemplate = `{{index .Labels "billing_email"}}`

// Config is the plugin configuration.
type Config struct {
	// APIKey is a Paddle API key, sent as a bearer token.
	APIKey string `json:"api_key"`
	// WebhookSecret is the notification destination's secret key
	// (pdl_ntfset_...).
	WebhookSecret string `json:"webhook_secret"`
	// Environment is "production" (default) or "sandbox".
	Environment string `json:"environment"`
	// APIBase overrides the environment's API URL.
	APIBase string `json:"api_base"`
	// Timeout per API request, e.g. "15s" (default).
	Timeout string `json:"timeout"`
	// Plans maps Tenarium plan IDs to Paddle price IDs (pri_...). Tenants on
	// other plans have no subscription.
	Plans map[string]string `json:"plans"`
	// CreateCustomers creates missing customers (default true). When false,
	// only existing customers with the tenant's billing email are used.
	CreateCustomers *bool `json:"create_customers"`
	// CustomerEmailTemplate renders the customer email from the tenant
	// (text/template). An empty result means the tenant has no customer.
	// Default: {{index .Labels "billing_email"}}.
	CustomerEmailTemplate string `json:"customer_email_template"`
	// SuspendOn lists Paddle event types that suspend the tenant. Default:
	// subscription.canceled and subscription.paused.
	SuspendOn []string `json:"suspend_on"`
	// SuspendOnPastDue also suspends when a subscription becomes past_due.
	SuspendOnPastDue bool `json:"suspend_on_past_due"`
	// ResumeOnPayment resumes billing-suspended tenants on
	// transaction.completed or when their subscription is active again
	// (default true).
	ResumeOnPayment *bool `json:"resume_on_payment"`
	// SyncPlanFromPaddle moves the tenant to the plan mapped to a price
	// changed in Paddle (default true).
	SyncPlanFromPaddle *bool `json:"sync_plan_from_paddle"`
	// CancelOnDelete is "immediately" (default) or "next_billing_period".
	CancelOnDelete string `json:"cancel_on_delete"`
	// ProrationBillingMode is used for price changes (default
	// prorated_immediately).
	ProrationBillingMode string `json:"proration_billing_mode"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["api_key", "webhook_secret"],
  "additionalProperties": false,
  "properties": {
    "api_key": {"type": "string", "minLength": 1},
    "webhook_secret": {"type": "string", "minLength": 1},
    "environment": {"enum": ["production", "sandbox"]},
    "api_base": {"type": "string", "pattern": "^https?://"},
    "timeout": {"type": "string"},
    "plans": {
      "type": "object",
      "additionalProperties": {"type": "string", "minLength": 1}
    },
    "create_customers": {"type": "boolean"},
    "customer_email_template": {"type": "string", "minLength": 1},
    "suspend_on": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "suspend_on_past_due": {"type": "boolean"},
    "resume_on_payment": {"type": "boolean"},
    "sync_plan_from_paddle": {"type": "boolean"},
    "cancel_on_delete": {"enum": ["immediately", "next_billing_period"]},
    "proration_billing_mode": {"enum": [
      "prorated_immediately", "prorated_next_billing_period",
      "full_immediately", "full_next_billing_period", "do_not_bill"
    ]}
  }
}`)

var defaultSuspendOn = []string{evSubCanceled, evSubPaused}

var prorationModes = []string{
	"prorated_immediately", "prorated_next_billing_period",
	"full_immediately", "full_next_billing_period", "do_not_bill",
}

// Plugin is the Paddle Billing plugin.
type Plugin struct {
	cfg       Config
	base      string
	planOf    map[string]string // price ID → plan ID
	suspendOn map[string]bool
	email     *template.Template
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
		ID:           "paddle",
		Name:         "Paddle",
		Version:      version,
		Description:  "Syncs tenants to Paddle Billing customers and subscriptions and suspends or resumes tenants from Paddle notifications.",
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
	r.PublicRoute("POST /webhook", http.HandlerFunc(p.webhook))
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.tenantBilling))
	return nil
}

// applyConfig validates the configuration and fills in defaults.
func (p *Plugin) applyConfig() error {
	c := &p.cfg
	switch {
	case strings.TrimSpace(c.APIKey) == "":
		return errors.New("api_key is required")
	case strings.TrimSpace(c.WebhookSecret) == "":
		return errors.New("webhook_secret is required")
	}

	switch c.Environment {
	case "", "production":
		c.Environment = "production"
		p.base = ProductionBase
	case "sandbox":
		p.base = SandboxBase
	default:
		return fmt.Errorf("environment must be production or sandbox, got %q", c.Environment)
	}
	if c.APIBase != "" {
		u, err := url.Parse(c.APIBase)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("api_base must be an absolute http(s) URL, got %q", c.APIBase)
		}
		p.base = strings.TrimRight(c.APIBase, "/")
	}

	timeout := 15 * time.Second
	if c.Timeout != "" {
		var err error
		if timeout, err = time.ParseDuration(c.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
	}
	p.client = &http.Client{Timeout: timeout}

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

	if c.CustomerEmailTemplate == "" {
		c.CustomerEmailTemplate = defaultEmailTemplate
	}
	tmpl, err := template.New("customer_email_template").Option("missingkey=error").Parse(c.CustomerEmailTemplate)
	if err != nil {
		return fmt.Errorf("customer_email_template: %w", err)
	}
	p.email = tmpl

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

	switch c.CancelOnDelete {
	case "":
		c.CancelOnDelete = cancelImmediately
	case cancelImmediately, cancelNextPeriod:
	default:
		return fmt.Errorf("cancel_on_delete must be immediately or next_billing_period, got %q", c.CancelOnDelete)
	}

	if c.ProrationBillingMode == "" {
		c.ProrationBillingMode = "prorated_immediately"
	}
	valid := false
	for _, m := range prorationModes {
		valid = valid || m == c.ProrationBillingMode
	}
	if !valid {
		return fmt.Errorf("proration_billing_mode must be one of %s, got %q", strings.Join(prorationModes, ", "), c.ProrationBillingMode)
	}
	return nil
}

// Reconfigure applies every setting without a restart: API key, environment
// and base, timeout, webhook secret (secret rotation), plans, customer email
// template, suspend/resume rules and cancel/proration modes. Subscriptions
// and routes do not depend on the configuration.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{host: p.host, log: p.log, now: p.now, seen: p.seen}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if err := n.applyConfig(); err != nil {
		return err
	}
	p.next.Store(n)
	return nil
}

func enabled(b *bool) bool { return b == nil || *b }

// priceFor returns the Paddle price of a Tenarium plan, or "" if the plan
// is not billed.
func (p *Plugin) priceFor(plan string) string {
	if plan == "" {
		return ""
	}
	return p.cfg.Plans[plan]
}

// emailFor renders the tenant's billing email. "" means the tenant has
// none (or the template failed, which is logged).
func (p *Plugin) emailFor(t sdk.Tenant) string {
	var b strings.Builder
	if err := p.email.Execute(&b, t); err != nil {
		p.log.Warn("customer_email_template failed", "tenant", t.ID, "err", err)
		return ""
	}
	email := strings.TrimSpace(b.String())
	if email != "" && !strings.Contains(email, "@") {
		p.log.Warn("customer_email_template did not render an email address", "tenant", t.ID)
		return ""
	}
	return email
}

// Health checks the API key with a cheap authenticated request.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	return p.call(ctx, http.MethodGet, "/event-types", nil, nil, nil)
}

// BillingInfo is the response of GET /tenants/{tenant}.
type BillingInfo struct {
	CustomerID       string     `json:"customer_id"`
	Email            string     `json:"email,omitempty"`
	SubscriptionID   string     `json:"subscription_id,omitempty"`
	Status           string     `json:"status,omitempty"`
	Price            string     `json:"price,omitempty"`
	CurrentPeriodEnd *time.Time `json:"current_period_end,omitempty"`
	NextBilledAt     *time.Time `json:"next_billed_at,omitempty"`
	ScheduledChange  string     `json:"scheduled_change,omitempty"`
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
	cust, err := p.findCustomer(ctx, t, p.emailFor(t))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if cust == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant has no Paddle customer"})
		return
	}
	info := BillingInfo{CustomerID: cust.ID, Email: cust.Email}
	subs, err := p.liveSubscriptions(ctx, cust.ID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if subs = p.planSubscriptions(t.ID, subs); len(subs) > 0 {
		s := subs[0]
		info.SubscriptionID, info.Status, info.Price = s.ID, s.Status, s.price()
		info.NextBilledAt = s.NextBilledAt
		if s.CurrentBillingPeriod != nil {
			info.CurrentPeriodEnd = s.CurrentBillingPeriod.EndsAt
		}
		if s.ScheduledChange != nil {
			info.ScheduledChange = s.ScheduledChange.Action
		}
	}
	writeJSON(w, http.StatusOK, info)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
