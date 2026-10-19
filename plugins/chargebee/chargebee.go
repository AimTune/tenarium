// Package chargebee keeps Chargebee customers and subscriptions in step with
// tenants and drives the tenant lifecycle from Chargebee billing events. It
// talks to the Chargebee API v2 (Product Catalog 2.0) directly.
//
// Tenarium → Chargebee (subscription "sync"):
//
//   - tenant.created finds or creates the tenant's customer and, when the
//     tenant's plan maps to an item price in plans, a subscription to that
//     item price.
//   - tenant.plan_changed replaces the subscription's items with the new
//     plan's item price, creates (or reactivates) the subscription when
//     there is none, or cancels it immediately when the new plan is not
//     billed.
//   - tenant.updated sets the customer's company and slug metadata.
//   - tenant.deleted cancels the tenant's live subscriptions, immediately or
//     at the end of the term (cancel_on_delete). The customer is kept for its
//     billing history.
//
// Nothing is stored locally. Chargebee lets callers choose IDs, so the
// tenant ID is both the customer ID and the plan subscription ID
// (customers and subscriptions are separate ID namespaces). Creations are
// therefore naturally idempotent: a redelivered event that tries to create
// an existing object gets "duplicate_entry", which is treated as success.
// Customers and subscriptions also carry meta_data
// {"tenarium_tenant_id": ..., "tenarium_slug": ...} and, with
// tenant_id_field, a custom field holding the tenant ID, so objects created
// elsewhere (e.g. by a hosted checkout) can be linked to a tenant too.
//
// Chargebee → Tenarium: add a webhook in Chargebee for
// /v1/plugins/{instance}/public/webhook with basic authentication
// (webhook_username / webhook_password). Events listed in suspend_on suspend
// the tenant with the reason "billing: <event type>" unless the
// subscription is healthy again by the time the event is handled; with
// suspend_on_payment_failed, so does payment_failed. With
// resume_on_payment, payment_succeeded and a subscription becoming healthy
// (resumed, activated, reactivated, renewed, ...) resume the tenant, but
// only if it was suspended for billing (its status reason starts with
// "billing:") and the subscription has no due invoices. With
// sync_plan_from_chargebee, a subscription whose item price changed in
// Chargebee moves the tenant to the plan mapped to that item price. Tenants
// on a plan without an item price are never suspended for billing.
//
// GET /v1/plugins/{instance}/tenants/{tenant} returns the tenant's customer
// and subscription.
//
// Configuration:
//
//	plugins:
//	  - plugin: chargebee
//	    config:
//	      site: acme            # https://acme.chargebee.com
//	      api_key: live_...
//	      webhook_username: tenarium
//	      webhook_password: a-long-random-secret
//	      plans:
//	        pro: pro-USD-Monthly
//	        enterprise: enterprise-USD-Yearly
//	      tenant_id_field: cf_tenarium_tenant_id
//	      suspend_on_payment_failed: true
//	      cancel_on_delete: end_of_term
package chargebee

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

const version = "0.1.0"

func init() {
	sdk.Register("chargebee", func() sdk.Plugin { return &Plugin{} })
}

const (
	cancelImmediately = "immediately"
	cancelEndOfTerm   = "end_of_term"
)

// maxIDLen is the longest ID Chargebee accepts for customers and
// subscriptions.
const maxIDLen = 50

// Config is the plugin configuration.
type Config struct {
	// Site is the Chargebee site name: https://{site}.chargebee.com.
	Site string `json:"site"`
	// APIKey is a full-access (or suitably restricted) API key. It is sent
	// as the HTTP basic auth username.
	APIKey string `json:"api_key"`
	// APIBase overrides the API base URL (default
	// https://{site}.chargebee.com/api/v2).
	APIBase string `json:"api_base"`
	// Timeout per API request, e.g. "15s" (default).
	Timeout string `json:"timeout"`
	// WebhookUsername and WebhookPassword are the basic auth credentials
	// configured on the Chargebee webhook.
	WebhookUsername string `json:"webhook_username"`
	WebhookPassword string `json:"webhook_password"`
	// Plans maps Tenarium plan IDs to Chargebee item price IDs. Tenants on
	// other plans have no subscription.
	Plans map[string]string `json:"plans"`
	// CreateCustomers creates missing customers (default true). When false,
	// only an existing customer whose ID is the tenant ID is used.
	CreateCustomers *bool `json:"create_customers"`
	// SuspendOn lists Chargebee event types that suspend the tenant.
	// Default: subscription_cancelled and subscription_paused.
	SuspendOn []string `json:"suspend_on"`
	// SuspendOnPaymentFailed also suspends on payment_failed.
	SuspendOnPaymentFailed bool `json:"suspend_on_payment_failed"`
	// ResumeOnPayment resumes billing-suspended tenants on
	// payment_succeeded or when their subscription is healthy again
	// (default true).
	ResumeOnPayment *bool `json:"resume_on_payment"`
	// SyncPlanFromChargebee moves the tenant to the plan mapped to an item
	// price changed in Chargebee (default true).
	SyncPlanFromChargebee *bool `json:"sync_plan_from_chargebee"`
	// CancelOnDelete is "immediately" (default) or "end_of_term".
	CancelOnDelete string `json:"cancel_on_delete"`
	// TenantIDField is an optional customer custom field (cf_...) set to
	// the tenant ID. It must exist in Chargebee.
	TenantIDField string `json:"tenant_id_field"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["site", "api_key", "webhook_username", "webhook_password"],
  "additionalProperties": false,
  "properties": {
    "site": {"type": "string", "pattern": "^[a-z0-9-]+$"},
    "api_key": {"type": "string", "minLength": 1},
    "api_base": {"type": "string", "pattern": "^https?://"},
    "timeout": {"type": "string"},
    "webhook_username": {"type": "string", "minLength": 1},
    "webhook_password": {"type": "string", "minLength": 1},
    "plans": {
      "type": "object",
      "additionalProperties": {"type": "string", "minLength": 1}
    },
    "create_customers": {"type": "boolean"},
    "suspend_on": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "suspend_on_payment_failed": {"type": "boolean"},
    "resume_on_payment": {"type": "boolean"},
    "sync_plan_from_chargebee": {"type": "boolean"},
    "cancel_on_delete": {"enum": ["immediately", "end_of_term"]},
    "tenant_id_field": {"type": "string", "pattern": "^cf_[a-z0-9_]+$"}
  }
}`)

var (
	sitePattern    = regexp.MustCompile(`^[a-z0-9-]+$`)
	cfFieldPattern = regexp.MustCompile(`^cf_[a-z0-9_]+$`)
)

var defaultSuspendOn = []string{evSubCancelled, evSubPaused}

// Plugin is the Chargebee billing plugin.
type Plugin struct {
	cfg       Config
	base      string
	planOf    map[string]string // item price ID → plan ID
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
		ID:           "chargebee",
		Name:         "Chargebee",
		Version:      version,
		Description:  "Syncs tenants to Chargebee customers and subscriptions and suspends or resumes tenants from billing events.",
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
	case c.Site == "":
		return errors.New("site is required")
	case !sitePattern.MatchString(c.Site):
		return fmt.Errorf("site must match ^[a-z0-9-]+$ (the subdomain of chargebee.com), got %q", c.Site)
	case c.APIKey == "":
		return errors.New("api_key is required")
	case c.WebhookUsername == "":
		return errors.New("webhook_username is required")
	case c.WebhookPassword == "":
		return errors.New("webhook_password is required")
	case c.TenantIDField != "" && !cfFieldPattern.MatchString(c.TenantIDField):
		return fmt.Errorf("tenant_id_field must be a custom field name matching ^cf_[a-z0-9_]+$, got %q", c.TenantIDField)
	}
	base := c.APIBase
	if base == "" {
		base = "https://" + c.Site + ".chargebee.com/api/v2"
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("api_base must be an absolute http(s) URL, got %q", c.APIBase)
	}
	p.base = strings.TrimRight(base, "/")

	timeout := 15 * time.Second
	if c.Timeout != "" {
		if timeout, err = time.ParseDuration(c.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
	}
	p.client = &http.Client{Timeout: timeout}

	if c.CancelOnDelete == "" {
		c.CancelOnDelete = cancelImmediately
	}
	if c.CancelOnDelete != cancelImmediately && c.CancelOnDelete != cancelEndOfTerm {
		return fmt.Errorf("cancel_on_delete must be immediately or end_of_term, got %q", c.CancelOnDelete)
	}

	p.planOf = make(map[string]string, len(c.Plans))
	for plan, price := range c.Plans {
		if plan == "" || price == "" {
			return fmt.Errorf("plans: plan and item price IDs must not be empty (%q: %q)", plan, price)
		}
		if other, dup := p.planOf[price]; dup {
			return fmt.Errorf("plans: item price %s is mapped to both %s and %s", price, other, plan)
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

// Reconfigure applies every setting without a restart: site, API key and
// base, timeout, webhook credentials (credential rotation), plans, tenant ID
// field, suspend/resume rules and the cancel mode. Subscriptions and routes
// do not depend on the configuration.
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

// priceFor returns the Chargebee item price of a Tenarium plan, or "" if
// the plan is not billed.
func (p *Plugin) priceFor(plan string) string {
	if plan == "" {
		return ""
	}
	return p.cfg.Plans[plan]
}

// Health checks the site and API key with a cheap authenticated request.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	return p.call(ctx, http.MethodGet, "/customers", url.Values{"limit": {"1"}}, nil)
}

// BillingInfo is the response of GET /tenants/{tenant}.
type BillingInfo struct {
	CustomerID     string     `json:"customer_id"`
	SubscriptionID string     `json:"subscription_id,omitempty"`
	Status         string     `json:"status,omitempty"`
	ItemPriceID    string     `json:"item_price_id,omitempty"`
	CurrentTermEnd *time.Time `json:"current_term_end,omitempty"`
	DueInvoices    int        `json:"due_invoices,omitempty"`
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
	cust, err := p.getCustomer(ctx, t.ID)
	if isNotFound(err) || (err == nil && cust.Deleted) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant has no Chargebee customer"})
		return
	} else if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	info := BillingInfo{CustomerID: cust.ID}
	subs, err := p.liveSubscriptions(ctx, cust.ID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if subs = p.planSubscriptions(t.ID, subs); len(subs) > 0 {
		s := subs[0]
		info.SubscriptionID, info.Status, info.ItemPriceID, info.DueInvoices = s.ID, s.Status, s.planPrice(), s.DueInvoicesCount
		if s.CurrentTermEnd > 0 {
			ts := time.Unix(s.CurrentTermEnd, 0).UTC()
			info.CurrentTermEnd = &ts
		}
	}
	writeJSON(w, http.StatusOK, info)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
