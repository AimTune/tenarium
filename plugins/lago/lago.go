// Package lago exports tenant usage to Lago (https://getlago.com) for
// usage-based billing and can keep Lago customers in step with tenants. It
// talks to the Lago REST API directly.
//
// Usage (subscription "meters"): the final value of every ended usage period
// (tenant.usage_period_closed) of a metric listed in metrics is sent to Lago
// as one event for the mapped billable metric code. The event is timestamped
// one second before the period end (inside the period) and its
// transaction_id is "tenarium-<tenant_id>-<metric>-<period>", so retries and
// redeliveries never bill twice: Lago rejects a repeated transaction_id with
// 422 value_already_exist, which the plugin treats as success. Only period
// totals are exported, not real-time increments. The event carries the
// value in properties.value, so sum billable metrics should use field_name
// "value".
//
// The customer (external_customer_id) or, when subscription_id_template is
// set, the subscription (external_subscription_id) is rendered from Go
// templates against the tenant, read through the host. If the tenant no
// longer exists, the templates see a tenant with only its ID set.
//
// Customers (subscription "customers", with sync_customers): tenant.created
// and tenant.updated (when the name or slug changed) create or update the
// Lago customer whose external_id is rendered from customer_id_template,
// with the tenant's name and the metadata tenarium_tenant_id and
// tenarium_slug. Lago upserts customers by external_id, so redeliveries
// converge on the same customer.
//
// Configuration:
//
//	plugins:
//	  - plugin: lago
//	    config:
//	      api_key: ${LAGO_API_KEY}
//	      api_url: https://api.getlago.com     # or a self-hosted Lago
//	      metrics:
//	        api_calls: api_calls               # Tenarium metric: billable metric code
//	        storage_gb: storage
//	      customer_id_template: "{{.ID}}"
//	      subscription_id_template: "sub-{{.Slug}}"
//	      sync_customers: true
package lago

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
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

const version = "0.1.0"

func init() {
	sdk.Register("lago", func() sdk.Plugin { return &Plugin{} })
}

// Config is the plugin configuration.
type Config struct {
	// APIKey is the Lago API key, sent as a bearer token.
	APIKey string `json:"api_key"`
	// APIURL defaults to https://api.getlago.com (Lago Cloud US). Use the
	// EU endpoint or a self-hosted API URL as needed.
	APIURL string `json:"api_url"`
	// Timeout per API request, e.g. "10s" (default).
	Timeout string `json:"timeout"`
	// Metrics maps Tenarium usage metrics to Lago billable metric codes.
	// Other metrics are not exported.
	Metrics map[string]string `json:"metrics"`
	// CustomerIDTemplate renders the Lago external customer ID from the
	// tenant (default "{{.ID}}").
	CustomerIDTemplate string `json:"customer_id_template"`
	// SubscriptionIDTemplate, if set, renders the Lago external
	// subscription ID from the tenant. Events then carry
	// external_subscription_id instead of external_customer_id.
	SubscriptionIDTemplate string `json:"subscription_id_template"`
	// SyncCustomers creates and updates Lago customers from tenant.created
	// and tenant.updated (default false).
	SyncCustomers bool `json:"sync_customers"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["api_key", "metrics"],
  "additionalProperties": false,
  "properties": {
    "api_key": {"type": "string", "minLength": 1},
    "api_url": {"type": "string", "pattern": "^https?://"},
    "timeout": {"type": "string"},
    "metrics": {
      "type": "object",
      "minProperties": 1,
      "propertyNames": {"minLength": 1},
      "additionalProperties": {"type": "string", "minLength": 1}
    },
    "customer_id_template": {"type": "string", "minLength": 1},
    "subscription_id_template": {"type": "string", "minLength": 1},
    "sync_customers": {"type": "boolean"}
  }
}`)

// Plugin is the Lago usage export plugin.
type Plugin struct {
	cfg      Config
	base     string
	custTmpl *template.Template
	subTmpl  *template.Template // nil: events carry the customer ID
	client   *http.Client
	host     sdk.Host
	log      *slog.Logger
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "lago",
		Name:         "Lago",
		Version:      version,
		Description:  "Exports closed usage periods to Lago billable metrics and optionally syncs tenants to Lago customers.",
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

	r.Subscribe("meters", sdk.EventFilter{Types: []string{sdk.EventTenantUsagePeriodClosed}}, p.reportUsage)
	if p.cfg.SyncCustomers {
		r.Subscribe("customers", sdk.EventFilter{Types: []string{sdk.EventTenantCreated, sdk.EventTenantUpdated}}, p.syncCustomer)
	}
	return nil
}

// applyConfig validates the configuration and fills in defaults.
func (p *Plugin) applyConfig() error {
	c := &p.cfg
	if c.APIKey == "" {
		return errors.New("api_key is required")
	}
	if len(c.Metrics) == 0 {
		return errors.New("metrics: at least one metric must be mapped to a billable metric code")
	}
	for metric, code := range c.Metrics {
		if metric == "" || code == "" {
			return fmt.Errorf("metrics: metric and billable metric code must not be empty (%q: %q)", metric, code)
		}
	}
	c.APIURL = cmp.Or(c.APIURL, "https://api.getlago.com")
	u, err := url.Parse(c.APIURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("api_url must be an absolute http(s) URL, got %q", c.APIURL)
	}
	p.base = strings.TrimRight(c.APIURL, "/")

	timeout := 10 * time.Second
	if c.Timeout != "" {
		if timeout, err = time.ParseDuration(c.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
	}
	p.client = &http.Client{Timeout: timeout}

	c.CustomerIDTemplate = cmp.Or(c.CustomerIDTemplate, "{{.ID}}")
	if p.custTmpl, err = parseTemplate("customer_id_template", c.CustomerIDTemplate); err != nil {
		return err
	}
	if c.SubscriptionIDTemplate != "" {
		if p.subTmpl, err = parseTemplate("subscription_id_template", c.SubscriptionIDTemplate); err != nil {
			return err
		}
	}
	return nil
}

// Health checks the API key with a cheap authenticated request.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	return p.call(ctx, http.MethodGet, "/api/v1/billable_metrics?per_page=1", nil, nil)
}

// Reconfigure applies a new API key, API URL, timeout, metric mapping and
// ID templates without a restart (e.g. key rotation). sync_customers
// decides the subscriptions and is fixed at startup.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{host: p.host, log: p.log}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if n.cfg.SyncCustomers != p.cfg.SyncCustomers {
		return errors.New("sync_customers takes effect after a restart")
	}
	if err := n.applyConfig(); err != nil {
		return err
	}
	p.next.Store(n)
	return nil
}

// parseTemplate parses a tenant template and checks it against a sample
// tenant, so unknown fields (e.g. {{.Id}}) fail at startup. Missing label
// keys are only known at render time.
func parseTemplate(field, text string) (*template.Template, error) {
	t, err := template.New(field).Option("missingkey=error").Parse(text)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	sample := sdk.Tenant{ID: "id", Slug: "slug", Name: "name", Plan: "plan", Labels: map[string]string{}}
	if err := t.Execute(new(strings.Builder), sample); err != nil && !strings.Contains(err.Error(), "map has no entry for key") {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return t, nil
}

// render executes a tenant template and rejects empty results.
func render(t *template.Template, tn sdk.Tenant) (string, error) {
	var b strings.Builder
	if err := t.Execute(&b, tn); err != nil {
		return "", fmt.Errorf("%s: tenant %s: %w", t.Name(), tn.ID, err)
	}
	s := strings.TrimSpace(b.String())
	if s == "" {
		return "", fmt.Errorf("%s rendered an empty value for tenant %s", t.Name(), tn.ID)
	}
	return s, nil
}

// tenant returns the tenant for template rendering. A tenant that no longer
// exists is rendered with only its ID, so its last usage is still exported.
func (p *Plugin) tenant(ctx context.Context, id string) (sdk.Tenant, error) {
	t, err := p.host.GetTenant(ctx, id)
	if errors.Is(err, sdk.ErrNotFound) {
		p.log.Warn("tenant not found; rendering templates with its ID only", "tenant", id)
		return sdk.Tenant{ID: id}, nil
	}
	return t, err
}
