// Package orb exports tenant usage to Orb (https://withorb.com) for
// usage-based billing. It talks to the Orb REST API directly.
//
// Usage (subscription "meters"): the final value of every ended usage period
// (tenant.usage_period_closed) of a metric listed in metrics is ingested
// into Orb (POST /v1/ingest) as one event with the mapped event_name. The
// event is timestamped one second before the period end (inside the period)
// and its idempotency_key is "tenarium-<tenant_id>-<metric>-<period>"; Orb
// deduplicates events by that key, so retries and redeliveries never bill
// twice. Only period totals are exported, not real-time increments. The
// value is sent in the property named by property_name (default "value"),
// next to tenarium_metric and tenarium_period.
//
// The external_customer_id is rendered from customer_id_template against the
// tenant, read through the host. If the tenant no longer exists, the
// template sees a tenant with only its ID set.
//
// Orb answers 200 even when it rejects an event and lists it in
// validation_failed (e.g. an unknown customer or a timestamp outside the
// ingestion grace period). The plugin returns an error with Orb's messages
// so the event is retried and dead-lettered instead of being lost silently.
//
// Configuration:
//
//	plugins:
//	  - plugin: orb
//	    config:
//	      api_key: ${ORB_API_KEY}
//	      metrics:
//	        api_calls: api_request     # Tenarium metric: Orb event_name
//	      customer_id_template: "{{.ID}}"
//	      property_name: value
package orb

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
	sdk.Register("orb", func() sdk.Plugin { return &Plugin{} })
}

// Config is the plugin configuration.
type Config struct {
	// APIKey is the Orb API key, sent as a bearer token.
	APIKey string `json:"api_key"`
	// APIURL defaults to https://api.withorb.com.
	APIURL string `json:"api_url"`
	// Timeout per API request, e.g. "10s" (default).
	Timeout string `json:"timeout"`
	// Metrics maps Tenarium usage metrics to Orb event names. Other metrics
	// are not exported.
	Metrics map[string]string `json:"metrics"`
	// CustomerIDTemplate renders the Orb external_customer_id from the
	// tenant (default "{{.ID}}").
	CustomerIDTemplate string `json:"customer_id_template"`
	// PropertyName is the event property carrying the value (default
	// "value"); Orb billable metrics aggregate it, e.g. SUM(value).
	PropertyName string `json:"property_name"`
	// Debug asks Orb to report ingested and duplicate events (logged at
	// debug level).
	Debug bool `json:"debug"`
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
    "property_name": {"type": "string", "minLength": 1, "not": {"enum": ["tenarium_metric", "tenarium_period"]}},
    "debug": {"type": "boolean"}
  }
}`)

// Plugin is the Orb usage export plugin.
type Plugin struct {
	cfg      Config
	base     string
	custTmpl *template.Template
	client   *http.Client
	host     sdk.Host
	log      *slog.Logger
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "orb",
		Name:         "Orb",
		Version:      version,
		Description:  "Exports closed usage periods to Orb as idempotent usage events.",
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
	return nil
}

// applyConfig validates the configuration and fills in defaults.
func (p *Plugin) applyConfig() error {
	c := &p.cfg
	if c.APIKey == "" {
		return errors.New("api_key is required")
	}
	if len(c.Metrics) == 0 {
		return errors.New("metrics: at least one metric must be mapped to an event name")
	}
	for metric, name := range c.Metrics {
		if metric == "" || name == "" {
			return fmt.Errorf("metrics: metric and event name must not be empty (%q: %q)", metric, name)
		}
	}
	c.APIURL = cmp.Or(c.APIURL, "https://api.withorb.com")
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

	c.PropertyName = cmp.Or(c.PropertyName, "value")
	if c.PropertyName == "tenarium_metric" || c.PropertyName == "tenarium_period" {
		return fmt.Errorf("property_name must not be %q (reserved)", c.PropertyName)
	}
	c.CustomerIDTemplate = cmp.Or(c.CustomerIDTemplate, "{{.ID}}")
	if p.custTmpl, err = parseTemplate("customer_id_template", c.CustomerIDTemplate); err != nil {
		return err
	}
	return nil
}

// Health checks the API key with Orb's ping endpoint.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	return p.call(ctx, http.MethodGet, "/v1/ping", nil, nil)
}

// Reconfigure applies every setting without a restart (e.g. key rotation,
// a new metric mapping); the subscribed event is not configurable.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{host: p.host, log: p.log}
	if err := decode(&n.cfg); err != nil {
		return err
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
