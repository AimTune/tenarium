// Package openmeter exports tenant usage to OpenMeter
// (https://openmeter.io), cloud or self-hosted, as CloudEvents.
//
// Usage (subscription "meters"): the final value of every ended usage period
// (tenant.usage_period_closed) of a metric listed in metrics is sent to
// POST /api/v1/events as one CloudEvents 1.0 event of the mapped type, so the
// OpenMeter meter listening to that type aggregates it. The event time is one
// second before the period end (inside the period) and its id is
// "tenarium-<tenant_id>-<metric>-<period>"; OpenMeter deduplicates events by
// (id, source), so retries and redeliveries never count twice. Only period
// totals are exported, not real-time increments. The value is in the data
// property named by value_property (default "value"), next to metric and
// period.
//
// The subject is rendered from subject_template against the tenant, read
// through the host. If the tenant no longer exists, the template sees a
// tenant with only its ID set.
//
// Configuration:
//
//	plugins:
//	  - plugin: openmeter
//	    config:
//	      api_key: ${OPENMETER_API_KEY}   # optional for self-hosted
//	      api_url: https://openmeter.cloud
//	      metrics:
//	        api_calls: tenarium.api_calls # Tenarium metric: CloudEvent type
//	      subject_template: "{{.ID}}"
//	      source: tenarium
//	      value_property: value
package openmeter

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
	sdk.Register("openmeter", func() sdk.Plugin { return &Plugin{} })
}

// Config is the plugin configuration.
type Config struct {
	// APIKey is the OpenMeter API token, sent as a bearer token. Optional
	// for self-hosted OpenMeter without authentication.
	APIKey string `json:"api_key"`
	// APIURL defaults to https://openmeter.cloud.
	APIURL string `json:"api_url"`
	// Timeout per API request, e.g. "10s" (default).
	Timeout string `json:"timeout"`
	// Metrics maps Tenarium usage metrics to the CloudEvent types the
	// OpenMeter meters listen to (eventType). Other metrics are not
	// exported.
	Metrics map[string]string `json:"metrics"`
	// SubjectTemplate renders the event subject (the OpenMeter customer
	// subject) from the tenant (default "{{.ID}}").
	SubjectTemplate string `json:"subject_template"`
	// Source is the CloudEvents source (default "tenarium").
	Source string `json:"source"`
	// ValueProperty is the data property carrying the value (default
	// "value"); meters read it with valueProperty "$.value".
	ValueProperty string `json:"value_property"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["metrics"],
  "additionalProperties": false,
  "properties": {
    "api_key": {"type": "string"},
    "api_url": {"type": "string", "pattern": "^https?://"},
    "timeout": {"type": "string"},
    "metrics": {
      "type": "object",
      "minProperties": 1,
      "propertyNames": {"minLength": 1},
      "additionalProperties": {"type": "string", "minLength": 1}
    },
    "subject_template": {"type": "string", "minLength": 1},
    "source": {"type": "string", "minLength": 1},
    "value_property": {"type": "string", "minLength": 1, "not": {"enum": ["metric", "period"]}}
  }
}`)

// Plugin is the OpenMeter usage export plugin.
type Plugin struct {
	cfg     Config
	base    string
	subTmpl *template.Template
	client  *http.Client
	host    sdk.Host
	log     *slog.Logger
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "openmeter",
		Name:         "OpenMeter",
		Version:      version,
		Description:  "Exports closed usage periods to OpenMeter as idempotent CloudEvents.",
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
	if len(c.Metrics) == 0 {
		return errors.New("metrics: at least one metric must be mapped to an event type")
	}
	for metric, typ := range c.Metrics {
		if metric == "" || strings.TrimSpace(typ) == "" {
			return fmt.Errorf("metrics: metric and event type must not be empty (%q: %q)", metric, typ)
		}
	}
	c.APIURL = cmp.Or(c.APIURL, "https://openmeter.cloud")
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

	c.Source = cmp.Or(c.Source, "tenarium")
	c.ValueProperty = cmp.Or(c.ValueProperty, "value")
	if c.ValueProperty == "metric" || c.ValueProperty == "period" {
		return fmt.Errorf("value_property must not be %q (reserved)", c.ValueProperty)
	}
	c.SubjectTemplate = cmp.Or(c.SubjectTemplate, "{{.ID}}")
	if p.subTmpl, err = parseTemplate("subject_template", c.SubjectTemplate); err != nil {
		return err
	}
	return nil
}

// Health checks connectivity (and the token, if set) by listing meters.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	return p.call(ctx, http.MethodGet, "/api/v1/meters", "", nil)
}

// Reconfigure applies a new API key, API URL, timeout, metric mapping,
// subject template and value property without a restart (e.g. key
// rotation). source is part of OpenMeter's deduplication key, so changing
// it while deliveries are retried could count usage twice; it takes effect
// after a restart.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{host: p.host, log: p.log}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if err := n.applyConfig(); err != nil {
		return err
	}
	if n.cfg.Source != p.cfg.Source {
		return errors.New("source takes effect after a restart")
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
