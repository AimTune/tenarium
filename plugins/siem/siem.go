// Package siem exports Tenarium events as an audit trail to SIEM systems.
// Every event (or the ones selected with events / exclude_events) is turned
// into a flat audit record that names who did what to which tenant, and sent
// to any combination of:
//
//   - Splunk HTTP Event Collector (HEC): POST /services/collector/event with
//     the configured index, sourcetype and source. The tenant, actor and
//     event type are also sent as indexed fields.
//   - syslog (RFC 5424) over TCP, TLS or UDP, with the record as JSON or as
//     ArcSight CEF in the message. TCP and TLS use octet-counting framing
//     (RFC 6587/5425) by default.
//   - Elasticsearch or OpenSearch via the _bulk API, into one index per day
//     ("tenarium-events-2026.10.10"). Documents carry ECS fields and use the
//     event ID as _id with the "create" action, so redelivered events are not
//     indexed twice.
//
// Each sink has its own subscription ("splunk", "syslog", "elastic"), so a
// failing sink is retried and dead-lettered without holding back the others.
//
// Configuration:
//
//	plugins:
//	  - plugin: siem
//	    config:
//	      exclude_events: ["tenant.usage_*"]
//	      splunk:
//	        url: https://splunk.example.com:8088
//	        token: ${SPLUNK_HEC_TOKEN}
//	        index: tenarium
//	        sourcetype: tenarium:audit
//	      syslog:
//	        address: siem.example.com:6514
//	        network: tls
//	        format: cef
//	      elastic:
//	        url: https://es.example.com:9200
//	        api_key: ${ES_API_KEY}
//	        index_prefix: tenarium-audit
package siem

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

const version = "0.1.0"

func init() {
	sdk.Register("siem", func() sdk.Plugin { return &Plugin{} })
}

// Config is the plugin configuration. At least one sink must be set.
type Config struct {
	// Events are glob patterns of event types to export. Empty means all.
	Events []string `json:"events"`
	// ExcludeEvents are glob patterns of event types never exported.
	ExcludeEvents []string `json:"exclude_events"`
	// IncludeData adds the event payload to records (default true).
	IncludeData *bool `json:"include_data"`
	// Timeout per request or connection attempt, e.g. "10s" (default).
	Timeout string `json:"timeout"`

	Splunk  *SplunkConfig  `json:"splunk"`
	Syslog  *SyslogConfig  `json:"syslog"`
	Elastic *ElasticConfig `json:"elastic"`
}

// TLSConfig configures TLS for a sink.
type TLSConfig struct {
	// CAFile is a PEM bundle of CAs to trust instead of the system roots.
	CAFile string `json:"ca_file"`
	// CertFile and KeyFile set a client certificate (mutual TLS).
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	// ServerName overrides the name verified in the server certificate.
	ServerName string `json:"server_name"`
	// InsecureSkipVerify disables certificate verification (testing only).
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

const tlsSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "ca_file": {"type": "string", "minLength": 1},
    "cert_file": {"type": "string", "minLength": 1},
    "key_file": {"type": "string", "minLength": 1},
    "server_name": {"type": "string"},
    "insecure_skip_verify": {"type": "boolean"}
  },
  "dependentRequired": {"cert_file": ["key_file"], "key_file": ["cert_file"]}
}`

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "anyOf": [{"required": ["splunk"]}, {"required": ["syslog"]}, {"required": ["elastic"]}],
  "properties": {
    "events": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "exclude_events": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "include_data": {"type": "boolean"},
    "timeout": {"type": "string"},
    "splunk": {
      "type": "object",
      "additionalProperties": false,
      "required": ["url", "token"],
      "properties": {
        "url": {"type": "string", "pattern": "^https?://"},
        "token": {"type": "string", "minLength": 1},
        "index": {"type": "string"},
        "sourcetype": {"type": "string"},
        "source": {"type": "string"},
        "host": {"type": "string"},
        "channel": {"type": "string"},
        "tls": ` + tlsSchema + `
      }
    },
    "syslog": {
      "type": "object",
      "additionalProperties": false,
      "required": ["address"],
      "properties": {
        "address": {"type": "string", "pattern": "^.+:[0-9]+$"},
        "network": {"enum": ["tcp", "tls", "udp"]},
        "format": {"enum": ["json", "cef"]},
        "framing": {"enum": ["octet_counting", "non_transparent"]},
        "facility": {"type": "integer", "minimum": 0, "maximum": 23},
        "severity": {"type": "integer", "minimum": 0, "maximum": 7},
        "app_name": {"type": "string", "pattern": "^[!-~]{1,48}$"},
        "hostname": {"type": "string", "pattern": "^[!-~]{1,255}$"},
        "sd_id": {"type": "string", "pattern": "^[!-~]+@[0-9]+(\\.[0-9]+)*$"},
        "tls": ` + tlsSchema + `
      }
    },
    "elastic": {
      "type": "object",
      "additionalProperties": false,
      "required": ["url"],
      "properties": {
        "url": {"type": "string", "pattern": "^https?://"},
        "username": {"type": "string"},
        "password": {"type": "string"},
        "api_key": {"type": "string"},
        "index_prefix": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]*$"},
        "index_date_format": {"type": "string"},
        "pipeline": {"type": "string"},
        "tls": ` + tlsSchema + `
      },
      "not": {"required": ["api_key", "username"]},
      "dependentRequired": {"password": ["username"]}
    }
  }
}`)

// Plugin is the SIEM export plugin.
type Plugin struct {
	cfg     Config
	timeout time.Duration
	log     *slog.Logger
	now     func() time.Time

	splunk  *splunkSink
	syslog  *syslogSink
	elastic *elasticSink

	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "siem",
		Name:         "SIEM export",
		Version:      version,
		Description:  "Exports events as an audit trail to Splunk HEC, syslog (RFC 5424, JSON or CEF) and Elasticsearch/OpenSearch.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	p.log = r.Logger()
	if p.now == nil {
		p.now = time.Now
	}
	if err := p.applyConfig(); err != nil {
		return err
	}
	filter := sdk.EventFilter{Types: p.cfg.Events}
	if p.splunk != nil {
		r.Subscribe("splunk", filter, p.handler("splunk"))
	}
	if p.syslog != nil {
		r.Subscribe("syslog", filter, p.handler("syslog"))
	}
	if p.elastic != nil {
		r.Subscribe("elastic", filter, p.handler("elastic"))
	}
	return nil
}

func (p *Plugin) applyConfig() error {
	c := &p.cfg
	if c.Splunk == nil && c.Syslog == nil && c.Elastic == nil {
		return errors.New("configure at least one of splunk, syslog or elastic")
	}
	for _, list := range [][]string{c.Events, c.ExcludeEvents} {
		for _, pat := range list {
			if _, err := path.Match(pat, ""); err != nil || pat == "" {
				return fmt.Errorf("events: invalid pattern %q", pat)
			}
		}
	}
	p.timeout = 10 * time.Second
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
		p.timeout = d
	}
	var err error
	if c.Splunk != nil {
		if p.splunk, err = newSplunkSink(*c.Splunk, p.timeout); err != nil {
			return fmt.Errorf("splunk: %w", err)
		}
	}
	if c.Syslog != nil {
		if p.syslog, err = newSyslogSink(*c.Syslog, p.timeout); err != nil {
			return fmt.Errorf("syslog: %w", err)
		}
	}
	if c.Elastic != nil {
		if p.elastic, err = newElasticSink(*c.Elastic, p.timeout); err != nil {
			return fmt.Errorf("elastic: %w", err)
		}
	}
	return nil
}

// handler adapts a sink ("splunk", "syslog" or "elastic") to an event
// handler.
func (p *Plugin) handler(sink string) sdk.EventHandler {
	return func(ctx context.Context, e sdk.Event) error { return p.export(ctx, sink, e) }
}

// export sends an event to a sink, applying exclusions.
func (p *Plugin) export(ctx context.Context, sink string, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.export(ctx, sink, e)
	}
	if p.excluded(e.Type) {
		return nil
	}
	r := p.record(e)
	switch sink {
	case "splunk":
		return p.splunk.send(ctx, r)
	case "syslog":
		return p.syslog.send(ctx, r)
	default:
		return p.elastic.send(ctx, r)
	}
}

func (p *Plugin) excluded(typ string) bool {
	for _, pat := range p.cfg.ExcludeEvents {
		if ok, _ := path.Match(pat, typ); ok {
			return true
		}
	}
	return false
}

// Health checks every configured sink.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	var errs []error
	if p.splunk != nil {
		if err := p.splunk.health(ctx); err != nil {
			errs = append(errs, fmt.Errorf("splunk: %w", err))
		}
	}
	if p.syslog != nil {
		if err := p.syslog.health(ctx); err != nil {
			errs = append(errs, fmt.Errorf("syslog: %w", err))
		}
	}
	if p.elastic != nil {
		if err := p.elastic.health(ctx); err != nil {
			errs = append(errs, fmt.Errorf("elastic: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Stop closes the syslog connection.
func (p *Plugin) Stop(context.Context) error {
	var errs []error
	if n := p.next.Load(); n != nil && n.syslog != nil {
		errs = append(errs, n.syslog.close())
	}
	if p.syslog != nil {
		errs = append(errs, p.syslog.close())
	}
	return errors.Join(errs...)
}

// Reconfigure applies new sink settings (URLs, tokens, credentials, TLS
// files, index, syslog address and format, ...), exclude_events,
// include_data and the timeout without a restart. The events filter and
// which sinks are configured are fixed at startup. The previous syslog
// connection is closed once the new configuration is in place; an event
// still being written on it fails and is retried.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{log: p.log, now: p.now}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if !slices.Equal(n.cfg.Events, p.cfg.Events) ||
		(n.cfg.Splunk == nil) != (p.cfg.Splunk == nil) ||
		(n.cfg.Syslog == nil) != (p.cfg.Syslog == nil) ||
		(n.cfg.Elastic == nil) != (p.cfg.Elastic == nil) {
		return errors.New("events and adding or removing a sink take effect after a restart")
	}
	if err := n.applyConfig(); err != nil {
		return err
	}
	old := p.next.Swap(n)
	if old == nil {
		old = p
	}
	// Requests in flight keep their connections; only idle ones are closed.
	if old.splunk != nil {
		old.splunk.client.CloseIdleConnections()
	}
	if old.elastic != nil {
		old.elastic.client.CloseIdleConnections()
	}
	if old.syslog != nil {
		if err := old.syslog.close(); err != nil && p.log != nil {
			p.log.Warn("closing the previous syslog connection", "err", err)
		}
	}
	return nil
}

// Record is the audit record exported for every event. Splunk receives it
// as the event body, syslog as the JSON message (or CEF extension fields),
// and Elasticsearch under "tenarium" next to ECS fields.
type Record struct {
	Time     time.Time `json:"time"`
	ID       string    `json:"id"`
	Type     string    `json:"type"`
	Seq      int64     `json:"seq"`
	Source   string    `json:"source,omitempty"`
	Subject  string    `json:"subject,omitempty"`
	TenantID string    `json:"tenant_id,omitempty"`
	// TenantSlug and TenantName are set for tenant.* events.
	TenantSlug string `json:"tenant_slug,omitempty"`
	TenantName string `json:"tenant_name,omitempty"`
	// Actor is the raw actor; ActorType is the part before the first ":"
	// ("system" when there is none) and ActorID the rest.
	Actor     string `json:"actor,omitempty"`
	ActorType string `json:"actor_type,omitempty"`
	ActorID   string `json:"actor_id,omitempty"`
	// Outcome is "failure" for *_failed and quota events, else "success".
	Outcome string          `json:"outcome"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (p *Plugin) record(e sdk.Event) Record {
	r := Record{
		Time: e.Time.UTC(), ID: e.ID, Type: e.Type, Seq: e.Seq, Source: e.Source, Subject: e.Subject,
		TenantID: e.TenantID, Actor: e.Actor, Outcome: "success",
	}
	if r.Time.IsZero() {
		r.Time = p.now().UTC()
	}
	if r.Actor != "" {
		typ, id, ok := strings.Cut(r.Actor, ":")
		if ok {
			r.ActorType, r.ActorID = typ, id
		} else {
			r.ActorType, r.ActorID = r.Actor, ""
		}
	}
	if failure(e.Type) {
		r.Outcome = "failure"
	}
	if strings.HasPrefix(e.Type, "tenant.") && len(e.Data) > 0 {
		var d struct {
			Tenant *struct {
				ID   string `json:"id"`
				Slug string `json:"slug"`
				Name string `json:"name"`
			} `json:"tenant"`
		}
		if json.Unmarshal(e.Data, &d) == nil && d.Tenant != nil {
			r.TenantSlug, r.TenantName = d.Tenant.Slug, d.Tenant.Name
			r.TenantID = cmp.Or(r.TenantID, d.Tenant.ID)
		}
	}
	if p.cfg.IncludeData == nil || *p.cfg.IncludeData {
		r.Data = e.Data
	}
	return r
}

// failure reports whether an event type denotes a failed or refused action.
func failure(typ string) bool {
	return strings.HasSuffix(typ, "_failed") || typ == sdk.EventTenantQuotaExceeded || typ == sdk.EventUserLocked
}

// fields returns the record's key attributes as strings, in a stable
// order, for indexed fields and structured data.
func (r Record) fields() [][2]string {
	out := [][2]string{{"event_id", r.ID}, {"event_type", r.Type}, {"seq", strconv.FormatInt(r.Seq, 10)}}
	for _, kv := range [][2]string{
		{"tenant_id", r.TenantID}, {"tenant_slug", r.TenantSlug}, {"actor", r.Actor},
		{"actor_type", r.ActorType}, {"actor_id", r.ActorID}, {"outcome", r.Outcome},
	} {
		if kv[1] != "" {
			out = append(out, kv)
		}
	}
	return out
}
