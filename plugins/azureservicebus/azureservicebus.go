// Package azureservicebus publishes events to an Azure Service Bus queue or
// topic as CloudEvents (plugin ID "azure-servicebus").
//
// It uses the Service Bus REST API (POST /{entity}/messages) with Shared
// Access Signature authentication, so it needs nothing beyond the standard
// library. The body is the structured CloudEvent JSON; BrokerProperties
// carry MessageId = event ID (used by duplicate detection), Label = event
// type and, with session enabled, SessionId = tenant ID. The custom
// properties ce_id, ce_type, ce_source, ce_specversion and tenant_id are
// set on every message for subscription SQL filters.
package azureservicebus

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("azure-servicebus", func() sdk.Plugin { return &Plugin{} })
}

const (
	// GlobalSession is the session of events without a tenant (plan.*).
	GlobalSession = "global"
	apiVersion    = "2017-04"
)

type Config struct {
	// ConnectionString is a namespace or entity connection string:
	// Endpoint=sb://<ns>.servicebus.windows.net/;SharedAccessKeyName=...;SharedAccessKey=...[;EntityPath=...]
	ConnectionString string `json:"connection_string"`
	// Entity is the queue or topic name; it defaults to EntityPath.
	Entity string   `json:"entity"`
	Events []string `json:"events"`
	// Session sets SessionId to the tenant ID (required by session-enabled entities).
	Session bool `json:"session"`
	// Properties are custom properties added to every message.
	Properties map[string]string `json:"properties"`
	// TimeToLive sets the message TTL, e.g. "168h"; empty uses the entity default.
	TimeToLive string `json:"time_to_live"`
	// Endpoint overrides the namespace URL derived from the connection
	// string (https://<ns>.servicebus.windows.net), e.g. for a proxy.
	Endpoint string `json:"endpoint"`
	// TokenTTL is the SAS token lifetime (default 1h).
	TokenTTL string `json:"token_ttl"`
	// Timeout bounds one request (default 30s).
	Timeout string `json:"timeout"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "connection_string": {"type": "string", "pattern": "Endpoint="},
    "entity": {"type": "string", "minLength": 1, "maxLength": 260},
    "events": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "session": {"type": "boolean"},
    "properties": {
      "type": "object",
      "propertyNames": {"pattern": "^[A-Za-z0-9_.-]+$"},
      "additionalProperties": {"type": "string"}
    },
    "time_to_live": {"type": "string"},
    "endpoint": {"type": "string", "pattern": "^https?://"},
    "token_ttl": {"type": "string"},
    "timeout": {"type": "string"}
  },
  "required": ["connection_string"],
  "additionalProperties": false
}`)

// Custom properties set by the plugin.
var reservedProperties = []string{"ce_id", "ce_type", "ce_source", "ce_specversion", "tenant_id"}

var (
	propertyRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	entityRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
)

// ConnectionString is a parsed Service Bus connection string.
type ConnectionString struct {
	Endpoint string // sb://ns.servicebus.windows.net/
	KeyName  string
	Key      string
	// SAS is a pre-generated SharedAccessSignature, used instead of a key.
	SAS        string
	EntityPath string
}

// ParseConnectionString parses "Key=Value;..." pairs. Values may contain
// "=" (base64 keys), so each pair is split at the first "=" only.
func ParseConnectionString(s string) (ConnectionString, error) {
	var cs ConnectionString
	for part := range strings.SplitSeq(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return cs, fmt.Errorf("connection string: malformed segment %q", redactSegment(part))
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "endpoint":
			cs.Endpoint = v
		case "sharedaccesskeyname":
			cs.KeyName = v
		case "sharedaccesskey":
			cs.Key = v
		case "sharedaccesssignature":
			cs.SAS = v
		case "entitypath":
			cs.EntityPath = v
		case "usedevelopmentemulator":
			return cs, errors.New("connection string: the Service Bus emulator only speaks AMQP, which this plugin does not use")
		default:
			return cs, fmt.Errorf("connection string: unknown key %q", k)
		}
	}
	if cs.Endpoint == "" {
		return cs, errors.New("connection string: Endpoint is required")
	}
	if cs.SAS == "" && (cs.KeyName == "" || cs.Key == "") {
		return cs, errors.New("connection string: SharedAccessKeyName and SharedAccessKey (or SharedAccessSignature) are required")
	}
	if cs.SAS != "" && !strings.HasPrefix(cs.SAS, "SharedAccessSignature ") {
		return cs, errors.New("connection string: SharedAccessSignature must start with \"SharedAccessSignature \"")
	}
	return cs, nil
}

func redactSegment(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}

// SASToken returns a Service Bus SAS token for resourceURI valid until
// expiry: HMAC-SHA256 over "<url-encoded uri>\n<expiry unix>" keyed with
// the shared access key.
func SASToken(resourceURI, keyName, key string, expiry time.Time) string {
	sr := url.QueryEscape(resourceURI)
	se := strconv.FormatInt(expiry.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(sr + "\n" + se))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("SharedAccessSignature sr=%s&sig=%s&se=%s&skn=%s", sr, url.QueryEscape(sig), se, url.QueryEscape(keyName))
}

type Plugin struct {
	cfg      Config
	cs       ConnectionString
	log      *slog.Logger
	client   *http.Client
	baseURL  string // https://ns.servicebus.windows.net
	resource string // https://ns.servicebus.windows.net/entity (SAS audience)
	tokenTTL time.Duration
	ttl      time.Duration
	now      func() time.Time

	mu       sync.Mutex
	token    string
	tokenExp time.Time

	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "azure-servicebus",
		Name:         "Azure Service Bus Publisher",
		Version:      "0.1.0",
		Description:  "Publishes tenant events to an Azure Service Bus queue or topic as CloudEvents.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	p.log = r.Logger()
	timeout, err := p.validate()
	if err != nil {
		return err
	}
	p.client = &http.Client{Timeout: timeout}
	r.Subscribe("publish", sdk.EventFilter{Types: p.cfg.Events}, p.publish)
	return nil
}

// Reconfigure applies a new connection string (e.g. key rotation), entity,
// session, properties, TTLs, endpoint or timeout without a restart; the
// SAS token is re-issued with the new key. The plugin holds no connections
// of its own: in-flight publishes finish with the previous client. The
// event filter is fixed at startup.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{log: p.log}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if !slices.Equal(n.cfg.Events, p.cfg.Events) {
		return errors.New("azure-servicebus: events take effect after a restart")
	}
	timeout, err := n.validate()
	if err != nil {
		return err
	}
	n.now = p.now
	n.client = &http.Client{Timeout: timeout}
	p.next.Store(n)
	return nil
}

func (p *Plugin) validate() (time.Duration, error) {
	c := &p.cfg
	p.now = time.Now
	cs, err := ParseConnectionString(c.ConnectionString)
	if err != nil {
		return 0, fmt.Errorf("azure-servicebus: %w", err)
	}
	p.cs = cs
	if c.Entity == "" {
		c.Entity = cs.EntityPath
	} else if cs.EntityPath != "" && !strings.EqualFold(cs.EntityPath, c.Entity) {
		return 0, fmt.Errorf("azure-servicebus: entity %q differs from the connection string's EntityPath %q", c.Entity, cs.EntityPath)
	}
	if c.Entity == "" {
		return 0, errors.New("azure-servicebus: entity is required (or EntityPath in the connection string)")
	}
	if !entityRe.MatchString(c.Entity) || len(c.Entity) > 260 || strings.Contains(c.Entity, "..") {
		return 0, fmt.Errorf("azure-servicebus: invalid entity name %q", c.Entity)
	}
	ep, err := url.Parse(cs.Endpoint)
	if err != nil || ep.Host == "" {
		return 0, fmt.Errorf("azure-servicebus: invalid Endpoint %q", cs.Endpoint)
	}
	p.baseURL = "https://" + ep.Host
	p.resource = p.baseURL + "/" + c.Entity
	if c.Endpoint != "" {
		u, err := url.Parse(c.Endpoint)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return 0, fmt.Errorf("azure-servicebus: invalid endpoint %q", c.Endpoint)
		}
		if u.Scheme == "http" && !isLoopback(u.Hostname()) {
			return 0, errors.New("azure-servicebus: a plain-http endpoint is only allowed on loopback")
		}
		p.baseURL = strings.TrimRight(c.Endpoint, "/")
	}
	for k := range c.Properties {
		if !propertyRe.MatchString(k) || slices.Contains(reservedProperties, k) || strings.EqualFold(k, "BrokerProperties") {
			return 0, fmt.Errorf("azure-servicebus: property name %q is invalid or reserved", k)
		}
	}
	if p.tokenTTL, err = parseDuration("token_ttl", c.TokenTTL, time.Hour); err != nil {
		return 0, err
	}
	if p.tokenTTL < time.Minute*10 {
		return 0, errors.New("azure-servicebus: token_ttl must be at least 10m")
	}
	if p.ttl, err = parseDuration("time_to_live", c.TimeToLive, 0); err != nil {
		return 0, err
	}
	return parseDuration("timeout", c.Timeout, 30*time.Second)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// authorization returns a cached SAS token, renewed 5 minutes before expiry.
func (p *Plugin) authorization() string {
	if p.cs.SAS != "" {
		return p.cs.SAS
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if p.token == "" || now.Add(5*time.Minute).After(p.tokenExp) {
		p.tokenExp = now.Add(p.tokenTTL)
		p.token = SASToken(p.resource, p.cs.KeyName, p.cs.Key, p.tokenExp)
	}
	return p.token
}

type brokerProperties struct {
	MessageID  string `json:"MessageId"`
	SessionID  string `json:"SessionId,omitempty"`
	Label      string `json:"Label,omitempty"`
	TimeToLive int64  `json:"TimeToLive,omitempty"` // seconds
}

func (p *Plugin) request(ctx context.Context, e sdk.Event) (*http.Request, error) {
	ce := e.CloudEvent()
	body, err := json.Marshal(ce)
	if err != nil {
		return nil, err
	}
	bp := brokerProperties{MessageID: e.ID, Label: e.Type, TimeToLive: int64(p.ttl / time.Second)}
	if p.cfg.Session {
		bp.SessionID = cmp.Or(e.TenantID, GlobalSession)
	}
	bpJSON, err := json.Marshal(bp)
	if err != nil {
		return nil, err
	}
	u := p.baseURL + "/" + p.cfg.Entity + "/messages?api-version=" + apiVersion + "&timeout=60"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", p.authorization())
	req.Header.Set("Content-Type", "application/cloudevents+json")
	req.Header.Set("BrokerProperties", string(bpJSON))
	// Custom properties: the header name is the property name (set
	// directly to keep its case) and string values are JSON-quoted.
	setProp := func(k, v string) {
		if v != "" {
			q, _ := json.Marshal(v)
			req.Header[k] = []string{string(q)}
		}
	}
	for k, v := range p.cfg.Properties {
		setProp(k, v)
	}
	setProp("ce_id", ce.ID)
	setProp("ce_type", ce.Type)
	setProp("ce_source", ce.Source)
	setProp("ce_specversion", ce.SpecVersion)
	setProp("tenant_id", ce.TenantID)
	return req, nil
}

func (p *Plugin) publish(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.publish(ctx, e)
	}
	req, err := p.request(ctx, e)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("azure-servicebus: send %s: %w", e.ID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode/100 != 2 {
		return fmt.Errorf("azure-servicebus: send %s: %s", e.ID, responseError(resp))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return nil
}

// Health reads the entity description. A Send-only key may not read it;
// a "claims required" 401 still proves the namespace is reachable and the
// signature valid, so it counts as healthy.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	if p.client == nil {
		return errors.New("azure-servicebus: not initialized")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/"+p.cfg.Entity+"?api-version="+apiVersion, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", p.authorization())
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("azure-servicebus: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == http.StatusOK:
		if !bytes.Contains(raw, []byte("<entry")) {
			return fmt.Errorf("azure-servicebus: entity %s not found", p.cfg.Entity)
		}
		return nil
	case resp.StatusCode == http.StatusUnauthorized && bytes.Contains(bytes.ToLower(raw), []byte("claims required")):
		return nil
	default:
		return fmt.Errorf("azure-servicebus: entity %s: HTTP %d: %s", p.cfg.Entity, resp.StatusCode, summarize(raw))
	}
}

func responseError(resp *http.Response) string {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return fmt.Sprintf("HTTP %d: %s", resp.StatusCode, summarize(raw))
}

var detailRe = regexp.MustCompile(`(?s)<Detail>(.*?)</Detail>`)

// summarize extracts the <Detail> of a Service Bus XML error, or trims the body.
func summarize(raw []byte) string {
	if m := detailRe.FindSubmatch(raw); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func parseDuration(field, s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("azure-servicebus: %s: invalid duration %q", field, s)
	}
	return d, nil
}
