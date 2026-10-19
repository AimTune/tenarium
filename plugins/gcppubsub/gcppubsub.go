// Package gcppubsub publishes events to a Google Cloud Pub/Sub topic as
// CloudEvents (plugin ID "gcp-pubsub").
//
// It calls the Pub/Sub REST API (topics.publish) directly. The message data
// is the structured CloudEvent JSON; the attributes ce-id, ce-type,
// ce-source, ce-specversion, tenant_id and content-type allow subscription
// filters without decoding the body. With ordering enabled, the tenant ID is
// the ordering key, so subscriptions with message ordering receive each
// tenant's events in order.
//
// Credentials are a service account key file or JSON, or Application
// Default Credentials. With emulator, requests go to the endpoint without
// authentication.
package gcppubsub

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func init() {
	sdk.Register("gcp-pubsub", func() sdk.Plugin { return &Plugin{} })
}

const (
	// DefaultEndpoint is the global Pub/Sub REST endpoint.
	DefaultEndpoint = "https://pubsub.googleapis.com"
	// DefaultEmulatorEndpoint is used with emulator and no endpoint.
	DefaultEmulatorEndpoint = "http://localhost:8085"
	// GlobalOrderingKey orders events without a tenant (plan.*).
	GlobalOrderingKey = "global"

	scope = "https://www.googleapis.com/auth/pubsub"
)

type Config struct {
	Project string   `json:"project"`
	Topic   string   `json:"topic"`
	Events  []string `json:"events"`
	// Endpoint overrides the API base URL, e.g. a regional endpoint
	// (https://europe-west1-pubsub.googleapis.com) or the emulator.
	Endpoint string `json:"endpoint"`
	// Emulator disables authentication (for the Pub/Sub emulator).
	Emulator bool `json:"emulator"`
	// CredentialsFile / CredentialsJSON hold a service account key (or
	// another Google credential configuration). Default: ADC.
	CredentialsFile string `json:"credentials_file"`
	CredentialsJSON string `json:"credentials_json"`
	// Ordering sets the ordering key to the tenant ID.
	Ordering bool `json:"ordering"`
	// Attributes are added to every message.
	Attributes map[string]string `json:"attributes"`
	// Timeout bounds one API request (default 30s).
	Timeout string `json:"timeout"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "project": {"type": "string", "pattern": "^[a-z][a-z0-9.:-]{4,}[a-z0-9]$"},
    "topic": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9._~+%-]{2,254}$"},
    "events": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "endpoint": {"type": "string", "pattern": "^https?://"},
    "emulator": {"type": "boolean"},
    "credentials_file": {"type": "string", "minLength": 1},
    "credentials_json": {"type": "string", "minLength": 1},
    "ordering": {"type": "boolean"},
    "attributes": {"type": "object", "additionalProperties": {"type": "string"}},
    "timeout": {"type": "string"}
  },
  "required": ["project", "topic"],
  "not": {"required": ["credentials_file", "credentials_json"]},
  "additionalProperties": false
}`)

var (
	projectRe = regexp.MustCompile(`^[a-z][a-z0-9.:-]{4,}[a-z0-9]$`)
	topicRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._~+%-]{2,254}$`)
)

// Attribute keys set by the plugin; they cannot be overridden.
var reservedAttributes = []string{"ce-id", "ce-type", "ce-source", "ce-specversion", "ce-subject", "tenant_id", "content-type"}

type Plugin struct {
	cfg      Config
	log      *slog.Logger
	client   *http.Client
	topicURL string // https://.../v1/projects/p/topics/t
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "gcp-pubsub",
		Name:         "Google Cloud Pub/Sub Publisher",
		Version:      "0.1.0",
		Description:  "Publishes tenant events to a Google Cloud Pub/Sub topic as CloudEvents.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	p.log = r.Logger()
	if err := p.setup(); err != nil {
		return err
	}
	r.Subscribe("publish", sdk.EventFilter{Types: p.cfg.Events}, p.publish)
	return nil
}

// setup validates the configuration and builds the (authenticated) client.
func (p *Plugin) setup() error {
	timeout, err := p.validate()
	if err != nil {
		return err
	}
	p.client = &http.Client{Timeout: timeout}
	if !p.cfg.Emulator {
		ts, err := p.tokenSource()
		if err != nil {
			return err
		}
		p.client.Transport = &oauth2.Transport{Source: ts}
	}
	return nil
}

// Reconfigure applies a new project, topic, endpoint, credentials,
// emulator mode, ordering, attributes or timeout without a restart (e.g.
// credential rotation). The plugin holds no connections of its own:
// in-flight publishes finish with the previous client. The event filter is
// fixed at startup.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{log: p.log}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if !slices.Equal(n.cfg.Events, p.cfg.Events) {
		return errors.New("gcp-pubsub: events take effect after a restart")
	}
	if err := n.setup(); err != nil {
		return err
	}
	p.next.Store(n)
	return nil
}

func (p *Plugin) validate() (time.Duration, error) {
	c := &p.cfg
	if !projectRe.MatchString(c.Project) {
		return 0, fmt.Errorf("gcp-pubsub: invalid project ID %q", c.Project)
	}
	if !topicRe.MatchString(c.Topic) || strings.HasPrefix(c.Topic, "goog") {
		return 0, fmt.Errorf("gcp-pubsub: invalid topic name %q", c.Topic)
	}
	if c.CredentialsFile != "" && c.CredentialsJSON != "" {
		return 0, errors.New("gcp-pubsub: credentials_file and credentials_json are mutually exclusive")
	}
	if c.Emulator && (c.CredentialsFile != "" || c.CredentialsJSON != "") {
		return 0, errors.New("gcp-pubsub: the emulator takes no credentials")
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
		if c.Emulator {
			endpoint = DefaultEmulatorEndpoint
		}
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return 0, fmt.Errorf("gcp-pubsub: endpoint must be an http(s) URL, got %q", c.Endpoint)
	}
	if u.Scheme == "http" && !c.Emulator {
		return 0, errors.New("gcp-pubsub: a plain-http endpoint is only allowed with emulator (credentials would be sent in clear text)")
	}
	for k := range c.Attributes {
		if k == "" || len(k) > 256 || strings.HasPrefix(k, "goog") || slices.Contains(reservedAttributes, k) {
			return 0, fmt.Errorf("gcp-pubsub: attribute key %q is invalid or reserved", k)
		}
	}
	p.topicURL = strings.TrimRight(endpoint, "/") + "/v1/projects/" + c.Project + "/topics/" + c.Topic
	timeout := 30 * time.Second
	if c.Timeout != "" {
		timeout, err = time.ParseDuration(c.Timeout)
		if err != nil || timeout <= 0 {
			return 0, fmt.Errorf("gcp-pubsub: timeout: invalid duration %q", c.Timeout)
		}
	}
	return timeout, nil
}

// tokenSource loads credentials from the configuration or ADC. Only the
// standard Google credential types are accepted.
//
// Token sources keep the context they are created with for later refreshes,
// so they get context.Background rather than Init's context.
func (p *Plugin) tokenSource() (oauth2.TokenSource, error) {
	raw := []byte(p.cfg.CredentialsJSON)
	if p.cfg.CredentialsFile != "" {
		b, err := os.ReadFile(p.cfg.CredentialsFile)
		if err != nil {
			return nil, fmt.Errorf("gcp-pubsub: credentials_file: %w", err)
		}
		raw = b
	}
	if len(raw) == 0 {
		creds, err := google.FindDefaultCredentials(context.Background(), scope)
		if err != nil {
			return nil, fmt.Errorf("gcp-pubsub: application default credentials: %w", err)
		}
		return creds.TokenSource, nil
	}
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("gcp-pubsub: credentials are not JSON: %w", err)
	}
	t := google.CredentialsType(head.Type)
	switch t {
	case google.ServiceAccount, google.AuthorizedUser, google.ExternalAccount, google.ImpersonatedServiceAccount:
	default:
		return nil, fmt.Errorf("gcp-pubsub: unsupported credentials type %q", head.Type)
	}
	creds, err := google.CredentialsFromJSONWithType(context.Background(), raw, t, scope)
	if err != nil {
		return nil, fmt.Errorf("gcp-pubsub: credentials: %w", err)
	}
	return creds.TokenSource, nil
}

type pubsubMessage struct {
	Data        string            `json:"data"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	OrderingKey string            `json:"orderingKey,omitempty"`
}

func (p *Plugin) message(e sdk.Event) (pubsubMessage, error) {
	ce := e.CloudEvent()
	body, err := json.Marshal(ce)
	if err != nil {
		return pubsubMessage{}, err
	}
	attrs := maps.Clone(p.cfg.Attributes)
	if attrs == nil {
		attrs = map[string]string{}
	}
	set := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	set("ce-id", ce.ID)
	set("ce-type", ce.Type)
	set("ce-source", ce.Source)
	set("ce-specversion", ce.SpecVersion)
	set("ce-subject", ce.Subject)
	set("tenant_id", ce.TenantID)
	set("content-type", "application/cloudevents+json")
	m := pubsubMessage{Data: base64.StdEncoding.EncodeToString(body), Attributes: attrs}
	if p.cfg.Ordering {
		m.OrderingKey = cmp.Or(e.TenantID, GlobalOrderingKey)
	}
	return m, nil
}

func (p *Plugin) publish(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.publish(ctx, e)
	}
	m, err := p.message(e)
	if err != nil {
		return err
	}
	var out struct {
		MessageIDs []string `json:"messageIds"`
	}
	if err := p.call(ctx, http.MethodPost, ":publish", map[string]any{"messages": []pubsubMessage{m}}, &out); err != nil {
		return fmt.Errorf("gcp-pubsub: publish %s: %w", e.ID, err)
	}
	if len(out.MessageIDs) != 1 {
		return fmt.Errorf("gcp-pubsub: publish %s: expected 1 message ID, got %d", e.ID, len(out.MessageIDs))
	}
	return nil
}

// Health checks that the topic exists and, outside the emulator, that the
// credentials may publish to it.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	if p.client == nil {
		return errors.New("gcp-pubsub: not initialized")
	}
	if p.cfg.Emulator {
		if err := p.call(ctx, http.MethodGet, "", nil, nil); err != nil {
			return fmt.Errorf("gcp-pubsub: topic %s: %w", p.cfg.Topic, err)
		}
		return nil
	}
	var out struct {
		Permissions []string `json:"permissions"`
	}
	if err := p.call(ctx, http.MethodPost, ":testIamPermissions",
		map[string]any{"permissions": []string{"pubsub.topics.publish"}}, &out); err != nil {
		return fmt.Errorf("gcp-pubsub: topic %s: %w", p.cfg.Topic, err)
	}
	if !slices.Contains(out.Permissions, "pubsub.topics.publish") {
		return fmt.Errorf("gcp-pubsub: missing permission pubsub.topics.publish on topic %s", p.cfg.Topic)
	}
	return nil
}

// apiError is the Google API error envelope.
type apiError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

func (p *Plugin) call(ctx context.Context, method, suffix string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.topicURL+suffix, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var ae apiError
		if json.Unmarshal(raw, &ae) == nil && ae.Error.Message != "" {
			return fmt.Errorf("HTTP %d %s: %s", resp.StatusCode, ae.Error.Status, ae.Error.Message)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
