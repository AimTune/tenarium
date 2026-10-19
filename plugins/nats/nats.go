// Package nats publishes events to NATS JetStream as CloudEvents.
//
// Each event becomes one JetStream message on a subject rendered from a
// template over the event (default "tenarium.{{or .TenantID "global"}}.{{.Type}}"),
// so consumers can subscribe per tenant or per event type with NATS wildcards.
// The body is the structured CloudEvent JSON. The Nats-Msg-Id header carries
// the event ID: JetStream drops a republished event inside the stream's
// duplicate window, which turns Tenarium's at-least-once delivery into
// effectively-once storage for retries within that window.
package nats

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func init() {
	sdk.Register("nats", func() sdk.Plugin { return &Plugin{} })
}

// DefaultSubject is the subject template used when none is configured.
const DefaultSubject = `tenarium.{{or .TenantID "global"}}.{{.Type}}`

type Config struct {
	// URL is one or more comma-separated server URLs (nats://, tls://).
	URL string `json:"url"`
	// Subject is a text/template over sdk.Event.
	Subject string   `json:"subject"`
	Events  []string `json:"events"`
	// Name is the client connection name (default "tenarium").
	Name string `json:"name"`
	// Timeout bounds connecting and each publish acknowledgement (default 10s).
	Timeout string `json:"timeout"`

	// Authentication: at most one method.
	CredsFile    string `json:"creds_file"`
	NkeySeed     string `json:"nkey_seed"`
	NkeySeedFile string `json:"nkey_seed_file"`
	Token        string `json:"token"`
	Username     string `json:"username"`
	Password     string `json:"password"`

	TLS    *TLSConfig    `json:"tls"`
	Stream *StreamConfig `json:"stream"`
}

type TLSConfig struct {
	Enabled            bool   `json:"enabled"`
	CAFile             string `json:"ca_file"`
	CertFile           string `json:"cert_file"`
	KeyFile            string `json:"key_file"`
	ServerName         string `json:"server_name"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

// StreamConfig names the stream that must capture the subjects. Publishes
// are rejected by the server if the subject lands in another stream.
type StreamConfig struct {
	Name string `json:"name"`
	// Create creates the stream if it does not exist. An existing stream is
	// never modified.
	Create   bool     `json:"create"`
	Subjects []string `json:"subjects"`
	// Storage is "file" (default) or "memory".
	Storage  string `json:"storage"`
	Replicas int    `json:"replicas"`
	// MaxAge limits message age, e.g. "720h"; empty keeps messages forever.
	MaxAge string `json:"max_age"`
	// DuplicateWindow is the Nats-Msg-Id dedupe window (default server 2m).
	DuplicateWindow string `json:"duplicate_window"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "url": {"type": "string", "minLength": 1},
    "subject": {"type": "string", "minLength": 1},
    "events": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "name": {"type": "string"},
    "timeout": {"type": "string"},
    "creds_file": {"type": "string", "minLength": 1},
    "nkey_seed": {"type": "string", "minLength": 1},
    "nkey_seed_file": {"type": "string", "minLength": 1},
    "token": {"type": "string", "minLength": 1},
    "username": {"type": "string", "minLength": 1},
    "password": {"type": "string"},
    "tls": {
      "type": "object",
      "properties": {
        "enabled": {"type": "boolean"},
        "ca_file": {"type": "string"},
        "cert_file": {"type": "string"},
        "key_file": {"type": "string"},
        "server_name": {"type": "string"},
        "insecure_skip_verify": {"type": "boolean"}
      },
      "additionalProperties": false
    },
    "stream": {
      "type": "object",
      "properties": {
        "name": {"type": "string", "pattern": "^[^\\s.*>/\\\\]+$"},
        "create": {"type": "boolean"},
        "subjects": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "storage": {"enum": ["file", "memory"]},
        "replicas": {"type": "integer", "minimum": 1, "maximum": 5},
        "max_age": {"type": "string"},
        "duplicate_window": {"type": "string"}
      },
      "required": ["name"],
      "additionalProperties": false
    }
  },
  "required": ["url"],
  "additionalProperties": false
}`)

// publisher is the part of jetstream.JetStream the plugin uses; tests fake it.
type publisher interface {
	PublishMsg(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

type Plugin struct {
	cfg     Config
	log     *slog.Logger
	subject *template.Template
	timeout time.Duration

	nc  *nats.Conn
	js  jetstream.JetStream
	pub publisher

	mu            sync.Mutex
	streamEnsured bool
	streamCfg     *jetstream.StreamConfig

	// inflight is read-held by publishes and health checks on this copy;
	// Reconfigure write-locks it to wait for them before it sets retired
	// and closes the connection this copy no longer passes on.
	inflight sync.RWMutex
	retired  bool

	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
	// reconfMu serializes Reconfigure and Stop.
	reconfMu sync.Mutex
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

// acquire returns the copy holding the active configuration, read-locked
// against retirement; the caller must call c.inflight.RUnlock.
func (p *Plugin) acquire() *Plugin {
	for {
		c := p.next.Load()
		if c == nil {
			c = p
		}
		c.inflight.RLock()
		if !c.retired {
			return c
		}
		// Retired after it was loaded: p.next already holds its successor.
		c.inflight.RUnlock()
	}
}

// connect opens the connection. Without retry, an unreachable server is
// an error instead of being retried in the background.
func (p *Plugin) connect(retry bool) error {
	opts, err := p.connectOptions()
	if err != nil {
		return err
	}
	opts = append(opts, nats.RetryOnFailedConnect(retry))
	nc, err := nats.Connect(p.cfg.URL, opts...)
	if err != nil {
		return fmt.Errorf("nats: connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return fmt.Errorf("nats: jetstream: %w", err)
	}
	p.nc, p.js, p.pub = nc, js, js
	return nil
}

// Reconfigure applies new settings without a restart. A change of url,
// name, timeout, authentication or tls opens a new connection and checks
// JetStream on it before switching; if that fails the previous settings
// stay. The old connection is drained only after the publishes in flight on
// it have finished. A change of only subject or stream keeps the current
// connection. The event filter is fixed at startup.
func (p *Plugin) Reconfigure(ctx context.Context, decode func(v any) error) error {
	p.reconfMu.Lock()
	defer p.reconfMu.Unlock()
	n := &Plugin{log: p.log}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if !slices.Equal(n.cfg.Events, p.cfg.Events) {
		return errors.New("nats: events take effect after a restart")
	}
	if err := n.validate(); err != nil {
		return err
	}
	old := p.next.Load()
	if old == nil {
		old = p
	}
	handover := sameConnection(old.cfg, n.cfg)
	if handover {
		n.nc, n.js, n.pub = old.nc, old.js, old.pub
	} else {
		if err := n.connect(false); err != nil {
			return err
		}
		vctx, cancel := context.WithTimeout(ctx, n.timeout)
		_, err := n.js.AccountInfo(vctx)
		cancel()
		if err != nil {
			n.nc.Close()
			return fmt.Errorf("nats: jetstream: %w", err)
		}
	}
	p.next.Store(n)
	// Wait for publishes in flight on the old copy; later ones go to n.
	old.inflight.Lock()
	old.retired = true
	old.inflight.Unlock()
	if !handover && old.nc != nil {
		if err := old.nc.Drain(); err != nil {
			old.nc.Close()
		}
	}
	return nil
}

// sameConnection reports whether a and b need the same connection: they
// differ at most in per-publish settings.
func sameConnection(a, b Config) bool {
	a.Subject, a.Stream, a.Events = b.Subject, b.Stream, b.Events
	return reflect.DeepEqual(a, b)
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "nats",
		Name:         "NATS JetStream Publisher",
		Version:      "0.1.0",
		Description:  "Publishes tenant events to NATS JetStream as CloudEvents, deduplicated by event ID.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(ctx context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	p.log = r.Logger()
	if err := p.validate(); err != nil {
		return err
	}
	// NATS being down must not block startup; publishing fails (and is
	// retried) until the connection is up.
	if err := p.connect(true); err != nil {
		return err
	}
	if p.streamCfg != nil {
		initCtx, cancel := context.WithTimeout(ctx, p.timeout)
		defer cancel()
		if err := p.ensureStream(initCtx); err != nil {
			p.log.Warn("could not ensure stream at startup; will retry", "stream", p.streamCfg.Name, "err", err)
		}
	}
	r.Subscribe("publish", sdk.EventFilter{Types: p.cfg.Events}, p.publish)
	return nil
}

func (p *Plugin) validate() error {
	c := &p.cfg
	if strings.TrimSpace(c.URL) == "" {
		return errors.New("nats: url is required")
	}
	var err error
	p.timeout, err = parseDuration("timeout", c.Timeout, 10*time.Second)
	if err != nil {
		return err
	}
	if p.subject, err = parseTemplate("subject", cmp.Or(c.Subject, DefaultSubject)); err != nil {
		return err
	}
	if _, err := p.renderSubject(sampleEvent()); err != nil {
		return fmt.Errorf("nats: subject: %w", err)
	}
	methods := 0
	for _, set := range []bool{c.CredsFile != "", c.NkeySeed != "", c.NkeySeedFile != "", c.Token != "", c.Username != ""} {
		if set {
			methods++
		}
	}
	if methods > 1 {
		return errors.New("nats: configure at most one of creds_file, nkey_seed, nkey_seed_file, token, username")
	}
	if c.Password != "" && c.Username == "" {
		return errors.New("nats: password requires username")
	}
	if t := c.TLS; t != nil && (t.CertFile == "") != (t.KeyFile == "") {
		return errors.New("nats: tls.cert_file and tls.key_file must be set together")
	}
	if s := c.Stream; s != nil {
		if s.Name == "" || strings.ContainsAny(s.Name, " \t\r\n.*>/\\") {
			return fmt.Errorf("nats: invalid stream name %q", s.Name)
		}
		sc := &jetstream.StreamConfig{Name: s.Name, Subjects: s.Subjects, Replicas: s.Replicas}
		if len(sc.Subjects) == 0 {
			sc.Subjects = []string{"tenarium.>"}
		}
		switch s.Storage {
		case "", "file":
			sc.Storage = jetstream.FileStorage
		case "memory":
			sc.Storage = jetstream.MemoryStorage
		default:
			return fmt.Errorf("nats: stream.storage must be file or memory, got %q", s.Storage)
		}
		if s.Replicas < 0 || s.Replicas > 5 {
			return fmt.Errorf("nats: stream.replicas must be 1..5, got %d", s.Replicas)
		}
		if sc.MaxAge, err = parseDuration("stream.max_age", s.MaxAge, 0); err != nil {
			return err
		}
		if sc.Duplicates, err = parseDuration("stream.duplicate_window", s.DuplicateWindow, 0); err != nil {
			return err
		}
		if s.Create {
			p.streamCfg = sc
		}
	}
	return nil
}

func (p *Plugin) connectOptions() ([]nats.Option, error) {
	c := p.cfg
	opts := []nats.Option{
		nats.Name(cmp.Or(c.Name, "tenarium")),
		nats.Timeout(p.timeout),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				p.log.Warn("nats disconnected", "err", err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) { p.log.Info("nats reconnected", "server", nc.ConnectedUrlRedacted()) }),
	}
	switch {
	case c.CredsFile != "":
		opts = append(opts, nats.UserCredentials(c.CredsFile))
	case c.NkeySeedFile != "":
		o, err := nats.NkeyOptionFromSeed(c.NkeySeedFile)
		if err != nil {
			return nil, fmt.Errorf("nats: nkey_seed_file: %w", err)
		}
		opts = append(opts, o)
	case c.NkeySeed != "":
		kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(c.NkeySeed)))
		if err != nil {
			return nil, fmt.Errorf("nats: nkey_seed: %w", err)
		}
		pub, err := kp.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("nats: nkey_seed: %w", err)
		}
		opts = append(opts, nats.Nkey(pub, kp.Sign))
	case c.Token != "":
		opts = append(opts, nats.Token(c.Token))
	case c.Username != "":
		opts = append(opts, nats.UserInfo(c.Username, c.Password))
	}
	if t := c.TLS; t != nil && t.Enabled {
		tc, err := tlsConfig(t)
		if err != nil {
			return nil, err
		}
		opts = append(opts, nats.Secure(tc))
	}
	return opts, nil
}

func tlsConfig(t *TLSConfig) (*tls.Config, error) {
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         t.ServerName,
		InsecureSkipVerify: t.InsecureSkipVerify, //nolint:gosec // explicit opt-in
	}
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("nats: tls.ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("nats: tls.ca_file %s: no certificates", t.CAFile)
		}
		tc.RootCAs = pool
	}
	if t.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("nats: tls client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}

// ensureStream creates the stream once if it is missing; an existing stream
// (possibly managed by an operator) is left untouched.
func (p *Plugin) ensureStream(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.streamEnsured || p.streamCfg == nil {
		return nil
	}
	_, err := p.js.Stream(ctx, p.streamCfg.Name)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		_, err = p.js.CreateStream(ctx, *p.streamCfg)
		if errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
			err = nil
		}
	}
	if err != nil {
		return fmt.Errorf("nats: ensure stream %s: %w", p.streamCfg.Name, err)
	}
	p.streamEnsured = true
	return nil
}

func (p *Plugin) publish(ctx context.Context, e sdk.Event) error {
	c := p.acquire()
	defer c.inflight.RUnlock()
	return c.publishOn(ctx, e)
}

func (p *Plugin) publishOn(ctx context.Context, e sdk.Event) error {
	if p.js != nil {
		if err := p.ensureStream(ctx); err != nil {
			return err
		}
	}
	msg, err := p.message(e)
	if err != nil {
		return err
	}
	opts := []jetstream.PublishOpt{jetstream.WithMsgID(e.ID)}
	if s := p.cfg.Stream; s != nil {
		opts = append(opts, jetstream.WithExpectStream(s.Name))
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	ack, err := p.pub.PublishMsg(ctx, msg, opts...)
	if err != nil {
		return fmt.Errorf("nats: publish %s to %s: %w", e.ID, msg.Subject, err)
	}
	if ack != nil && ack.Duplicate {
		p.log.Debug("duplicate event ignored by JetStream", "id", e.ID, "stream", ack.Stream)
	}
	return nil
}

// message builds the JetStream message for e: structured CloudEvent JSON
// body, Nats-Msg-Id = event ID, and a few ce-* headers for routing without
// parsing the body.
func (p *Plugin) message(e sdk.Event) (*nats.Msg, error) {
	subject, err := p.renderSubject(e)
	if err != nil {
		return nil, fmt.Errorf("nats: subject for %s: %w", e.ID, err)
	}
	body, err := json.Marshal(e.CloudEvent())
	if err != nil {
		return nil, err
	}
	msg := nats.NewMsg(subject)
	msg.Data = body
	msg.Header.Set(jetstream.MsgIDHeader, e.ID)
	msg.Header.Set("Content-Type", "application/cloudevents+json")
	msg.Header.Set("ce-id", e.ID)
	msg.Header.Set("ce-type", e.Type)
	if e.TenantID != "" {
		msg.Header.Set("ce-tenantid", e.TenantID)
	}
	return msg, nil
}

func (p *Plugin) renderSubject(e sdk.Event) (string, error) {
	var b strings.Builder
	if err := p.subject.Execute(&b, e); err != nil {
		return "", err
	}
	s := b.String()
	if err := validSubject(s); err != nil {
		return "", err
	}
	return s, nil
}

// validSubject rejects subjects that are empty, contain whitespace or
// wildcards, or have empty tokens (e.g. an event without a tenant ID
// rendered into "tenarium..plan.created").
func validSubject(s string) error {
	if s == "" {
		return errors.New("empty subject")
	}
	if strings.ContainsAny(s, " \t\r\n*>") {
		return fmt.Errorf("subject %q contains whitespace or wildcards", s)
	}
	for _, tok := range strings.Split(s, ".") {
		if tok == "" {
			return fmt.Errorf("subject %q has an empty token", s)
		}
	}
	return nil
}

func (p *Plugin) Health(ctx context.Context) error {
	c := p.acquire()
	defer c.inflight.RUnlock()
	return c.health(ctx)
}

func (p *Plugin) health(ctx context.Context) error {
	if p.nc == nil {
		return errors.New("nats: not initialized")
	}
	if !p.nc.IsConnected() {
		return fmt.Errorf("nats: not connected (%s)", p.nc.Status())
	}
	if _, err := p.js.AccountInfo(ctx); err != nil {
		return fmt.Errorf("nats: jetstream: %w", err)
	}
	return nil
}

// Stop drains the current connection; connections replaced by Reconfigure
// were drained then (or handed over to the current one).
func (p *Plugin) Stop(ctx context.Context) error {
	p.reconfMu.Lock()
	defer p.reconfMu.Unlock()
	nc := p.nc
	if n := p.next.Load(); n != nil {
		nc = n.nc
	}
	if nc == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- nc.Drain() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		nc.Close()
		return ctx.Err()
	}
}

func parseTemplate(name, text string) (*template.Template, error) {
	t, err := template.New(name).Option("missingkey=error").Parse(text)
	if err != nil {
		return nil, fmt.Errorf("nats: %s template: %w", name, err)
	}
	return t, nil
}

func parseDuration(field, s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("nats: %s: invalid duration %q", field, s)
	}
	return d, nil
}

func sampleEvent() sdk.Event {
	return sdk.Event{ID: "sample", Type: sdk.EventTenantCreated, Source: "tenarium", TenantID: "tenant", Time: time.Now()}
}
