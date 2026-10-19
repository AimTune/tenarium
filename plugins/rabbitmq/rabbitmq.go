// Package rabbitmq publishes events to a RabbitMQ (AMQP 0-9-1) exchange as
// CloudEvents.
//
// Every message is persistent, carries the structured CloudEvent JSON as its
// body and the event ID as message_id, and is published with publisher
// confirms: an event counts as delivered only once the broker has taken
// responsibility for it, otherwise the handler returns an error and Tenarium
// retries. The routing key is a template over the event (default
// "{{.Type}}"), which suits topic exchanges ("tenant.*", "#").
//
// The connection is re-established lazily: if it (or the channel) is closed,
// for example after a broker restart, the next publish or health check
// reconnects and re-declares the exchange.
package rabbitmq

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
	amqp "github.com/rabbitmq/amqp091-go"
)

func init() {
	sdk.Register("rabbitmq", func() sdk.Plugin { return &Plugin{} })
}

// DefaultRoutingKey is the routing key template used when none is configured.
const DefaultRoutingKey = "{{.Type}}"

type Config struct {
	// URL is an AMQP URI: amqp://user:pass@host:5672/vhost (amqps:// for TLS).
	URL string `json:"url"`
	// Exchange to publish to; "" is the default exchange, which routes by
	// queue name (the routing key must then render a queue name).
	Exchange string `json:"exchange"`
	// ExchangeType is used when declaring: topic (default), direct, fanout, headers.
	ExchangeType string `json:"exchange_type"`
	// DeclareExchange declares the exchange (durable) on every (re)connect.
	DeclareExchange bool `json:"declare_exchange"`
	// RoutingKey is a text/template over sdk.Event.
	RoutingKey string   `json:"routing_key"`
	Events     []string `json:"events"`
	// Mandatory makes unroutable messages fail (and be retried) instead of
	// being dropped silently by the broker.
	Mandatory bool `json:"mandatory"`
	// Timeout bounds dialing and each publisher confirm (default 10s).
	Timeout string     `json:"timeout"`
	TLS     *TLSConfig `json:"tls"`
}

type TLSConfig struct {
	CAFile             string `json:"ca_file"`
	CertFile           string `json:"cert_file"`
	KeyFile            string `json:"key_file"`
	ServerName         string `json:"server_name"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "url": {"type": "string", "pattern": "^amqps?://"},
    "exchange": {"type": "string"},
    "exchange_type": {"enum": ["topic", "direct", "fanout", "headers"]},
    "declare_exchange": {"type": "boolean"},
    "routing_key": {"type": "string"},
    "events": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "mandatory": {"type": "boolean"},
    "timeout": {"type": "string"},
    "tls": {
      "type": "object",
      "properties": {
        "ca_file": {"type": "string"},
        "cert_file": {"type": "string"},
        "key_file": {"type": "string"},
        "server_name": {"type": "string"},
        "insecure_skip_verify": {"type": "boolean"}
      },
      "additionalProperties": false
    }
  },
  "required": ["url"],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg        Config
	log        *slog.Logger
	routingKey *template.Template
	timeout    time.Duration
	amqpCfg    amqp.Config

	mu      sync.Mutex // serializes publishes and (re)connects
	conn    *amqp.Connection
	ch      *amqp.Channel
	returns chan amqp.Return
	// retired is set (under mu) once Reconfigure replaced this copy; it
	// then neither publishes nor reconnects.
	retired bool

	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
	// reconfMu serializes Reconfigure and Stop.
	reconfMu sync.Mutex
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

// current returns the copy holding the active configuration.
func (p *Plugin) current() *Plugin {
	if n := p.next.Load(); n != nil {
		return n
	}
	return p
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "rabbitmq",
		Name:         "RabbitMQ Publisher",
		Version:      "0.1.0",
		Description:  "Publishes tenant events to a RabbitMQ exchange as persistent CloudEvents with publisher confirms.",
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
	// RabbitMQ being down must not block startup; publishing reconnects.
	p.mu.Lock()
	err := p.connectLocked()
	p.mu.Unlock()
	if err != nil {
		p.log.Warn("could not connect to RabbitMQ at startup; will retry", "err", err)
	}
	r.Subscribe("publish", sdk.EventFilter{Types: p.cfg.Events}, p.publish)
	return nil
}

func (p *Plugin) validate() error {
	c := &p.cfg
	if !strings.HasPrefix(c.URL, "amqp://") && !strings.HasPrefix(c.URL, "amqps://") {
		return errors.New("rabbitmq: url must be an amqp:// or amqps:// URI")
	}
	uri, err := amqp.ParseURI(c.URL)
	if err != nil {
		return fmt.Errorf("rabbitmq: url: %w", err)
	}
	switch c.ExchangeType {
	case "":
		c.ExchangeType = amqp.ExchangeTopic
	case amqp.ExchangeTopic, amqp.ExchangeDirect, amqp.ExchangeFanout, amqp.ExchangeHeaders:
	default:
		return fmt.Errorf("rabbitmq: exchange_type must be topic, direct, fanout or headers, got %q", c.ExchangeType)
	}
	if c.DeclareExchange && c.Exchange == "" {
		return errors.New("rabbitmq: declare_exchange needs an exchange name")
	}
	if strings.HasPrefix(c.Exchange, "amq.") && c.DeclareExchange {
		return errors.New("rabbitmq: exchanges named amq.* are reserved and cannot be declared")
	}
	if p.timeout, err = parseDuration("timeout", c.Timeout, 10*time.Second); err != nil {
		return err
	}
	p.routingKey, err = template.New("routing_key").Option("missingkey=error").Parse(cmp.Or(c.RoutingKey, DefaultRoutingKey))
	if err != nil {
		return fmt.Errorf("rabbitmq: routing_key template: %w", err)
	}
	if _, err := p.renderRoutingKey(sdk.Event{ID: "sample", Type: sdk.EventTenantCreated, TenantID: "tenant"}); err != nil {
		return err
	}

	p.amqpCfg = amqp.Config{
		Heartbeat:  10 * time.Second,
		Locale:     "en_US",
		Properties: amqp.Table{"connection_name": "tenarium", "product": "tenarium"},
		Dial:       amqp.DefaultDial(p.timeout),
	}
	if t := c.TLS; t != nil {
		if uri.Scheme != "amqps" {
			return errors.New("rabbitmq: tls requires an amqps:// url")
		}
		tc, err := tlsConfig(t, uri.Host)
		if err != nil {
			return err
		}
		p.amqpCfg.TLSClientConfig = tc
	}
	return nil
}

func tlsConfig(t *TLSConfig, host string) (*tls.Config, error) {
	if (t.CertFile == "") != (t.KeyFile == "") {
		return nil, errors.New("rabbitmq: tls.cert_file and tls.key_file must be set together")
	}
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         cmp.Or(t.ServerName, host),
		InsecureSkipVerify: t.InsecureSkipVerify, //nolint:gosec // explicit opt-in
	}
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("rabbitmq: tls.ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("rabbitmq: tls.ca_file %s: no certificates", t.CAFile)
		}
		tc.RootCAs = pool
	}
	if t.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("rabbitmq: tls client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}

// connectLocked (re)establishes the connection and a confirm-mode channel
// if either is missing or closed. p.mu must be held.
func (p *Plugin) connectLocked() error {
	if p.conn != nil && !p.conn.IsClosed() && p.ch != nil && !p.ch.IsClosed() {
		return nil
	}
	p.closeLocked()
	conn, err := amqp.DialConfig(p.cfg.URL, p.amqpCfg)
	if err != nil {
		return fmt.Errorf("rabbitmq: dial: %w", redactErr(err, p.cfg.URL))
	}
	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("rabbitmq: open channel: %w", err)
	}
	if err := ch.Confirm(false); err != nil {
		_ = conn.Close()
		return fmt.Errorf("rabbitmq: enable publisher confirms: %w", err)
	}
	if p.cfg.DeclareExchange {
		if err := ch.ExchangeDeclare(p.cfg.Exchange, p.cfg.ExchangeType, true, false, false, false, nil); err != nil {
			_ = conn.Close()
			return fmt.Errorf("rabbitmq: declare exchange %s: %w", p.cfg.Exchange, err)
		}
	}
	// Returns arrive before the matching confirm on the same channel and
	// are dispatched synchronously, so a buffered channel holds them by
	// the time the confirm is observed.
	p.returns = ch.NotifyReturn(make(chan amqp.Return, 16))
	p.conn, p.ch = conn, ch
	return nil
}

func (p *Plugin) closeLocked() {
	if p.conn != nil {
		_ = p.conn.Close()
	}
	p.conn, p.ch, p.returns = nil, nil, nil
}

func (p *Plugin) publish(ctx context.Context, e sdk.Event) error {
	for {
		// A copy retired by Reconfigure after it was loaded hands over to
		// the one that replaced it.
		if retired, err := p.current().publishOn(ctx, e); !retired {
			return err
		}
	}
}

// publishOn publishes e with p's settings and connection. It reports
// retired (and does nothing) if Reconfigure replaced p.
func (p *Plugin) publishOn(ctx context.Context, e sdk.Event) (retired bool, _ error) {
	key, err := p.renderRoutingKey(e)
	if err != nil {
		return false, err
	}
	msg, err := message(e)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.retired {
		return true, nil
	}
	return false, p.publishLocked(ctx, e, key, msg)
}

func (p *Plugin) publishLocked(ctx context.Context, e sdk.Event, key string, msg amqp.Publishing) error {
	if err := p.connectLocked(); err != nil {
		return err
	}
	// Discard returns left over from an earlier, timed-out publish.
	for len(p.returns) > 0 {
		<-p.returns
	}
	dc, err := p.ch.PublishWithDeferredConfirmWithContext(ctx, p.cfg.Exchange, key, p.cfg.Mandatory, false, msg)
	if err != nil {
		p.closeLocked()
		return fmt.Errorf("rabbitmq: publish %s: %w", e.ID, err)
	}
	ok, err := dc.WaitContext(ctx)
	if err != nil {
		// The confirm may still arrive; drop the channel so its state does
		// not leak into the next publish. The event is retried (and may be
		// duplicated, which consumers handle by message_id).
		p.closeLocked()
		return fmt.Errorf("rabbitmq: waiting for confirm of %s: %w", e.ID, err)
	}
	if !ok {
		return fmt.Errorf("rabbitmq: broker nacked %s", e.ID)
	}
	if p.cfg.Mandatory {
		select {
		case ret := <-p.returns:
			if ret.MessageId == e.ID {
				return fmt.Errorf("rabbitmq: %s unroutable via exchange %q key %q: %d %s",
					e.ID, ret.Exchange, ret.RoutingKey, ret.ReplyCode, ret.ReplyText)
			}
		default:
		}
	}
	return nil
}

// message builds the persistent AMQP message for e.
func message(e sdk.Event) (amqp.Publishing, error) {
	body, err := json.Marshal(e.CloudEvent())
	if err != nil {
		return amqp.Publishing{}, err
	}
	headers := amqp.Table{"ce_type": e.Type, "ce_id": e.ID, "ce_source": e.Source}
	if e.TenantID != "" {
		headers["tenant_id"] = e.TenantID
	}
	return amqp.Publishing{
		Headers:      headers,
		ContentType:  "application/cloudevents+json",
		DeliveryMode: amqp.Persistent,
		MessageId:    e.ID,
		Timestamp:    e.Time,
		Type:         e.Type,
		AppId:        "tenarium",
		Body:         body,
	}, nil
}

func (p *Plugin) renderRoutingKey(e sdk.Event) (string, error) {
	var b strings.Builder
	if err := p.routingKey.Execute(&b, e); err != nil {
		return "", fmt.Errorf("rabbitmq: routing_key: %w", err)
	}
	if b.Len() > 255 {
		return "", fmt.Errorf("rabbitmq: routing key longer than 255 bytes for %s", e.ID)
	}
	return b.String(), nil
}

// Health reconnects if needed and reports whether the broker is reachable.
func (p *Plugin) Health(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		for {
			c := p.current()
			c.mu.Lock()
			if c.retired {
				c.mu.Unlock()
				continue
			}
			err := c.connectLocked()
			c.mu.Unlock()
			done <- err
			return
		}
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Plugin) Stop(context.Context) error {
	p.reconfMu.Lock()
	defer p.reconfMu.Unlock()
	for _, c := range []*Plugin{p.current(), p} {
		c.mu.Lock()
		c.closeLocked()
		c.mu.Unlock()
	}
	return nil
}

// Reconfigure applies new settings without a restart. A change of url,
// tls, timeout or the exchange settings opens and verifies a new
// connection (declaring the exchange if configured) before switching to
// it; if that fails the previous settings stay. The old connection is
// closed only after its in-flight publish has finished (publishes are
// serialized per connection). A change of only routing_key or mandatory
// keeps the current connection. The event filter is fixed at startup.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	p.reconfMu.Lock()
	defer p.reconfMu.Unlock()
	n := &Plugin{log: p.log}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if !slices.Equal(n.cfg.Events, p.cfg.Events) {
		return errors.New("rabbitmq: events take effect after a restart")
	}
	if err := n.validate(); err != nil {
		return err
	}
	old := p.current()
	if sameConnection(old.cfg, n.cfg) {
		// Hand the connection over; old publishes no more once retired.
		old.mu.Lock()
		n.conn, n.ch, n.returns = old.conn, old.ch, old.returns
		old.conn, old.ch, old.returns = nil, nil, nil
		old.retired = true
		p.next.Store(n)
		old.mu.Unlock()
		return nil
	}
	n.mu.Lock()
	err := n.connectLocked()
	n.mu.Unlock()
	if err != nil {
		return err
	}
	p.next.Store(n)
	// Waits for a publish in progress on the old connection.
	old.mu.Lock()
	old.retired = true
	old.closeLocked()
	old.mu.Unlock()
	return nil
}

// sameConnection reports whether a and b need the same connection: they
// differ at most in per-publish settings.
func sameConnection(a, b Config) bool {
	a.RoutingKey, a.Mandatory, a.Events = b.RoutingKey, b.Mandatory, b.Events
	return reflect.DeepEqual(a, b)
}

// redactErr removes the URL's password from err, in case the library echoes it.
func redactErr(err error, rawURL string) error {
	uri, perr := amqp.ParseURI(rawURL)
	if perr != nil || uri.Password == "" || !strings.Contains(err.Error(), uri.Password) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), uri.Password, "xxxxx"))
}

func parseDuration(field, s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("rabbitmq: %s: invalid duration %q", field, s)
	}
	return d, nil
}
