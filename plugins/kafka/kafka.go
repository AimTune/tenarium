// Package kafka publishes events to a Kafka topic.
//
// Records are keyed by tenant ID, so all events of one tenant land in the
// same partition and keep their order. Two encodings follow the CloudEvents
// Kafka protocol binding:
//
//   - structured (default): value is the full CloudEvent JSON.
//   - binary: value is the event data; attributes go into ce_* headers.
package kafka

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

func init() {
	sdk.Register("kafka", func() sdk.Plugin { return &Plugin{} })
}

type Config struct {
	Brokers  []string `json:"brokers"`
	Topic    string   `json:"topic"`
	Events   []string `json:"events"`
	ClientID string   `json:"client_id"`
	// Mode is "structured" (default) or "binary".
	Mode string      `json:"mode"`
	SASL *SASLConfig `json:"sasl"`
	TLS  *TLSConfig  `json:"tls"`
	// CreateTopic creates the topic if it does not exist, for clusters
	// where automatic topic creation is disabled.
	CreateTopic *TopicConfig `json:"create_topic"`
}

type TopicConfig struct {
	Partitions int32 `json:"partitions"` // default 3
	// ReplicationFactor defaults to the broker default (-1).
	ReplicationFactor int16 `json:"replication_factor"`
}

type SASLConfig struct {
	// Mechanism is PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512.
	Mechanism string `json:"mechanism"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type TLSConfig struct {
	Enabled            bool `json:"enabled"`
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

type Plugin struct {
	cfg    Config
	client *kgo.Client
	log    *slog.Logger

	mu           sync.Mutex
	topicEnsured bool

	// inflight is read-held by publishes and health checks on this copy;
	// Reconfigure write-locks it to wait for them before it sets retired
	// and closes the client this copy no longer passes on.
	inflight sync.RWMutex
	retired  bool

	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
	// reconfMu serializes Reconfigure and Stop.
	reconfMu sync.Mutex
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:          "kafka",
		Name:        "Kafka Publisher",
		Version:     "0.1.0",
		Description: "Publishes tenant events to Kafka as CloudEvents.",
	}
}

func (p *Plugin) Init(ctx context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	if err := p.newClient(); err != nil {
		return err
	}
	p.log = r.Logger()
	if p.cfg.CreateTopic != nil {
		// Kafka being down must not block startup; publishing retries.
		initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := p.ensureTopic(initCtx); err != nil {
			p.log.Warn("could not ensure topic at startup; will retry", "topic", p.cfg.Topic, "err", err)
		}
	}
	r.Subscribe("publish", sdk.EventFilter{Types: p.cfg.Events}, p.publish)
	return nil
}

func (p *Plugin) validate() error {
	if len(p.cfg.Brokers) == 0 || p.cfg.Topic == "" {
		return errors.New("brokers and topic are required")
	}
	switch p.cfg.Mode {
	case "":
		p.cfg.Mode = "structured"
	case "structured", "binary":
	default:
		return fmt.Errorf("mode must be structured or binary, got %q", p.cfg.Mode)
	}
	if s := p.cfg.SASL; s != nil {
		if _, err := saslMechanism(s); err != nil {
			return err
		}
	}
	return nil
}

// newClient creates the client; it connects lazily.
func (p *Plugin) newClient() error {
	opts := []kgo.Opt{
		kgo.SeedBrokers(p.cfg.Brokers...),
		kgo.DefaultProduceTopic(p.cfg.Topic),
		kgo.ClientID(cmp.Or(p.cfg.ClientID, "tenarium")),
		// Producer is idempotent by default; acks=all keeps it durable.
		kgo.RequiredAcks(kgo.AllISRAcks()),
	}
	if s := p.cfg.SASL; s != nil {
		mech, err := saslMechanism(s)
		if err != nil {
			return err
		}
		opts = append(opts, mech)
	}
	if t := p.cfg.TLS; t != nil && t.Enabled {
		opts = append(opts, kgo.DialTLSConfig(&tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: t.InsecureSkipVerify, //nolint:gosec // explicit opt-in
		}))
	}
	client, err := kgo.NewClient(opts...)
	if err != nil {
		return err
	}
	p.client = client
	return nil
}

// Reconfigure applies new settings without a restart. A change of brokers,
// client_id, sasl or tls creates a new client and pings the cluster with it
// before switching; if that fails the previous settings stay. The old
// client is closed only after the publishes in flight on it have been
// acknowledged (or failed). A change of only topic, mode or create_topic
// keeps the current client. The event filter is fixed at startup.
func (p *Plugin) Reconfigure(ctx context.Context, decode func(v any) error) error {
	p.reconfMu.Lock()
	defer p.reconfMu.Unlock()
	n := &Plugin{log: p.log}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if !slices.Equal(n.cfg.Events, p.cfg.Events) {
		return errors.New("events take effect after a restart")
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
		n.client = old.client
	} else {
		if err := n.newClient(); err != nil {
			return err
		}
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := n.client.Ping(pctx)
		cancel()
		if err != nil {
			n.client.Close()
			return fmt.Errorf("ping with the new settings: %w", err)
		}
	}
	p.next.Store(n)
	// Wait for publishes in flight on the old copy; later ones go to n.
	old.inflight.Lock()
	old.retired = true
	old.inflight.Unlock()
	if !handover {
		old.client.Close()
	}
	return nil
}

// sameConnection reports whether a and b need the same client: they differ
// at most in per-publish settings.
func sameConnection(a, b Config) bool {
	a.Topic, a.Mode, a.CreateTopic, a.Events = b.Topic, b.Mode, b.CreateTopic, b.Events
	return reflect.DeepEqual(a, b)
}

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

// ensureTopic creates the topic once; "already exists" counts as success.
func (p *Plugin) ensureTopic(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.topicEnsured || p.cfg.CreateTopic == nil {
		return nil
	}
	partitions := p.cfg.CreateTopic.Partitions
	if partitions <= 0 {
		partitions = 3
	}
	rf := p.cfg.CreateTopic.ReplicationFactor
	if rf == 0 {
		rf = -1
	}
	resp, err := kadm.NewClient(p.client).CreateTopic(ctx, partitions, rf, nil, p.cfg.Topic)
	if err == nil {
		err = resp.Err
	}
	if err != nil && !errors.Is(err, kerr.TopicAlreadyExists) {
		return fmt.Errorf("create topic %s: %w", p.cfg.Topic, err)
	}
	p.topicEnsured = true
	return nil
}

func saslMechanism(s *SASLConfig) (kgo.Opt, error) {
	switch strings.ToUpper(s.Mechanism) {
	case "PLAIN":
		return kgo.SASL(plain.Auth{User: s.Username, Pass: s.Password}.AsMechanism()), nil
	case "SCRAM-SHA-256":
		return kgo.SASL(scram.Auth{User: s.Username, Pass: s.Password}.AsSha256Mechanism()), nil
	case "SCRAM-SHA-512":
		return kgo.SASL(scram.Auth{User: s.Username, Pass: s.Password}.AsSha512Mechanism()), nil
	default:
		return nil, fmt.Errorf("unsupported SASL mechanism %q", s.Mechanism)
	}
}

func (p *Plugin) publish(ctx context.Context, e sdk.Event) error {
	c := p.acquire()
	defer c.inflight.RUnlock()
	return c.publishOn(ctx, e)
}

func (p *Plugin) publishOn(ctx context.Context, e sdk.Event) error {
	if err := p.ensureTopic(ctx); err != nil {
		return err
	}
	rec, err := p.record(e)
	if err != nil {
		return err
	}
	return p.client.ProduceSync(ctx, rec).FirstErr()
}

func (p *Plugin) record(e sdk.Event) (*kgo.Record, error) {
	ce := e.CloudEvent()
	// The topic is set per record: a client handed over by Reconfigure
	// keeps its original default topic.
	rec := &kgo.Record{Topic: p.cfg.Topic, Key: []byte(e.TenantID)}
	if p.cfg.Mode == "structured" {
		v, err := json.Marshal(ce)
		if err != nil {
			return nil, err
		}
		rec.Value = v
		rec.Headers = []kgo.RecordHeader{{Key: "content-type", Value: []byte("application/cloudevents+json")}}
		return rec, nil
	}
	rec.Value = e.Data
	h := func(k, v string) {
		if v != "" {
			rec.Headers = append(rec.Headers, kgo.RecordHeader{Key: k, Value: []byte(v)})
		}
	}
	h("ce_specversion", ce.SpecVersion)
	h("ce_id", ce.ID)
	h("ce_source", ce.Source)
	h("ce_type", ce.Type)
	h("ce_subject", ce.Subject)
	h("ce_time", ce.Time)
	h("ce_tenantid", ce.TenantID)
	h("ce_sequence", ce.Sequence)
	h("content-type", ce.DataContentType)
	return rec, nil
}

func (p *Plugin) Health(ctx context.Context) error {
	c := p.acquire()
	defer c.inflight.RUnlock()
	return c.client.Ping(ctx)
}

// Stop flushes and closes the current client; clients replaced by
// Reconfigure were closed then (or handed over to the current one).
func (p *Plugin) Stop(ctx context.Context) error {
	p.reconfMu.Lock()
	defer p.reconfMu.Unlock()
	client := p.client
	if n := p.next.Load(); n != nil {
		client = n.client
	}
	if client == nil {
		return nil
	}
	err := client.Flush(ctx)
	client.Close()
	return err
}
