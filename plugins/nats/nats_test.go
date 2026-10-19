package nats

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type fakePublisher struct {
	msgs []*nats.Msg
	opts int
	err  error
}

func (f *fakePublisher) PublishMsg(_ context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.msgs = append(f.msgs, msg)
	f.opts = len(opts)
	return &jetstream.PubAck{Stream: "S"}, nil
}

func newTestPlugin(t *testing.T, cfg Config) (*Plugin, *fakePublisher) {
	t.Helper()
	p := &Plugin{cfg: cfg, log: sdktest.NewRegistrar(nil).Log}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	f := &fakePublisher{}
	p.pub = f
	return p, f
}

func TestMessage(t *testing.T) {
	p, f := newTestPlugin(t, Config{URL: "nats://x", Stream: &StreamConfig{Name: "TENARIUM"}})
	e := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1", Slug: "acme"})
	e.Seq = 3
	if err := p.publish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	m := f.msgs[0]
	if m.Subject != "tenarium.t1.tenant.created" {
		t.Fatalf("subject %q", m.Subject)
	}
	if m.Header.Get(jetstream.MsgIDHeader) != e.ID || m.Header.Get("ce-type") != sdk.EventTenantCreated ||
		m.Header.Get("Content-Type") != "application/cloudevents+json" || m.Header.Get("ce-tenantid") != "t1" {
		t.Fatalf("headers %v", m.Header)
	}
	var ce sdk.CloudEvent
	if err := json.Unmarshal(m.Data, &ce); err != nil || ce.ID != e.ID || ce.Sequence != "3" {
		t.Fatalf("body %s %v", m.Data, err)
	}
	if f.opts != 2 { // msg id + expect stream
		t.Fatalf("publish opts %d", f.opts)
	}

	// Events without a tenant fall back to "global" with the default template.
	plan := sdk.Event{ID: "p1", Type: sdk.EventPlanCreated}
	if err := p.publish(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if f.msgs[1].Subject != "tenarium.global.plan.created" {
		t.Fatalf("subject %q", f.msgs[1].Subject)
	}
}

func TestSubjectTemplate(t *testing.T) {
	p, _ := newTestPlugin(t, Config{URL: "nats://x", Subject: "events.{{.TenantID}}.{{.Type}}"})
	if _, err := p.renderSubject(sdk.Event{Type: "plan.created"}); err == nil {
		t.Fatal("empty token accepted")
	}
	s, err := p.renderSubject(sdk.Event{Type: "tenant.updated", TenantID: "abc"})
	if err != nil || s != "events.abc.tenant.updated" {
		t.Fatalf("%q %v", s, err)
	}
}

func TestPublishError(t *testing.T) {
	p, f := newTestPlugin(t, Config{URL: "nats://x"})
	f.err = errors.New("no responders")
	if err := p.publish(context.Background(), sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1"})); err == nil {
		t.Fatal("expected error")
	}
}

func TestConfigValidation(t *testing.T) {
	for _, cfg := range []map[string]any{
		{},
		{"url": "nats://x", "nope": 1},
		{"url": "nats://x", "subject": "{{.Nope}}"},
		{"url": "nats://x", "subject": "a.*"},
		{"url": "nats://x", "token": "t", "username": "u"},
		{"url": "nats://x", "password": "p"},
		{"url": "nats://x", "timeout": "soon"},
		{"url": "nats://x", "stream": map[string]any{"name": "a.b"}},
		{"url": "nats://x", "stream": map[string]any{"name": "S", "storage": "disk"}},
		{"url": "nats://x", "stream": map[string]any{"name": "S", "max_age": "x"}},
		{"url": "nats://x", "tls": map[string]any{"enabled": true, "cert_file": "c"}},
		{"url": "nats://x", "nkey_seed": "not-a-seed"},
	} {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("config %v accepted", cfg)
		}
	}
}

func TestConfigSchema(t *testing.T) {
	s, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{"url": "nats://localhost:4222", "subject": "x.{{.Type}}", "events": []any{"tenant.*"},
		"creds_file": "/c", "tls": map[string]any{"enabled": true},
		"stream": map[string]any{"name": "TENARIUM", "create": true, "storage": "memory", "replicas": 1, "duplicate_window": "5m"}}
	if err := s.Validate(good); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[string]any{
		"missing url":    {},
		"unknown field":  {"url": "x", "nope": true},
		"bad storage":    {"url": "x", "stream": map[string]any{"name": "S", "storage": "disk"}},
		"stream no name": {"url": "x", "stream": map[string]any{"create": true}},
		"tls unknown":    {"url": "x", "tls": map[string]any{"on": true}},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%s: expected schema error", name)
		}
	}
}

// TestJetStream needs a server with JetStream, e.g.
// `docker run -d -p 14222:4222 nats -js` and TENARIUM_TEST_NATS_URL=nats://localhost:14222.
func TestJetStream(t *testing.T) {
	url := os.Getenv("TENARIUM_TEST_NATS_URL")
	if url == "" {
		t.Skip("TENARIUM_TEST_NATS_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream := fmt.Sprintf("TENARIUM_TEST_%d", time.Now().UnixNano())
	prefix := fmt.Sprintf("tt%d", time.Now().UnixNano())
	reg := sdktest.NewRegistrar(map[string]any{
		"url":     url,
		"subject": prefix + `.{{or .TenantID "global"}}.{{.Type}}`,
		"events":  []string{"tenant.*"},
		"stream":  map[string]any{"name": stream, "create": true, "subjects": []string{prefix + ".>"}, "storage": "memory"},
	})
	p := &Plugin{}
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Stop(context.Background()) }()
	defer func() {
		c := p.acquire() // the current connection, after Reconfigure below
		defer c.inflight.RUnlock()
		_ = c.js.DeleteStream(context.Background(), stream)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for p.Health(ctx) != nil && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}

	e := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "tenant-1", Slug: "acme"})
	for range 2 { // the second publish is a retry: JetStream must drop it
		if err := reg.Deliver(ctx, "publish", e); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	if err := reg.Deliver(ctx, "publish", sdktest.TenantEvent(sdk.EventTenantSuspended, sdk.Tenant{ID: "tenant-1"})); err != nil {
		t.Fatal(err)
	}
	s, err := p.js.Stream(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	info, err := s.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 2 {
		t.Fatalf("stream has %d messages, want 2 (dedupe)", info.State.Msgs)
	}
	raw, err := s.GetMsg(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	var ce sdk.CloudEvent
	if err := json.Unmarshal(raw.Data, &ce); err != nil || ce.ID != e.ID || raw.Subject != prefix+".tenant-1.tenant.created" {
		t.Fatalf("message %s %s %v", raw.Subject, raw.Data, err)
	}

	// A connection name change switches to a new, verified connection and
	// drains the old one.
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(map[string]any{
		"url":     url,
		"name":    "tenarium-reconfigured",
		"subject": prefix + `.r.{{or .TenantID "global"}}.{{.Type}}`,
		"events":  []string{"tenant.*"},
		"stream":  map[string]any{"name": stream, "create": true, "subjects": []string{prefix + ".>"}, "storage": "memory"},
	}).Config); err != nil {
		t.Fatal(err)
	}
	if !p.nc.IsClosed() && !p.nc.IsDraining() {
		t.Fatal("old connection not drained")
	}
	if err := reg.Deliver(ctx, "publish", sdktest.TenantEvent(sdk.EventTenantResumed, sdk.Tenant{ID: "tenant-1"})); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health after reconfigure: %v", err)
	}
	// s is bound to the drained connection; read through the new one.
	if s, err = p.next.Load().js.Stream(ctx, stream); err != nil {
		t.Fatal(err)
	}
	if raw, err = s.GetMsg(ctx, 3); err != nil || raw.Subject != prefix+".r.tenant-1.tenant.resumed" {
		t.Fatalf("message after reconfigure: %v", err)
	}
}

func TestReconfigure(t *testing.T) {
	// No server: startup tolerates it, but a new connection must verify.
	base := map[string]any{"url": "nats://127.0.0.1:1", "timeout": "1s"}
	reg := sdktest.NewRegistrar(base)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Stop(context.Background()) }()
	f := &fakePublisher{}
	p.pub = f
	e := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1"})

	// A subject change keeps the connection (and here the fake publisher).
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(map[string]any{
		"url": "nats://127.0.0.1:1", "timeout": "1s", "subject": "events.{{.Type}}",
	}).Config); err != nil {
		t.Fatal(err)
	}
	if err := reg.Deliver(context.Background(), "publish", e); err != nil {
		t.Fatal(err)
	}
	if len(f.msgs) != 1 || f.msgs[0].Subject != "events.tenant.created" || !p.retired || p.next.Load().nc != p.nc {
		t.Fatalf("published %v", f.msgs)
	}

	// A new connection that cannot be established is rejected.
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(map[string]any{
		"url": "nats://127.0.0.1:2", "timeout": "1s",
	}).Config); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Fatalf("unreachable url: %v", err)
	}
	// Invalid config: rejected.
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(map[string]any{
		"url": "nats://127.0.0.1:1", "subject": "a.*",
	}).Config); err == nil {
		t.Fatal("invalid config accepted")
	}
	if err := reg.Deliver(context.Background(), "publish", e); err != nil || len(f.msgs) != 2 || f.msgs[1].Subject != "events.tenant.created" {
		t.Fatalf("after failed reconfigure: %v %v", err, f.msgs)
	}

	// The event filter is fixed at startup.
	base["events"] = []string{"tenant.*"}
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(base).Config); err == nil ||
		!strings.Contains(err.Error(), "restart") {
		t.Fatalf("events change: %v", err)
	}
}
