package rabbitmq

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	amqp "github.com/rabbitmq/amqp091-go"
)

func TestMessage(t *testing.T) {
	e := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1", Slug: "acme"})
	e.Seq = 9
	m, err := message(e)
	if err != nil {
		t.Fatal(err)
	}
	if m.MessageId != e.ID || m.DeliveryMode != amqp.Persistent || m.ContentType != "application/cloudevents+json" ||
		m.Type != e.Type || m.Headers["tenant_id"] != "t1" || m.Headers["ce_type"] != e.Type {
		t.Fatalf("message %+v", m)
	}
	var ce sdk.CloudEvent
	if err := json.Unmarshal(m.Body, &ce); err != nil || ce.ID != e.ID || ce.Sequence != "9" {
		t.Fatalf("body %s %v", m.Body, err)
	}
	if err := m.Headers.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRoutingKey(t *testing.T) {
	p := &Plugin{cfg: Config{URL: "amqp://localhost", RoutingKey: `tenants.{{or .TenantID "none"}}.{{.Type}}`}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	k, err := p.renderRoutingKey(sdk.Event{Type: "plan.created"})
	if err != nil || k != "tenants.none.plan.created" {
		t.Fatalf("%q %v", k, err)
	}
	p = &Plugin{cfg: Config{URL: "amqp://localhost"}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if k, _ := p.renderRoutingKey(sdk.Event{Type: "tenant.deleted"}); k != "tenant.deleted" {
		t.Fatalf("default key %q", k)
	}
	if p.cfg.ExchangeType != "topic" {
		t.Fatalf("default exchange type %q", p.cfg.ExchangeType)
	}
}

func TestRedact(t *testing.T) {
	err := redactErr(fmt.Errorf("dial amqp://u:s3cret@h failed"), "amqp://u:s3cret@h")
	if err.Error() != "dial amqp://u:xxxxx@h failed" {
		t.Fatal(err)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, cfg := range []map[string]any{
		{},
		{"url": "http://x"},
		{"url": "amqp://x", "nope": 1},
		{"url": "amqp://x", "exchange_type": "fanciful"},
		{"url": "amqp://x", "declare_exchange": true},
		{"url": "amqp://x", "exchange": "amq.topic", "declare_exchange": true},
		{"url": "amqp://x", "routing_key": "{{.Nope}}"},
		{"url": "amqp://x", "timeout": "0s"},
		{"url": "amqp://x", "tls": map[string]any{}},
		{"url": "amqps://x", "tls": map[string]any{"cert_file": "c"}},
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
	good := map[string]any{"url": "amqps://u:p@h/v", "exchange": "tenarium", "exchange_type": "topic",
		"declare_exchange": true, "routing_key": "{{.Type}}", "events": []any{"tenant.*"}, "mandatory": true,
		"timeout": "5s", "tls": map[string]any{"ca_file": "/ca.pem"}}
	if err := s.Validate(good); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[string]any{
		"missing url":   {},
		"bad scheme":    {"url": "http://x"},
		"unknown field": {"url": "amqp://x", "nope": true},
		"bad type":      {"url": "amqp://x", "exchange_type": "x"},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%s: expected schema error", name)
		}
	}
}

// TestBroker needs RabbitMQ, e.g. `docker run -d -p 15673:5672 rabbitmq:3-management`
// and TENARIUM_TEST_RABBITMQ_URL=amqp://guest:guest@localhost:15673/.
func TestBroker(t *testing.T) {
	url := os.Getenv("TENARIUM_TEST_RABBITMQ_URL")
	if url == "" {
		t.Skip("TENARIUM_TEST_RABBITMQ_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	exchange := fmt.Sprintf("tenarium-test-%d", time.Now().UnixNano())

	reg := sdktest.NewRegistrar(map[string]any{
		"url": url, "exchange": exchange, "declare_exchange": true, "mandatory": true,
		"routing_key": `{{.TenantID}}.{{.Type}}`,
	})
	p := &Plugin{}
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Stop(ctx) }()
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}

	// Nothing is bound yet: mandatory publishing must fail.
	e1 := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "tenant-1"})
	if err := reg.Deliver(ctx, "publish", e1); err == nil {
		t.Fatal("unroutable publish succeeded")
	}

	conn, err := amqp.Dial(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ch.ExchangeDelete(exchange, false, false) }()
	q, err := ch.QueueDeclare("", false, true, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.QueueBind(q.Name, "tenant-1.#", exchange, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := reg.Deliver(ctx, "publish", e1); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Simulate a lost connection: the next publish must reconnect.
	p.mu.Lock()
	_ = p.conn.Close()
	p.mu.Unlock()
	e2 := sdktest.TenantEvent(sdk.EventTenantSuspended, sdk.Tenant{ID: "tenant-1"})
	if err := reg.Deliver(ctx, "publish", e2); err != nil {
		t.Fatalf("publish after reconnect: %v", err)
	}

	// A timeout change switches to a new, verified connection and closes
	// the old one.
	oldConn := p.conn
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(map[string]any{
		"url": url, "exchange": exchange, "declare_exchange": true, "mandatory": true,
		"routing_key": `{{.TenantID}}.r.{{.Type}}`, "timeout": "5s",
	}).Config); err != nil {
		t.Fatal(err)
	}
	if !oldConn.IsClosed() {
		t.Fatal("old connection still open")
	}
	e3 := sdktest.TenantEvent(sdk.EventTenantResumed, sdk.Tenant{ID: "tenant-1"})
	if err := reg.Deliver(ctx, "publish", e3); err != nil {
		t.Fatalf("publish after reconfigure: %v", err)
	}

	msgs, err := ch.Consume(q.Name, "", true, true, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{"tenant-1.", "tenant-1.", "tenant-1.r."}
	for i, want := range []sdk.Event{e1, e2, e3} {
		select {
		case d := <-msgs:
			var ce sdk.CloudEvent
			_ = json.Unmarshal(d.Body, &ce)
			if d.MessageId != want.ID || ce.Type != want.Type || d.DeliveryMode != amqp.Persistent ||
				d.RoutingKey != keys[i]+want.Type {
				t.Fatalf("got %s %s %s", d.MessageId, d.RoutingKey, d.Body)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for message")
		}
	}
}

func TestReconfigure(t *testing.T) {
	// No broker: startup tolerates it, but a new connection must verify.
	base := map[string]any{"url": "amqp://127.0.0.1:1/", "timeout": "1s", "routing_key": "a.{{.Type}}"}
	p := &Plugin{}
	if err := p.Init(context.Background(), sdktest.NewRegistrar(base)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Stop(context.Background()) }()
	e := sdk.Event{ID: "1", Type: sdk.EventTenantCreated}

	// Per-publish settings keep the connection.
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(map[string]any{
		"url": "amqp://127.0.0.1:1/", "timeout": "1s", "routing_key": "b.{{.Type}}", "mandatory": true,
	}).Config); err != nil {
		t.Fatal(err)
	}
	if k, _ := p.current().renderRoutingKey(e); k != "b.tenant.created" || !p.current().cfg.Mandatory || !p.retired {
		t.Fatalf("routing key %q", k)
	}

	// A new connection that cannot be established is rejected.
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(map[string]any{
		"url": "amqp://127.0.0.1:2/", "timeout": "1s",
	}).Config); err == nil || !strings.Contains(err.Error(), "dial") {
		t.Fatalf("unreachable url: %v", err)
	}
	// Invalid config: rejected.
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(map[string]any{
		"url": "amqp://127.0.0.1:1/", "routing_key": "{{.Nope}}",
	}).Config); err == nil {
		t.Fatal("invalid config accepted")
	}
	if c := p.current(); c.cfg.URL != "amqp://127.0.0.1:1/" || c.cfg.RoutingKey != "b.{{.Type}}" {
		t.Fatalf("settings after failed reconfigure: %+v", c.cfg)
	}

	// The event filter is fixed at startup.
	base["events"] = []string{"tenant.*"}
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(base).Config); err == nil ||
		!strings.Contains(err.Error(), "restart") {
		t.Fatalf("events change: %v", err)
	}
}
