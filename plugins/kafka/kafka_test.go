package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/twmb/franz-go/pkg/kgo"
)

func TestRecordEncoding(t *testing.T) {
	e := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1", Slug: "acme"})
	e.Seq = 7

	p := &Plugin{cfg: Config{Mode: "structured"}}
	rec, err := p.record(e)
	if err != nil {
		t.Fatal(err)
	}
	var ce sdk.CloudEvent
	if err := json.Unmarshal(rec.Value, &ce); err != nil || ce.Type != sdk.EventTenantCreated || ce.Sequence != "7" {
		t.Fatalf("structured value: %s %v", rec.Value, err)
	}
	if string(rec.Key) != "t1" || header(rec, "content-type") != "application/cloudevents+json" {
		t.Fatalf("structured key/headers: %s %v", rec.Key, rec.Headers)
	}

	p.cfg.Mode = "binary"
	rec, _ = p.record(e)
	if header(rec, "ce_type") != sdk.EventTenantCreated || header(rec, "ce_tenantid") != "t1" || !strings.Contains(string(rec.Value), "acme") {
		t.Fatalf("binary record: %v %s", rec.Headers, rec.Value)
	}
}

func header(r *kgo.Record, k string) string {
	for _, h := range r.Headers {
		if h.Key == k {
			return string(h.Value)
		}
	}
	return ""
}

func TestConfigValidation(t *testing.T) {
	for _, cfg := range []map[string]any{
		{},
		{"brokers": []string{"x:9092"}},
		{"brokers": []string{"x:9092"}, "topic": "t", "mode": "weird"},
		{"brokers": []string{"x:9092"}, "topic": "t", "sasl": map[string]any{"mechanism": "KERBEROS"}},
	} {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("config %v accepted", cfg)
		}
	}
}

// TestPublishToBroker needs a broker, e.g. `docker compose up -d redpanda`
// and TENARIUM_TEST_KAFKA_BROKERS=localhost:19092.
func TestPublishToBroker(t *testing.T) {
	brokers := os.Getenv("TENARIUM_TEST_KAFKA_BROKERS")
	if brokers == "" {
		t.Skip("TENARIUM_TEST_KAFKA_BROKERS not set")
	}
	topic := fmt.Sprintf("tenarium-test-%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	reg := sdktest.NewRegistrar(map[string]any{"brokers": strings.Split(brokers, ","), "topic": topic, "create_topic": map[string]any{"partitions": 1}})
	p := &Plugin{}
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Stop(ctx) }()
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	for i, typ := range []string{sdk.EventTenantCreated, sdk.EventTenantSuspended} {
		e := sdktest.TenantEvent(typ, sdk.Tenant{ID: "tenant-1", Slug: "acme"})
		e.Seq = int64(i + 1)
		if err := reg.Deliver(ctx, "publish", e); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}

	// A client_id change switches to a new, pinged client.
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(map[string]any{"brokers": strings.Split(brokers, ","), "topic": topic,
		"client_id": "tenarium-reconfigured", "create_topic": map[string]any{"partitions": 1}}).Config); err != nil {
		t.Fatal(err)
	}
	if p.next.Load().client == p.client {
		t.Fatal("client not replaced")
	}
	if err := reg.Deliver(ctx, "publish", sdktest.TenantEvent(sdk.EventTenantResumed, sdk.Tenant{ID: "tenant-1"})); err != nil {
		t.Fatalf("publish after reconfigure: %v", err)
	}

	consumer, err := kgo.NewClient(kgo.SeedBrokers(strings.Split(brokers, ",")...), kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	var got []string
	for len(got) < 3 {
		fetches := consumer.PollFetches(ctx)
		if err := ctx.Err(); err != nil {
			t.Fatalf("consumed %v before timeout", got)
		}
		fetches.EachRecord(func(r *kgo.Record) {
			var ce sdk.CloudEvent
			_ = json.Unmarshal(r.Value, &ce)
			if string(r.Key) != "tenant-1" {
				t.Errorf("key %q", r.Key)
			}
			got = append(got, ce.Type)
		})
	}
	if got[0] != sdk.EventTenantCreated || got[1] != sdk.EventTenantSuspended || got[2] != sdk.EventTenantResumed {
		t.Fatalf("order: %v", got)
	}
}

func TestReconfigure(t *testing.T) {
	// The client connects lazily, so Init needs no broker.
	base := map[string]any{"brokers": []string{"127.0.0.1:1"}, "topic": "a"}
	p := &Plugin{}
	if err := p.Init(context.Background(), sdktest.NewRegistrar(base)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Stop(context.Background()) }()
	e := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1"})

	// Per-publish settings keep the client.
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(map[string]any{
		"brokers": []string{"127.0.0.1:1"}, "topic": "b", "mode": "binary",
	}).Config); err != nil {
		t.Fatal(err)
	}
	c := p.acquire()
	rec, err := c.record(e)
	c.inflight.RUnlock()
	if err != nil || rec.Topic != "b" || header(rec, "ce_type") != e.Type || c.client != p.client || !p.retired {
		t.Fatalf("record %+v %v", rec, err)
	}

	// A new client that cannot reach the cluster is rejected.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(map[string]any{
		"brokers": []string{"127.0.0.1:2"}, "topic": "b",
	}).Config); err == nil || !strings.Contains(err.Error(), "ping") {
		t.Fatalf("unreachable brokers: %v", err)
	}
	// Invalid config: rejected.
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(map[string]any{
		"brokers": []string{"127.0.0.1:1"}, "topic": "c", "mode": "weird",
	}).Config); err == nil {
		t.Fatal("invalid config accepted")
	}
	if c := p.next.Load(); c.cfg.Topic != "b" || c.cfg.Brokers[0] != "127.0.0.1:1" {
		t.Fatalf("settings after failed reconfigure: %+v", c.cfg)
	}

	// The event filter is fixed at startup.
	base["events"] = []string{"tenant.*"}
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(base).Config); err == nil ||
		!strings.Contains(err.Error(), "restart") {
		t.Fatalf("events change: %v", err)
	}
}
