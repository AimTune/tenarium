package kafkatopic

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

// Integration tests run against a Kafka cluster with an ACL authorizer:
//
//   - TENARIUM_TEST_KAFKA_BROKERS: comma-separated brokers the plugin uses
//     as an administrator (a super user, e.g. a PLAINTEXT listener with
//     super.users=User:ANONYMOUS).
//   - TENARIUM_TEST_KAFKA_SASL_BROKERS (optional): a SASL_PLAINTEXT
//     SCRAM-SHA-512 listener; when set, the test also connects as the
//     tenant to check that its credential and ACLs work.

func testBrokers(t *testing.T) []string {
	t.Helper()
	b := os.Getenv("TENARIUM_TEST_KAFKA_BROKERS")
	if b == "" {
		t.Skip("TENARIUM_TEST_KAFKA_BROKERS not set")
	}
	return strings.Split(b, ",")
}

func randSlug(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "it-" + hex.EncodeToString(b)
}

func newIntegrationPlugin(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	cfg["brokers"] = testBrokers(t)
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	return p, reg
}

func integrationConfig(mode string) map[string]any {
	return map[string]any{
		"topics": []any{
			map[string]any{"name": "events", "partitions": 2, "replication_factor": 1, "configs": map[string]any{"retention.ms": "3600000"}},
		},
		"partitions_from_limit": "kafka_partitions",
		"max_partitions":        4,
		"scram":                 map[string]any{"password_secret": testSecret},
		"client_quotas":         map[string]any{"producer_byte_rate": "kafka_produce_bps"},
		"on_deprovision":        mode,
	}
}

func TestIntegrationProvisionDelete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, reg := newIntegrationPlugin(t, integrationConfig(DeprovisionDelete))
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"kafka_produce_bps": 1 << 20}})
	tenant := reg.HostImpl.AddTenant(sdk.Tenant{Slug: randSlug(t), Plan: "pro"})
	t.Cleanup(func() { _ = p.Deprovision(context.Background(), tenant) })
	tg, _ := p.target(tenant)

	for range 2 {
		if err := p.Provision(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	waitPartitions(ctx, t, p, tg.Topics[0], 2)
	acls, err := p.adm.DescribeACLs(ctx, aclFilter{Principal: &tg.Principal})
	if err != nil {
		t.Fatal(err)
	}
	if len(acls) != 5 {
		t.Fatalf("acls %v", acls)
	}
	if ok, err := p.adm.SCRAMUserExists(ctx, tg.User); err != nil || !ok {
		t.Fatalf("SCRAM user: %v %v", ok, err)
	}

	// Plan upgrade: more partitions.
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"kafka_partitions": 3}})
	if err := p.Provision(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	waitPartitions(ctx, t, p, tg.Topics[0], 3)

	// Another tenant with the same slug cannot take the prefix over.
	twin := reg.HostImpl.AddTenant(sdk.Tenant{Slug: tenant.Slug})
	if err := p.Provision(ctx, twin); err == nil || !strings.Contains(err.Error(), "belongs to tenant") {
		t.Fatalf("twin provision: %v", err)
	}

	if sasl := os.Getenv("TENARIUM_TEST_KAFKA_SASL_BROKERS"); sasl != "" {
		checkTenantAccess(ctx, t, strings.Split(sasl, ","), tg, TenantPassword(testSecret, tenant.ID))
	}

	if err := p.Deprovision(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, tenant); err != nil { // idempotent
		t.Fatal(err)
	}
	waitPartitions(ctx, t, p, tg.Topics[0], -1)
	acls, _ = p.adm.DescribeACLs(ctx, aclFilter{Principal: &tg.Principal})
	if len(acls) != 0 {
		t.Fatalf("acls left: %v", acls)
	}
	m, _ := p.markers(ctx, tg.TopicPrefix)
	if len(m.owners)+len(m.retained) != 0 {
		t.Fatalf("markers left: %+v", m)
	}
	if ok, _ := p.adm.SCRAMUserExists(ctx, tg.User); ok {
		t.Fatal("SCRAM user not deleted")
	}
}

// waitPartitions waits until topic has n partitions (-1: does not exist),
// since topic metadata propagates asynchronously.
func waitPartitions(ctx context.Context, t *testing.T, p *Plugin, topic string, n int32) {
	t.Helper()
	var last topicInfo
	var exists bool
	for range 100 {
		topics, err := p.adm.ListTopics(ctx)
		if err != nil {
			t.Fatal(err)
		}
		last, exists = topics[topic]
		if (n == -1 && !exists) || (exists && last.Partitions == n) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("topic %s: exists=%v %+v, want %d partitions", topic, exists, last, n)
}

// checkTenantAccess connects as the tenant: producing to and consuming
// from its own topic works, a topic outside its prefix is denied.
func checkTenantAccess(ctx context.Context, t *testing.T, brokers []string, tg target, password string) {
	t.Helper()
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.SASL(scram.Auth{User: tg.User, Pass: password}.AsSha512Mechanism()),
		kgo.ConsumerGroup(tg.GroupPrefix+"workers"),
		kgo.ConsumeTopics(tg.Topics[0]),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if err := cl.ProduceSync(ctx, &kgo.Record{Topic: tg.Topics[0], Value: []byte("hello")}).FirstErr(); err != nil {
		t.Fatalf("produce to own topic: %v", err)
	}
	pollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	got := false
	for !got && pollCtx.Err() == nil {
		fs := cl.PollFetches(pollCtx)
		if errs := fs.Errors(); len(errs) > 0 && pollCtx.Err() == nil {
			t.Fatalf("consume: %v", errs)
		}
		fs.EachRecord(func(r *kgo.Record) { got = got || string(r.Value) == "hello" })
	}
	if !got {
		t.Fatal("did not consume own record")
	}
	err = cl.ProduceSync(ctx, &kgo.Record{Topic: "outside-" + tg.Name, Value: []byte("x")}).FirstErr()
	if !errors.Is(err, kerr.TopicAuthorizationFailed) {
		t.Fatalf("produce outside prefix: %v, want TOPIC_AUTHORIZATION_FAILED", err)
	}
}

func TestIntegrationRetain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, reg := newIntegrationPlugin(t, integrationConfig(DeprovisionRetain))
	tenant := reg.HostImpl.AddTenant(sdk.Tenant{Slug: randSlug(t)})
	tg, _ := p.target(tenant)
	if err := p.Provision(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	waitPartitions(ctx, t, p, tg.Topics[0], 2)
	if err := p.Deprovision(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	topics, _ := p.adm.ListTopics(ctx)
	if _, ok := topics[tg.Topics[0]]; !ok {
		t.Fatal("retained topic deleted")
	}
	m, err := p.markers(ctx, tg.TopicPrefix)
	if err != nil || len(m.owners) != 0 || len(m.retained) != 1 {
		t.Fatalf("markers %+v %v", m, err)
	}
	if acls, _ := p.adm.DescribeACLs(ctx, aclFilter{Principal: &tg.Principal}); len(acls) != 0 {
		t.Fatalf("acls left: %v", acls)
	}
	twin := reg.HostImpl.AddTenant(sdk.Tenant{Slug: tenant.Slug})
	if err := p.Provision(ctx, twin); err == nil || !strings.Contains(err.Error(), "retained data") {
		t.Fatalf("twin provision: %v", err)
	}
	// Clean up as an operator would.
	if err := p.adm.DeleteTopics(ctx, tg.Topics); err != nil {
		t.Fatal(err)
	}
	if err := p.adm.DeleteACLs(ctx, []aclBinding{markerACL(RetainedPrincipalPrefix+tenant.ID, tg.TopicPrefix)}); err != nil {
		t.Fatal(err)
	}
}
