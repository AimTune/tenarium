package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type fakeSQS struct {
	sent []*sqs.SendMessageInput
	err  error
}

func (f *fakeSQS) SendMessage(_ context.Context, in *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	f.sent = append(f.sent, in)
	return &sqs.SendMessageOutput{}, f.err
}

func (f *fakeSQS) GetQueueAttributes(context.Context, *sqs.GetQueueAttributesInput, ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	return &sqs.GetQueueAttributesOutput{}, f.err
}

type fakeSNS struct{ sent []*sns.PublishInput }

func (f *fakeSNS) Publish(_ context.Context, in *sns.PublishInput, _ ...func(*sns.Options)) (*sns.PublishOutput, error) {
	f.sent = append(f.sent, in)
	return &sns.PublishOutput{}, nil
}

func (f *fakeSNS) GetTopicAttributes(context.Context, *sns.GetTopicAttributesInput, ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
	return &sns.GetTopicAttributesOutput{}, nil
}

type fakeEB struct {
	sent []*eventbridge.PutEventsInput
	out  *eventbridge.PutEventsOutput
}

func (f *fakeEB) PutEvents(_ context.Context, in *eventbridge.PutEventsInput, _ ...func(*eventbridge.Options)) (*eventbridge.PutEventsOutput, error) {
	f.sent = append(f.sent, in)
	if f.out != nil {
		return f.out, nil
	}
	return &eventbridge.PutEventsOutput{}, nil
}

func (f *fakeEB) DescribeEventBus(context.Context, *eventbridge.DescribeEventBusInput, ...func(*eventbridge.Options)) (*eventbridge.DescribeEventBusOutput, error) {
	return &eventbridge.DescribeEventBusOutput{}, nil
}

func testPlugin(t *testing.T, cfg Config) *Plugin {
	t.Helper()
	p := &Plugin{cfg: cfg}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func event() sdk.Event {
	e := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1", Slug: "acme"})
	e.Seq = 5
	return e
}

func TestSQSFIFO(t *testing.T) {
	p := testPlugin(t, Config{Target: "sqs", SQS: &SQSConfig{QueueURL: "https://sqs.eu-west-1.amazonaws.com/1/q.fifo"}})
	f := &fakeSQS{}
	p.sqs = f
	e := event()
	if err := p.publish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	in := f.sent[0]
	if aws.ToString(in.MessageGroupId) != "t1" || aws.ToString(in.MessageDeduplicationId) != e.ID {
		t.Fatalf("fifo ids %v %v", in.MessageGroupId, in.MessageDeduplicationId)
	}
	if aws.ToString(in.MessageAttributes["type"].StringValue) != e.Type || aws.ToString(in.MessageAttributes["tenant_id"].StringValue) != "t1" {
		t.Fatalf("attributes %v", in.MessageAttributes)
	}
	var ce sdk.CloudEvent
	if err := json.Unmarshal([]byte(aws.ToString(in.MessageBody)), &ce); err != nil || ce.ID != e.ID || ce.Sequence != "5" {
		t.Fatalf("body %v", err)
	}

	// Plan events have no tenant: they go to the global group.
	if err := p.publish(context.Background(), sdk.Event{ID: "p", Type: sdk.EventPlanCreated}); err != nil {
		t.Fatal(err)
	}
	if aws.ToString(f.sent[1].MessageGroupId) != GlobalGroup {
		t.Fatalf("group %v", f.sent[1].MessageGroupId)
	}

	f.err = errors.New("throttled")
	if p.publish(context.Background(), e) == nil || p.Health(context.Background()) == nil {
		t.Fatal("errors not returned")
	}
}

func TestSQSStandard(t *testing.T) {
	p := testPlugin(t, Config{Target: "sqs", SQS: &SQSConfig{QueueURL: "https://sqs.eu-west-1.amazonaws.com/1/q"}})
	f := &fakeSQS{}
	p.sqs = f
	if err := p.publish(context.Background(), event()); err != nil {
		t.Fatal(err)
	}
	if f.sent[0].MessageGroupId != nil || f.sent[0].MessageDeduplicationId != nil {
		t.Fatal("FIFO fields on a standard queue")
	}
}

func TestSNS(t *testing.T) {
	p := testPlugin(t, Config{Target: "sns", SNS: &SNSConfig{TopicARN: "arn:aws:sns:eu-west-1:1:events.fifo"}})
	f := &fakeSNS{}
	p.sns = f
	e := event()
	if err := p.publish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	in := f.sent[0]
	if aws.ToString(in.MessageGroupId) != "t1" || aws.ToString(in.MessageDeduplicationId) != e.ID ||
		aws.ToString(in.MessageAttributes["tenant_id"].StringValue) != "t1" || !strings.Contains(aws.ToString(in.Message), e.ID) {
		t.Fatalf("publish input %+v", in)
	}
}

func TestEventBridge(t *testing.T) {
	p := testPlugin(t, Config{Target: "eventbridge"})
	f := &fakeEB{}
	p.eb = f
	e := event()
	if err := p.publish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	entry := f.sent[0].Entries[0]
	if aws.ToString(entry.Source) != "tenarium" || aws.ToString(entry.DetailType) != e.Type ||
		aws.ToString(entry.EventBusName) != "default" || entry.Time == nil {
		t.Fatalf("entry %+v", entry)
	}
	var ce sdk.CloudEvent
	if err := json.Unmarshal([]byte(aws.ToString(entry.Detail)), &ce); err != nil || ce.ID != e.ID {
		t.Fatalf("detail %v", err)
	}

	f.out = &eventbridge.PutEventsOutput{FailedEntryCount: 1, Entries: []ebtypes.PutEventsResultEntry{
		{ErrorCode: aws.String("InternalFailure"), ErrorMessage: aws.String("try again")},
	}}
	err := p.publish(context.Background(), e)
	if err == nil || !strings.Contains(err.Error(), "InternalFailure") {
		t.Fatalf("partial failure: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, cfg := range []map[string]any{
		{},
		{"target": "kinesis"},
		{"target": "sqs"},
		{"target": "sns", "sns": map[string]any{"topic_arn": "events"}},
		{"target": "sqs", "sqs": map[string]any{"queue_url": "https://q"}, "sns": map[string]any{"topic_arn": "arn:x"}},
		{"target": "eventbridge", "eventbridge": map[string]any{"source": "aws.custom"}},
		{"target": "eventbridge", "access_key_id": "AK"},
		{"target": "eventbridge", "session_token": "t"},
		{"target": "eventbridge", "endpoint": "localhost:4566"},
		{"target": "eventbridge", "nope": 1},
	} {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("config %v accepted", cfg)
		}
	}
	// A valid config initializes without network access.
	reg := sdktest.NewRegistrar(map[string]any{"target": "eventbridge", "region": "eu-west-1",
		"access_key_id": "AK", "secret_access_key": "SK", "endpoint": "http://localhost:1"})
	if err := (&Plugin{}).Init(context.Background(), reg); err != nil || len(reg.Subscriptions) != 1 {
		t.Fatalf("valid config: %v", err)
	}
}

func TestConfigSchema(t *testing.T) {
	s, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	for _, good := range []map[string]any{
		{"target": "sqs", "region": "eu-west-1", "sqs": map[string]any{"queue_url": "https://sqs/1/q.fifo"}},
		{"target": "sns", "sns": map[string]any{"topic_arn": "arn:aws:sns:eu-west-1:1:t"}, "access_key_id": "a", "secret_access_key": "b"},
		{"target": "eventbridge", "eventbridge": map[string]any{"event_bus": "bus", "source": "acme.tenarium"}, "events": []any{"tenant.*"}},
	} {
		if err := s.Validate(good); err != nil {
			t.Errorf("%v: %v", good, err)
		}
	}
	for name, bad := range map[string]map[string]any{
		"missing target": {},
		"sqs no block":   {"target": "sqs"},
		"key no secret":  {"target": "eventbridge", "access_key_id": "a"},
		"unknown":        {"target": "eventbridge", "nope": 1},
		"bad endpoint":   {"target": "eventbridge", "endpoint": "localhost"},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%s: expected schema error", name)
		}
	}
}

// TestLocalStack runs against LocalStack (SQS, SNS, EventBridge), e.g.
// `docker run -d -p 14566:4566 localstack/localstack:3.8` and
// TENARIUM_TEST_AWS_ENDPOINT=http://localhost:14566.
func TestLocalStack(t *testing.T) {
	endpoint := os.Getenv("TENARIUM_TEST_AWS_ENDPOINT")
	if endpoint == "" {
		t.Skip("TENARIUM_TEST_AWS_ENDPOINT not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	base := map[string]any{"region": "us-east-1", "endpoint": endpoint, "access_key_id": "test", "secret_access_key": "test"}
	cfgWith := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	setup := &Plugin{cfg: Config{Region: "us-east-1", AccessKeyID: "test", SecretAccessKey: "test"}}
	awsCfg, err := setup.loadAWSConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sqsc := sqs.NewFromConfig(awsCfg, func(o *sqs.Options) { o.BaseEndpoint = aws.String(endpoint) })
	snsc := sns.NewFromConfig(awsCfg, func(o *sns.Options) { o.BaseEndpoint = aws.String(endpoint) })
	ebc := eventbridge.NewFromConfig(awsCfg, func(o *eventbridge.Options) { o.BaseEndpoint = aws.String(endpoint) })
	suffix := fmt.Sprint(time.Now().UnixNano())

	receive := func(t *testing.T, url string) []sqstypes.Message {
		t.Helper()
		out, err := sqsc.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: aws.String(url), MaxNumberOfMessages: 10,
			WaitTimeSeconds: 2, MessageAttributeNames: []string{"All"}, MessageSystemAttributeNames: []sqstypes.MessageSystemAttributeName{"All"}})
		if err != nil {
			t.Fatal(err)
		}
		return out.Messages
	}

	t.Run("sqs fifo", func(t *testing.T) {
		q, err := sqsc.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("tenarium-" + suffix + ".fifo"),
			Attributes: map[string]string{"FifoQueue": "true"}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = sqsc.DeleteQueue(ctx, &sqs.DeleteQueueInput{QueueUrl: q.QueueUrl}) }()
		reg := sdktest.NewRegistrar(cfgWith(map[string]any{"target": "sqs", "sqs": map[string]any{"queue_url": *q.QueueUrl}}))
		p := &Plugin{}
		if err := p.Init(ctx, reg); err != nil {
			t.Fatal(err)
		}
		if err := p.Health(ctx); err != nil {
			t.Fatal(err)
		}
		e := event()
		for range 2 { // retry: deduplicated by SQS
			if err := reg.Deliver(ctx, "publish", e); err != nil {
				t.Fatal(err)
			}
		}
		msgs := receive(t, *q.QueueUrl)
		if len(msgs) != 1 || msgs[0].Attributes["MessageGroupId"] != "t1" ||
			aws.ToString(msgs[0].MessageAttributes["type"].StringValue) != e.Type {
			t.Fatalf("messages %+v", msgs)
		}
	})

	t.Run("sns", func(t *testing.T) {
		topic, err := snsc.CreateTopic(ctx, &sns.CreateTopicInput{Name: aws.String("tenarium-" + suffix)})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = snsc.DeleteTopic(ctx, &sns.DeleteTopicInput{TopicArn: topic.TopicArn}) }()
		q, err := sqsc.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("tenarium-sns-" + suffix)})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = sqsc.DeleteQueue(ctx, &sqs.DeleteQueueInput{QueueUrl: q.QueueUrl}) }()
		qa, err := sqsc.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: q.QueueUrl,
			AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := snsc.Subscribe(ctx, &sns.SubscribeInput{TopicArn: topic.TopicArn, Protocol: aws.String("sqs"),
			Endpoint: aws.String(qa.Attributes["QueueArn"]), Attributes: map[string]string{
				"RawMessageDelivery": "true", "FilterPolicy": `{"tenant_id":["t1"]}`}}); err != nil {
			t.Fatal(err)
		}
		reg := sdktest.NewRegistrar(cfgWith(map[string]any{"target": "sns", "sns": map[string]any{"topic_arn": *topic.TopicArn}}))
		p := &Plugin{}
		if err := p.Init(ctx, reg); err != nil {
			t.Fatal(err)
		}
		if err := p.Health(ctx); err != nil {
			t.Fatal(err)
		}
		e := event()
		if err := reg.Deliver(ctx, "publish", e); err != nil {
			t.Fatal(err)
		}
		other := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t2"})
		if err := reg.Deliver(ctx, "publish", other); err != nil {
			t.Fatal(err)
		}
		msgs := receive(t, *q.QueueUrl)
		if len(msgs) != 1 || !strings.Contains(aws.ToString(msgs[0].Body), e.ID) {
			t.Fatalf("messages %+v", msgs)
		}
	})

	t.Run("eventbridge", func(t *testing.T) {
		bus := "tenarium-" + suffix
		if _, err := ebc.CreateEventBus(ctx, &eventbridge.CreateEventBusInput{Name: aws.String(bus)}); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = ebc.DeleteEventBus(ctx, &eventbridge.DeleteEventBusInput{Name: aws.String(bus)}) }()
		reg := sdktest.NewRegistrar(cfgWith(map[string]any{"target": "eventbridge", "eventbridge": map[string]any{"event_bus": bus}}))
		p := &Plugin{}
		if err := p.Init(ctx, reg); err != nil {
			t.Fatal(err)
		}
		if err := p.Health(ctx); err != nil {
			t.Fatal(err)
		}
		if err := reg.Deliver(ctx, "publish", event()); err != nil {
			t.Fatal(err)
		}
		missing := sdktest.NewRegistrar(cfgWith(map[string]any{"target": "eventbridge", "eventbridge": map[string]any{"event_bus": "missing-" + suffix}}))
		mp := &Plugin{}
		if err := mp.Init(ctx, missing); err != nil {
			t.Fatal(err)
		}
		if err := mp.Health(ctx); err == nil {
			t.Fatal("health passed for a missing bus")
		}
	})
}

func TestReconfigure(t *testing.T) {
	// Fake EventBridge endpoints recording the signing key ID and bus.
	fake := func() (*httptest.Server, func() []string) {
		var mu sync.Mutex
		var got []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var in struct {
				Entries []struct{ EventBusName string }
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			_, cred, _ := strings.Cut(r.Header.Get("Authorization"), "Credential=")
			key, _, _ := strings.Cut(cred, "/")
			mu.Lock()
			got = append(got, key+" "+in.Entries[0].EventBusName)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			_, _ = w.Write([]byte(`{"FailedEntryCount":0,"Entries":[{"EventId":"1"}]}`))
		}))
		t.Cleanup(srv.Close)
		return srv, func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), got...)
		}
	}
	oldSrv, oldGot := fake()
	newSrv, newGot := fake()
	cfg := func(endpoint, key, bus string) map[string]any {
		return map[string]any{"target": "eventbridge", "region": "eu-west-1", "endpoint": endpoint,
			"access_key_id": key, "secret_access_key": "SK", "eventbridge": map[string]any{"event_bus": bus}}
	}
	reg := sdktest.NewRegistrar(cfg(oldSrv.URL, "AK1", "bus1"))
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg(newSrv.URL, "AK2", "bus2")).Config); err != nil {
		t.Fatal(err)
	}
	if err := reg.Deliver(ctx, "publish", event()); err != nil {
		t.Fatal(err)
	}
	if got := newGot(); len(got) != 1 || got[0] != "AK2 bus2" || len(oldGot()) != 0 {
		t.Fatalf("new %v old %v", got, oldGot())
	}

	// Invalid config: rejected, the previous settings stay.
	bad := cfg(oldSrv.URL, "AK3", "bus3")
	bad["profile"] = "other"
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(bad).Config); err == nil {
		t.Fatal("invalid config accepted")
	}
	if err := reg.Deliver(ctx, "publish", event()); err != nil || len(newGot()) != 2 || len(oldGot()) != 0 {
		t.Fatalf("after failed reconfigure: %v %v", err, newGot())
	}

	// The event filter is fixed at startup.
	ev := cfg(newSrv.URL, "AK2", "bus2")
	ev["events"] = []string{"tenant.*"}
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(ev).Config); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("events change: %v", err)
	}
}
