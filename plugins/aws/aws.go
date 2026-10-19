// Package aws publishes events to Amazon SQS, SNS or EventBridge as
// CloudEvents (plugin ID "aws-events").
//
// One plugin instance targets one destination, chosen with target:
//
//   - sqs: SendMessage with the CloudEvent JSON as the body. For FIFO queues
//     (URL ending in ".fifo") MessageGroupId is the tenant ID, keeping each
//     tenant's events ordered, and MessageDeduplicationId is the event ID, so
//     retries within SQS' five-minute window are dropped.
//   - sns: Publish with the CloudEvent JSON as the message and the
//     attributes type, tenant_id and event_id for subscription filter
//     policies. FIFO topics get the same group and deduplication IDs as SQS.
//   - eventbridge: PutEvents with Source (default "tenarium"), DetailType =
//     event type and Detail = the CloudEvent JSON. A partially failed batch
//     (FailedEntryCount > 0) is an error, so the event is retried.
//
// Credentials come from static keys in the configuration or, if those are
// not set, from the default AWS credential chain (environment, shared config
// and profile, web identity, ECS/EC2 roles). endpoint overrides the service
// URL, e.g. for LocalStack.
package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func init() {
	sdk.Register("aws-events", func() sdk.Plugin { return &Plugin{} })
}

// Targets.
const (
	TargetSQS         = "sqs"
	TargetSNS         = "sns"
	TargetEventBridge = "eventbridge"
)

// GlobalGroup is the FIFO message group of events without a tenant (plan.*).
const GlobalGroup = "global"

type Config struct {
	// Target is sqs, sns or eventbridge.
	Target string   `json:"target"`
	Region string   `json:"region"`
	Events []string `json:"events"`
	// Endpoint overrides the service endpoint URL (LocalStack, VPC endpoints).
	Endpoint string `json:"endpoint"`
	// Static credentials; when empty, the default credential chain is used.
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	// Profile selects a shared config profile for the default chain.
	Profile string `json:"profile"`

	SQS         *SQSConfig         `json:"sqs"`
	SNS         *SNSConfig         `json:"sns"`
	EventBridge *EventBridgeConfig `json:"eventbridge"`
}

type SQSConfig struct {
	QueueURL string `json:"queue_url"`
}

type SNSConfig struct {
	TopicARN string `json:"topic_arn"`
}

type EventBridgeConfig struct {
	// EventBus is a bus name or ARN (default "default").
	EventBus string `json:"event_bus"`
	// Source is the EventBridge source (default "tenarium").
	Source string `json:"source"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "target": {"enum": ["sqs", "sns", "eventbridge"]},
    "region": {"type": "string", "minLength": 1},
    "events": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "endpoint": {"type": "string", "pattern": "^https?://"},
    "access_key_id": {"type": "string", "minLength": 1},
    "secret_access_key": {"type": "string", "minLength": 1},
    "session_token": {"type": "string"},
    "profile": {"type": "string", "minLength": 1},
    "sqs": {
      "type": "object",
      "properties": {"queue_url": {"type": "string", "pattern": "^https?://"}},
      "required": ["queue_url"],
      "additionalProperties": false
    },
    "sns": {
      "type": "object",
      "properties": {"topic_arn": {"type": "string", "pattern": "^arn:"}},
      "required": ["topic_arn"],
      "additionalProperties": false
    },
    "eventbridge": {
      "type": "object",
      "properties": {
        "event_bus": {"type": "string", "minLength": 1},
        "source": {"type": "string", "minLength": 1, "maxLength": 256}
      },
      "additionalProperties": false
    }
  },
  "required": ["target"],
  "dependentRequired": {
    "access_key_id": ["secret_access_key"],
    "secret_access_key": ["access_key_id"]
  },
  "allOf": [
    {"if": {"properties": {"target": {"const": "sqs"}}}, "then": {"required": ["sqs"]}},
    {"if": {"properties": {"target": {"const": "sns"}}}, "then": {"required": ["sns"]}}
  ],
  "additionalProperties": false
}`)

// The service calls the plugin makes; tests replace them with fakes.
type sqsAPI interface {
	SendMessage(ctx context.Context, in *sqs.SendMessageInput, opts ...func(*sqs.Options)) (*sqs.SendMessageOutput, error)
	GetQueueAttributes(ctx context.Context, in *sqs.GetQueueAttributesInput, opts ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

type snsAPI interface {
	Publish(ctx context.Context, in *sns.PublishInput, opts ...func(*sns.Options)) (*sns.PublishOutput, error)
	GetTopicAttributes(ctx context.Context, in *sns.GetTopicAttributesInput, opts ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error)
}

type eventBridgeAPI interface {
	PutEvents(ctx context.Context, in *eventbridge.PutEventsInput, opts ...func(*eventbridge.Options)) (*eventbridge.PutEventsOutput, error)
	DescribeEventBus(ctx context.Context, in *eventbridge.DescribeEventBusInput, opts ...func(*eventbridge.Options)) (*eventbridge.DescribeEventBusOutput, error)
}

type Plugin struct {
	cfg  Config
	log  *slog.Logger
	fifo bool

	sqs sqsAPI
	sns snsAPI
	eb  eventBridgeAPI

	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "aws-events",
		Name:         "AWS Events Publisher",
		Version:      "0.1.0",
		Description:  "Publishes tenant events to Amazon SQS, SNS or EventBridge as CloudEvents.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(ctx context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	p.log = r.Logger()
	if err := p.setup(ctx); err != nil {
		return err
	}
	r.Subscribe("publish", sdk.EventFilter{Types: p.cfg.Events}, p.publish)
	return nil
}

// Reconfigure applies a new target, destination, region, endpoint,
// credentials or profile without a restart (e.g. key rotation). The SDK
// clients hold no connections that need closing: in-flight publishes
// finish with the previous client. The event filter is fixed at startup.
func (p *Plugin) Reconfigure(ctx context.Context, decode func(v any) error) error {
	n := &Plugin{log: p.log}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if !slices.Equal(n.cfg.Events, p.cfg.Events) {
		return errors.New("aws-events: events take effect after a restart")
	}
	if err := n.setup(ctx); err != nil {
		return err
	}
	p.next.Store(n)
	return nil
}

// setup validates the configuration and builds the client for the target.
func (p *Plugin) setup(ctx context.Context) error {
	if err := p.validate(); err != nil {
		return err
	}
	awsCfg, err := p.loadAWSConfig(ctx)
	if err != nil {
		return err
	}
	ep := p.cfg.Endpoint
	switch p.cfg.Target {
	case TargetSQS:
		p.sqs = sqs.NewFromConfig(awsCfg, func(o *sqs.Options) {
			if ep != "" {
				o.BaseEndpoint = aws.String(ep)
			}
		})
	case TargetSNS:
		p.sns = sns.NewFromConfig(awsCfg, func(o *sns.Options) {
			if ep != "" {
				o.BaseEndpoint = aws.String(ep)
			}
		})
	case TargetEventBridge:
		p.eb = eventbridge.NewFromConfig(awsCfg, func(o *eventbridge.Options) {
			if ep != "" {
				o.BaseEndpoint = aws.String(ep)
			}
		})
	}
	return nil
}

func (p *Plugin) validate() error {
	c := &p.cfg
	if (c.AccessKeyID == "") != (c.SecretAccessKey == "") {
		return errors.New("aws-events: access_key_id and secret_access_key must be set together")
	}
	if c.SessionToken != "" && c.AccessKeyID == "" {
		return errors.New("aws-events: session_token requires access_key_id")
	}
	if c.Profile != "" && c.AccessKeyID != "" {
		return errors.New("aws-events: profile and static credentials are mutually exclusive")
	}
	if c.Endpoint != "" && !strings.HasPrefix(c.Endpoint, "http://") && !strings.HasPrefix(c.Endpoint, "https://") {
		return fmt.Errorf("aws-events: endpoint must be an http(s) URL, got %q", c.Endpoint)
	}
	blocks := map[string]bool{TargetSQS: c.SQS != nil, TargetSNS: c.SNS != nil, TargetEventBridge: c.EventBridge != nil}
	for name, set := range blocks {
		if set && name != c.Target {
			return fmt.Errorf("aws-events: %s block given but target is %q", name, c.Target)
		}
	}
	switch c.Target {
	case TargetSQS:
		if c.SQS == nil || c.SQS.QueueURL == "" {
			return errors.New("aws-events: sqs.queue_url is required")
		}
		p.fifo = strings.HasSuffix(c.SQS.QueueURL, ".fifo")
	case TargetSNS:
		if c.SNS == nil || !strings.HasPrefix(c.SNS.TopicARN, "arn:") {
			return errors.New("aws-events: sns.topic_arn is required")
		}
		p.fifo = strings.HasSuffix(c.SNS.TopicARN, ".fifo")
	case TargetEventBridge:
		if c.EventBridge == nil {
			c.EventBridge = &EventBridgeConfig{}
		}
		if c.EventBridge.EventBus == "" {
			c.EventBridge.EventBus = "default"
		}
		if c.EventBridge.Source == "" {
			c.EventBridge.Source = "tenarium"
		}
		if strings.HasPrefix(c.EventBridge.Source, "aws.") {
			return errors.New("aws-events: eventbridge.source must not start with \"aws.\"")
		}
	default:
		return fmt.Errorf("aws-events: target must be sqs, sns or eventbridge, got %q", c.Target)
	}
	return nil
}

func (p *Plugin) loadAWSConfig(ctx context.Context) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error
	if p.cfg.Region != "" {
		opts = append(opts, config.WithRegion(p.cfg.Region))
	}
	if p.cfg.AccessKeyID != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(p.cfg.AccessKeyID, p.cfg.SecretAccessKey, p.cfg.SessionToken)))
	}
	if p.cfg.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(p.cfg.Profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("aws-events: load AWS config: %w", err)
	}
	if cfg.Region == "" {
		return aws.Config{}, errors.New("aws-events: region is required (config or AWS_REGION)")
	}
	return cfg, nil
}

func (p *Plugin) publish(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.publish(ctx, e)
	}
	body, err := json.Marshal(e.CloudEvent())
	if err != nil {
		return err
	}
	switch p.cfg.Target {
	case TargetSQS:
		return p.sendSQS(ctx, e, string(body))
	case TargetSNS:
		return p.publishSNS(ctx, e, string(body))
	default:
		return p.putEvents(ctx, e, string(body))
	}
}

// group is the FIFO message group: the tenant, or GlobalGroup.
func group(e sdk.Event) string {
	if e.TenantID != "" {
		return e.TenantID
	}
	return GlobalGroup
}

func (p *Plugin) sendSQS(ctx context.Context, e sdk.Event, body string) error {
	in := &sqs.SendMessageInput{
		QueueUrl:          aws.String(p.cfg.SQS.QueueURL),
		MessageBody:       aws.String(body),
		MessageAttributes: map[string]sqstypes.MessageAttributeValue{},
	}
	for k, v := range attributes(e) {
		in.MessageAttributes[k] = sqstypes.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(v)}
	}
	if p.fifo {
		in.MessageGroupId = aws.String(group(e))
		in.MessageDeduplicationId = aws.String(e.ID)
	}
	if _, err := p.sqs.SendMessage(ctx, in); err != nil {
		return fmt.Errorf("aws-events: sqs send %s: %w", e.ID, err)
	}
	return nil
}

func (p *Plugin) publishSNS(ctx context.Context, e sdk.Event, body string) error {
	in := &sns.PublishInput{
		TopicArn:          aws.String(p.cfg.SNS.TopicARN),
		Message:           aws.String(body),
		MessageAttributes: map[string]snstypes.MessageAttributeValue{},
	}
	for k, v := range attributes(e) {
		in.MessageAttributes[k] = snstypes.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(v)}
	}
	if p.fifo {
		in.MessageGroupId = aws.String(group(e))
		in.MessageDeduplicationId = aws.String(e.ID)
	}
	if _, err := p.sns.Publish(ctx, in); err != nil {
		return fmt.Errorf("aws-events: sns publish %s: %w", e.ID, err)
	}
	return nil
}

func (p *Plugin) putEvents(ctx context.Context, e sdk.Event, body string) error {
	entry := ebtypes.PutEventsRequestEntry{
		EventBusName: aws.String(p.cfg.EventBridge.EventBus),
		Source:       aws.String(p.cfg.EventBridge.Source),
		DetailType:   aws.String(e.Type),
		Detail:       aws.String(body),
	}
	if !e.Time.IsZero() {
		entry.Time = aws.Time(e.Time)
	}
	out, err := p.eb.PutEvents(ctx, &eventbridge.PutEventsInput{Entries: []ebtypes.PutEventsRequestEntry{entry}})
	if err != nil {
		return fmt.Errorf("aws-events: eventbridge put %s: %w", e.ID, err)
	}
	if out.FailedEntryCount > 0 {
		var reasons []string
		for _, r := range out.Entries {
			if r.ErrorCode != nil {
				reasons = append(reasons, aws.ToString(r.ErrorCode)+": "+aws.ToString(r.ErrorMessage))
			}
		}
		return fmt.Errorf("aws-events: eventbridge rejected %s (%d failed): %s", e.ID, out.FailedEntryCount, strings.Join(reasons, "; "))
	}
	return nil
}

// attributes are the message attributes for SQS and SNS (filter policies).
func attributes(e sdk.Event) map[string]string {
	a := map[string]string{"type": e.Type, "event_id": e.ID, "content_type": "application/cloudevents+json"}
	if e.TenantID != "" {
		a["tenant_id"] = e.TenantID
	}
	return a
}

// Health checks that the destination exists and the credentials can see it.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	var err error
	switch p.cfg.Target {
	case TargetSQS:
		_, err = p.sqs.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
			QueueUrl:       aws.String(p.cfg.SQS.QueueURL),
			AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn},
		})
	case TargetSNS:
		_, err = p.sns.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: aws.String(p.cfg.SNS.TopicARN)})
	case TargetEventBridge:
		_, err = p.eb.DescribeEventBus(ctx, &eventbridge.DescribeEventBusInput{Name: aws.String(p.cfg.EventBridge.EventBus)})
	default:
		return errors.New("aws-events: not initialized")
	}
	if err != nil {
		return fmt.Errorf("aws-events: %s health: %w", p.cfg.Target, err)
	}
	return nil
}
