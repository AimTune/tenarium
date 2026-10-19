package sdk

import (
	"context"
	"encoding/json"
	"path"
	"strconv"
	"time"
)

// Event types emitted by the core. Plugins may filter on these with glob
// patterns, e.g. "tenant.*".
const (
	EventTenantCreated            = "tenant.created"
	EventTenantUpdated            = "tenant.updated"
	EventTenantProvisioning       = "tenant.provisioning"
	EventTenantProvisioned        = "tenant.provisioned"
	EventTenantProvisioningFailed = "tenant.provisioning_failed"
	EventTenantSuspended          = "tenant.suspended"
	EventTenantResumed            = "tenant.resumed"
	EventTenantDeleting           = "tenant.deleting"
	EventTenantDeleted            = "tenant.deleted"
	// EventTenantDeprovisioningFailed means resources could not be removed;
	// the tenant is "failed" and deleting it again retries.
	EventTenantDeprovisioningFailed = "tenant.deprovisioning_failed"
	// EventTenantPlanChanged is emitted in addition to tenant.updated when
	// an update changes the tenant's plan.
	EventTenantPlanChanged = "tenant.plan_changed"
	// EventTenantRegionChanged means the tenant was moved to another region;
	// Previous carries the old one.
	EventTenantRegionChanged = "tenant.region_changed"
	// EventTenantQuotaExceeded is emitted when a usage increment is refused.
	EventTenantQuotaExceeded = "tenant.quota_exceeded"
	// EventTenantUsageThreshold is emitted when a counter crosses a
	// configured percentage of its limit (soft limits, overage warnings).
	EventTenantUsageThreshold = "tenant.usage_threshold_reached"
	// EventTenantUsagePeriodClosed reports the final value of a counter
	// once its period ended, exactly once; billing exports consume it.
	EventTenantUsagePeriodClosed = "tenant.usage_period_closed"

	EventMemberAdded   = "tenant.member_added"
	EventMemberUpdated = "tenant.member_updated"
	EventMemberRemoved = "tenant.member_removed"

	EventPlanCreated = "plan.created"
	EventPlanUpdated = "plan.updated"
	EventPlanDeleted = "plan.deleted"
)

// Event is a domain event. Its fields map 1:1 onto CloudEvents 1.0
// attributes (tenantid is a CloudEvents extension attribute), so sinks can
// forward it to any CloudEvents-aware system without translation.
type Event struct {
	// Seq is the global, monotonically increasing position in the event log.
	Seq      int64  `json:"seq"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Source   string `json:"source"`
	Subject  string `json:"subject,omitempty"`
	TenantID string `json:"tenantid,omitempty"`
	// Actor is who caused the event: "{authenticator}:{subject}" for API
	// callers, "system" for internal transitions.
	Actor string          `json:"actor,omitempty"`
	Time  time.Time       `json:"time"`
	Data  json.RawMessage `json:"data,omitempty"`
	// TraceParent and TraceState are the W3C trace context of the request
	// that caused the event (CloudEvents distributed tracing extension);
	// empty when tracing is off.
	TraceParent string `json:"traceparent,omitempty"`
	TraceState  string `json:"tracestate,omitempty"`
	// DataSchema is the URI of the JSON Schema of Data (CloudEvents
	// "dataschema"), naming the schema version the payload follows.
	DataSchema string `json:"dataschema,omitempty"`
}

// CloudEvent is the CloudEvents 1.0 structured-mode JSON form of an Event.
type CloudEvent struct {
	SpecVersion     string          `json:"specversion"`
	ID              string          `json:"id"`
	Source          string          `json:"source"`
	Type            string          `json:"type"`
	Subject         string          `json:"subject,omitempty"`
	Time            string          `json:"time"`
	DataContentType string          `json:"datacontenttype,omitempty"`
	TenantID        string          `json:"tenantid,omitempty"`
	Actor           string          `json:"actor,omitempty"`
	Sequence        string          `json:"sequence"`
	TraceParent     string          `json:"traceparent,omitempty"`
	TraceState      string          `json:"tracestate,omitempty"`
	DataSchema      string          `json:"dataschema,omitempty"`
	Data            json.RawMessage `json:"data,omitempty"`
}

// CloudEvent converts e to its CloudEvents representation.
func (e Event) CloudEvent() CloudEvent {
	ce := CloudEvent{
		SpecVersion: "1.0",
		ID:          e.ID,
		Source:      e.Source,
		Type:        e.Type,
		Subject:     e.Subject,
		Time:        e.Time.UTC().Format(time.RFC3339Nano),
		TenantID:    e.TenantID,
		Actor:       e.Actor,
		Sequence:    strconv.FormatInt(e.Seq, 10),
		TraceParent: e.TraceParent,
		TraceState:  e.TraceState,
		DataSchema:  e.DataSchema,
		Data:        e.Data,
	}
	if len(e.Data) > 0 {
		ce.DataContentType = "application/json"
	}
	return ce
}

// EventHandler processes one event. Returning an error causes the delivery to
// be retried with backoff; after the subscription's max attempts the event is
// moved to the dead-letter queue. Handlers must be idempotent (use Event.ID).
type EventHandler func(ctx context.Context, e Event) error

// EventFilter selects which events a subscription receives.
type EventFilter struct {
	// Types are glob patterns (path.Match syntax) on Event.Type. Empty
	// means all events.
	Types []string `json:"types,omitempty"`
}

// Match reports whether e passes the filter.
func (f EventFilter) Match(e Event) bool {
	if len(f.Types) == 0 {
		return true
	}
	for _, p := range f.Types {
		if ok, _ := path.Match(p, e.Type); ok {
			return true
		}
	}
	return false
}

// SubscribeOptions tune delivery for one subscription.
type SubscribeOptions struct {
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	// Timeout bounds one delivery attempt; zero uses the server default.
	Timeout time.Duration
	// StartAtEnd makes a brand-new subscription skip historical events
	// instead of replaying the whole log.
	StartAtEnd bool
}

type SubscribeOption func(*SubscribeOptions)

func WithMaxAttempts(n int) SubscribeOption {
	return func(o *SubscribeOptions) { o.MaxAttempts = n }
}

func WithBackoff(base, max time.Duration) SubscribeOption {
	return func(o *SubscribeOptions) { o.BaseBackoff, o.MaxBackoff = base, max }
}

func WithStartAtEnd() SubscribeOption {
	return func(o *SubscribeOptions) { o.StartAtEnd = true }
}

// DefaultSubscribeOptions returns the options applied before user options.
func DefaultSubscribeOptions() SubscribeOptions {
	return SubscribeOptions{
		MaxAttempts: 10,
		BaseBackoff: 200 * time.Millisecond,
		MaxBackoff:  30 * time.Second,
	}
}
