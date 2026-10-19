// Package segment sends Tenarium events to Segment through the HTTP
// Tracking API (/v1/batch):
//
//   - group: tenant events update the tenant's group (groupId = tenant ID)
//     with traits such as name, slug, plan, status and labels.
//   - identify: user events update the user's profile (userId = user ID).
//   - group for members: member events link the member's user to the
//     tenant's group (link_members).
//   - track: selected event types are tracked as Segment events with the
//     tenant as context.groupId.
//
// Each message's messageId is derived from the event ID ("<id>:group",
// "<id>:identify", "<id>:track", "<id>:member"), so Segment drops messages
// redelivered after a retry.
//
// Messages are batched opportunistically: a delivery is sent at once when no
// request is in flight; deliveries arriving meanwhile share the next
// request (up to batch_size messages and Segment's 500 KB limit). A handler
// returns only after its messages were accepted, so at-least-once delivery
// is preserved.
//
// Configuration:
//
//	plugins:
//	  - plugin: segment
//	    config:
//	      write_key: ${SEGMENT_WRITE_KEY}
//	      track_events: ["tenant.created", "tenant.plan_changed", "tenant.deleted"]
//	      event_names:
//	        tenant.created: Tenant Created
package segment

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

const version = "0.1.0"

func init() {
	sdk.Register("segment", func() sdk.Plugin { return &Plugin{} })
}

// Config is the plugin configuration.
type Config struct {
	// WriteKey is the source's write key.
	WriteKey string `json:"write_key"`
	// APIURL defaults to https://api.segment.io; use
	// https://events.eu1.segmentapis.com for EU workspaces.
	APIURL string `json:"api_url"`
	// Timeout per request, e.g. "10s" (default).
	Timeout string `json:"timeout"`
	// GroupEvents are tenant event globs that send a group call (default
	// ["tenant.*"]; member and usage events are never group calls). An
	// empty list disables group calls.
	GroupEvents *[]string `json:"group_events"`
	// IdentifyUsers sends identify calls for user.* events (default true).
	IdentifyUsers *bool `json:"identify_users"`
	// LinkMembers sends a group call linking a member's user to the tenant
	// on tenant.member_added/updated (default true).
	LinkMembers *bool `json:"link_members"`
	// TrackEvents are event globs sent as track calls (default none).
	TrackEvents []string `json:"track_events"`
	// EventNames maps event types to track event names (default: the type).
	EventNames map[string]string `json:"event_names"`
	// UserActorPrefixes lists authenticators whose actor subject is a
	// Tenarium user ID ("<authenticator>:<user id>"); track calls caused by
	// them use that user as userId. Others use an anonymousId per tenant.
	UserActorPrefixes []string `json:"user_actor_prefixes"`
	// IncludeLabels adds tenant labels to group traits as "label_<key>"
	// (default true).
	IncludeLabels *bool `json:"include_labels"`
	// BatchSize is the maximum number of messages per request (default 100).
	BatchSize int `json:"batch_size"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["write_key"],
  "properties": {
    "write_key": {"type": "string", "minLength": 1},
    "api_url": {"type": "string", "pattern": "^https?://"},
    "timeout": {"type": "string"},
    "group_events": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "identify_users": {"type": "boolean"},
    "link_members": {"type": "boolean"},
    "track_events": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "event_names": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}},
    "user_actor_prefixes": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "include_labels": {"type": "boolean"},
    "batch_size": {"type": "integer", "minimum": 1, "maximum": 500}
  }
}`)

// Plugin is the Segment plugin.
type Plugin struct {
	cfg         Config
	base        string
	client      *http.Client
	log         *slog.Logger
	now         func() time.Time
	groupEvents []string
	batch       *batcher // shared with the copies made by Reconfigure
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "segment",
		Name:         "Segment",
		Version:      version,
		Description:  "Sends tenants (group), users (identify) and selected events (track) to Segment.",
		ConfigSchema: configSchema,
	}
}

func enabled(b *bool) bool { return b == nil || *b }

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	p.log = r.Logger()
	if p.now == nil {
		p.now = time.Now
	}
	if err := p.applyConfig(); err != nil {
		return err
	}
	p.batch = newBatcher(p.cfg.BatchSize, p.send)

	// One subscription per call kind: they progress independently, and
	// their concurrent deliveries share requests.
	if len(p.groupEvents) > 0 {
		r.Subscribe("group", sdk.EventFilter{Types: p.groupEvents}, p.onGroup)
	}
	if enabled(p.cfg.IdentifyUsers) {
		r.Subscribe("identify", sdk.EventFilter{Types: []string{"user.*"}}, p.onIdentify)
	}
	if enabled(p.cfg.LinkMembers) {
		r.Subscribe("members", sdk.EventFilter{Types: []string{sdk.EventMemberAdded, sdk.EventMemberUpdated}}, p.onMember)
	}
	if len(p.cfg.TrackEvents) > 0 {
		r.Subscribe("track", sdk.EventFilter{Types: p.cfg.TrackEvents}, p.onTrack)
	}
	return nil
}

func (p *Plugin) applyConfig() error {
	c := &p.cfg
	if c.WriteKey == "" {
		return errors.New("write_key is required")
	}
	c.APIURL = cmp.Or(c.APIURL, "https://api.segment.io")
	u, err := url.Parse(c.APIURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("api_url must be an absolute http(s) URL, got %q", c.APIURL)
	}
	p.base = strings.TrimRight(c.APIURL, "/")
	timeout := 10 * time.Second
	if c.Timeout != "" {
		if timeout, err = time.ParseDuration(c.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
	}
	p.client = &http.Client{Timeout: timeout}
	if c.BatchSize < 0 || c.BatchSize > 500 {
		return fmt.Errorf("batch_size must be 1-500, got %d", c.BatchSize)
	}
	c.BatchSize = cmp.Or(c.BatchSize, 100)

	p.groupEvents = []string{"tenant.*"}
	if c.GroupEvents != nil {
		p.groupEvents = *c.GroupEvents
	}
	for field, pats := range map[string][]string{"group_events": p.groupEvents, "track_events": c.TrackEvents} {
		for _, pat := range pats {
			if _, err := path.Match(pat, ""); err != nil || pat == "" {
				return fmt.Errorf("%s: invalid pattern %q", field, pat)
			}
		}
	}
	for typ, name := range c.EventNames {
		if typ == "" || name == "" {
			return fmt.Errorf("event_names: empty event type or name (%q: %q)", typ, name)
		}
	}
	for _, a := range c.UserActorPrefixes {
		if a == "" || strings.Contains(a, ":") {
			return fmt.Errorf("user_actor_prefixes: invalid authenticator name %q", a)
		}
	}
	return nil
}

// Health validates nothing remotely: the Tracking API has no endpoint that
// checks a write key without recording data. A wrong key shows up as
// failing deliveries (Segment answers 401).
func (p *Plugin) Health(context.Context) error { return nil }

// Stop waits for an in-flight request to finish.
func (p *Plugin) Stop(ctx context.Context) error { return p.batch.wait(ctx) }

// message is one Segment Tracking API call.
type message map[string]any

func (p *Plugin) newMessage(typ, id string, e sdk.Event) message {
	ts := e.Time
	if ts.IsZero() {
		ts = p.now()
	}
	return message{
		"type":      typ,
		"messageId": id,
		"timestamp": ts.UTC().Format(time.RFC3339Nano),
		"context":   map[string]any{"library": map[string]string{"name": "tenarium-segment", "version": version}},
	}
}

// identity sets userId when the event was caused by a known user, else an
// anonymousId for the tenant (or the platform).
func (p *Plugin) identity(m message, e sdk.Event) {
	if auth, subject, ok := strings.Cut(e.Actor, ":"); ok && subject != "" {
		for _, a := range p.cfg.UserActorPrefixes {
			if a == auth {
				m["userId"] = subject
				return
			}
		}
	}
	if e.TenantID != "" {
		m["anonymousId"] = "tenant:" + e.TenantID
	} else {
		m["anonymousId"] = "tenarium"
	}
}

// groupTraits describes a tenant.
func (p *Plugin) groupTraits(t sdk.Tenant) map[string]any {
	traits := map[string]any{
		"name": t.Name, "slug": t.Slug, "status": string(t.Status), "plan": t.Plan,
		"tenant_id": t.ID, "created_at": t.CreatedAt.UTC().Format(time.RFC3339),
	}
	if t.ParentID != "" {
		traits["parent_id"] = t.ParentID
	}
	if t.StatusReason != "" {
		traits["status_reason"] = t.StatusReason
	}
	if enabled(p.cfg.IncludeLabels) {
		for k, v := range t.Labels {
			traits["label_"+k] = v
		}
	}
	return traits
}

func (p *Plugin) onGroup(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.onGroup(ctx, e)
	}
	if strings.HasPrefix(e.Type, "tenant.member_") || strings.HasPrefix(e.Type, "tenant.usage_") || e.Type == sdk.EventTenantQuotaExceeded {
		return nil // no tenant in the payload
	}
	var d sdk.TenantEventData
	if err := json.Unmarshal(e.Data, &d); err != nil || d.Tenant.ID == "" {
		return nil
	}
	m := p.newMessage("group", e.ID+":group", e)
	p.identity(m, e)
	m["groupId"] = d.Tenant.ID
	traits := p.groupTraits(d.Tenant)
	if e.Type == sdk.EventTenantDeleted {
		traits["deleted"] = true
	}
	m["traits"] = traits
	return p.batch.submit(ctx, m)
}

func (p *Plugin) onIdentify(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.onIdentify(ctx, e)
	}
	var d sdk.UserEventData
	if err := json.Unmarshal(e.Data, &d); err != nil || d.User.ID == "" {
		return nil
	}
	u := d.User
	m := p.newMessage("identify", e.ID+":identify", e)
	m["userId"] = u.ID
	traits := map[string]any{
		"email": u.Email, "status": string(u.Status), "email_verified": u.EmailVerified,
		"created_at": u.CreatedAt.UTC().Format(time.RFC3339),
	}
	if u.Name != "" {
		traits["name"] = u.Name
	}
	if e.Type == sdk.EventUserDeleted {
		traits["deleted"] = true
	}
	m["traits"] = traits
	return p.batch.submit(ctx, m)
}

func (p *Plugin) onMember(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.onMember(ctx, e)
	}
	var d sdk.MemberEventData
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return nil
	}
	mem := d.Member
	if mem.UserID == "" || mem.TenantID == "" {
		return nil // invited, not linked to a user yet
	}
	m := p.newMessage("group", e.ID+":member", e)
	m["userId"] = mem.UserID
	m["groupId"] = mem.TenantID
	// Only the membership; tenant traits come from the tenant's own calls.
	m["traits"] = map[string]any{}
	m["context"].(map[string]any)["traits"] = map[string]any{"role": mem.Role, "email": mem.Email}
	return p.batch.submit(ctx, m)
}

func (p *Plugin) onTrack(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.onTrack(ctx, e)
	}
	m := p.newMessage("track", e.ID+":track", e)
	p.identity(m, e)
	m["event"] = cmp.Or(p.cfg.EventNames[e.Type], e.Type)
	props := map[string]any{"event_type": e.Type, "event_id": e.ID}
	if e.Actor != "" {
		props["actor"] = e.Actor
	}
	if e.TenantID != "" {
		props["tenant_id"] = e.TenantID
		m["context"].(map[string]any)["groupId"] = e.TenantID
	}
	for k, v := range trackProperties(e) {
		props[k] = v
	}
	m["properties"] = props
	return p.batch.submit(ctx, m)
}

// trackProperties extracts a compact, non-sensitive subset of the payload.
func trackProperties(e sdk.Event) map[string]any {
	out := map[string]any{}
	switch {
	case strings.HasPrefix(e.Type, "tenant.member_"):
		var d sdk.MemberEventData
		if json.Unmarshal(e.Data, &d) == nil {
			out["role"], out["member_status"] = d.Member.Role, string(d.Member.Status)
		}
	case e.Type == sdk.EventTenantQuotaExceeded:
		var d sdk.UsageEventData
		if json.Unmarshal(e.Data, &d) == nil {
			out["metric"], out["current"], out["requested"], out["limit"] = d.Metric, d.Current, d.Requested, d.Limit
		}
	case e.Type == sdk.EventTenantUsageThreshold || e.Type == sdk.EventTenantUsagePeriodClosed:
		var d sdk.UsagePeriodData
		if json.Unmarshal(e.Data, &d) == nil {
			out["metric"], out["value"], out["period"] = d.Metric, d.Value, d.Period
			if d.Limit != nil {
				out["limit"] = *d.Limit
			}
			if d.Percent != 0 {
				out["percent"] = d.Percent
			}
		}
	case strings.HasPrefix(e.Type, "tenant."):
		var d sdk.TenantEventData
		if json.Unmarshal(e.Data, &d) == nil && d.Tenant.ID != "" {
			out["tenant_slug"], out["plan"], out["status"] = d.Tenant.Slug, d.Tenant.Plan, string(d.Tenant.Status)
			if d.Previous != nil && d.Previous.Plan != d.Tenant.Plan {
				out["previous_plan"] = d.Previous.Plan
			}
		}
	case strings.HasPrefix(e.Type, "plan."):
		var d sdk.PlanEventData
		if json.Unmarshal(e.Data, &d) == nil {
			out["plan"] = d.Plan.ID
		}
	}
	return out
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

// Reconfigure applies a new write key, api_url, timeout, event_names,
// user_actor_prefixes and include_labels without a restart; messages still
// queued are sent with the new settings. The subscriptions (group_events,
// identify_users, link_members, track_events) and batch_size are fixed at
// startup.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{log: p.log, now: p.now, batch: p.batch}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if err := n.applyConfig(); err != nil {
		return err
	}
	if !slices.Equal(n.groupEvents, p.groupEvents) || !slices.Equal(n.cfg.TrackEvents, p.cfg.TrackEvents) ||
		enabled(n.cfg.IdentifyUsers) != enabled(p.cfg.IdentifyUsers) || enabled(n.cfg.LinkMembers) != enabled(p.cfg.LinkMembers) {
		return errors.New("group_events, track_events, identify_users and link_members take effect after a restart")
	}
	if n.cfg.BatchSize != p.cfg.BatchSize {
		return errors.New("batch_size takes effect after a restart")
	}
	p.next.Store(n)
	return nil
}
