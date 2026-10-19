// Package spicedb is an sdk.Authorizer backed by SpiceDB
// (https://authzed.com/spicedb) through its HTTP API. Each API request is
// mapped to a permission check
//
//	subject    = "{principal.kind}:{principal.subject}"    e.g. user:ann
//	permission = permissions[action] or "can_{action.verb}" e.g. can_update
//	resource   = "{resource.type}:{resource.id_or_tenant}" e.g. tenant:acme-id
//
// and sent to POST /v1/permissions/check with the preshared key. A granted
// permission returns Allow; other outcomes abstain unless configured to
// deny. The core's tenant-scope rule is applied before any authorizer and
// cannot be relaxed by this plugin.
//
// Optionally, a subscription writes tenant hierarchy and membership
// relationships (POST /v1/relationships/write) from Tenarium events.
package spicedb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("spicedb", func() sdk.Plugin { return &Plugin{} })
}

// Config configures the plugin. Templates use {placeholders}; see README.md.
type Config struct {
	// URL of the SpiceDB HTTP gateway, e.g. http://spicedb:8443.
	URL string `json:"url"`
	// Token is the preshared key, sent as a bearer token.
	Token string `json:"token"`

	Subject        string            `json:"subject"`
	Permission     string            `json:"permission"`
	Permissions    map[string]string `json:"permissions"`
	Resource       string            `json:"resource"`
	Resources      map[string]string `json:"resources"`
	GlobalResource string            `json:"global_resource"`

	// Consistency is "minimize_latency" (default), "fully_consistent" or
	// "at_least_as_fresh" (as fresh as this instance's last write).
	Consistency string `json:"consistency"`
	// OnNotAllowed is the decision when the permission is not granted
	// (including conditional results): "abstain" (default) or "deny".
	OnNotAllowed string `json:"on_not_allowed"`
	// FailMode is the decision when SpiceDB cannot be asked: "abstain"
	// (default) or "deny".
	FailMode  string `json:"fail_mode"`
	Timeout   string `json:"timeout"`
	CacheTTL  string `json:"cache_ttl"`
	CacheSize int    `json:"cache_size"`

	// TenantType and ParentRelation name the tenant definition and its
	// parent relation (tenant:child#parent@tenant:parent).
	TenantType     string `json:"tenant_type"`
	ParentRelation string `json:"parent_relation"`

	Sync *SyncConfig `json:"sync"`
}

// SyncConfig controls the relationship-writing subscription.
type SyncConfig struct {
	TenantParents bool `json:"tenant_parents"`
	Members       bool `json:"members"`
	// MemberSubject is the subject template for members.
	MemberSubject string `json:"member_subject"`
	// Roles maps membership roles to relations. Empty maps every role to a
	// relation of the same name; otherwise unmapped roles are skipped.
	Roles map[string]string `json:"roles"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "url": {"type": "string", "minLength": 1},
    "token": {"type": "string", "minLength": 1},
    "subject": {"type": "string", "minLength": 1},
    "permission": {"type": "string", "minLength": 1},
    "permissions": {"type": "object", "additionalProperties": {"type": "string"}},
    "resource": {"type": "string", "minLength": 1},
    "resources": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}},
    "global_resource": {"type": "string"},
    "consistency": {"enum": ["minimize_latency", "fully_consistent", "at_least_as_fresh"]},
    "on_not_allowed": {"enum": ["abstain", "deny"]},
    "fail_mode": {"enum": ["abstain", "deny"]},
    "timeout": {"type": "string"},
    "cache_ttl": {"type": "string"},
    "cache_size": {"type": "integer", "minimum": 1},
    "tenant_type": {"type": "string", "minLength": 1},
    "parent_relation": {"type": "string", "minLength": 1},
    "sync": {
      "type": "object",
      "properties": {
        "tenant_parents": {"type": "boolean"},
        "members": {"type": "boolean"},
        "member_subject": {"type": "string", "minLength": 1},
        "roles": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}}
      },
      "additionalProperties": false
    }
  },
  "required": ["url", "token"],
  "additionalProperties": false
}`)

// Result is a decision with a human-readable reason.
type Result struct {
	Decision sdk.Decision
	Reason   string
}

type Plugin struct {
	cfg           Config
	name          string
	base          string
	timeout       time.Duration
	client        *http.Client
	mapper        *mapper
	memberSubject *template
	cache         *decisionCache
	log           *slog.Logger
	denyNotAllow  bool
	denyOnError   bool
	// lastWrite is the ZedToken of this instance's latest write, used by
	// at_least_as_fresh consistency.
	lastWrite atomic.Pointer[string]
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var (
	_ sdk.Authorizer    = (*Plugin)(nil)
	_ sdk.HealthChecker = (*Plugin)(nil)
	_ sdk.Reconfigurer  = (*Plugin)(nil)
)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "spicedb",
		Name:         "SpiceDB",
		Version:      "0.1.0",
		Description:  "Authorizes API actions with SpiceDB permission checks and keeps tenant relationships in sync.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.setup(); err != nil {
		return err
	}
	p.log = r.Logger()
	p.name = r.InstanceName()
	r.Authorizer(p)
	if types := p.syncTypes(); len(types) > 0 {
		r.Subscribe("relationships", sdk.EventFilter{Types: types}, p.syncEvent)
	}
	return nil
}

// syncTypes returns the event types the relationship subscription needs.
func (p *Plugin) syncTypes() []string {
	s := p.cfg.Sync
	if s == nil {
		return nil
	}
	var types []string
	if s.TenantParents {
		types = append(types, sdk.EventTenantCreated, sdk.EventTenantDeleted)
	}
	if s.Members {
		types = append(types, sdk.EventMemberAdded, sdk.EventMemberUpdated, sdk.EventMemberRemoved)
	}
	return types
}

// Reconfigure applies the URL, token, mapping templates, consistency,
// decision modes, timeout, cache and sync templates and roles without a
// restart. The decision cache starts empty so no decision of the previous
// configuration is served; the last write's ZedToken is kept while the URL
// stays the same. Which events are synced (sync.tenant_parents,
// sync.members) is fixed at startup.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{log: p.log, name: p.name}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if !slices.Equal(n.syncTypes(), p.syncTypes()) {
		return errors.New("sync.tenant_parents and sync.members take effect after a restart")
	}
	if err := n.setup(); err != nil {
		return err
	}
	cur := p
	if c := p.next.Load(); c != nil {
		cur = c
	}
	if n.base == cur.base {
		n.lastWrite.Store(cur.lastWrite.Load())
	}
	p.next.Store(n)
	return nil
}

// setup applies defaults, validates p.cfg and builds the client, mapper and
// cache.
func (p *Plugin) setup() error {
	c := &p.cfg
	setDefault(&c.Subject, "{principal.kind}:{principal.subject}")
	setDefault(&c.Permission, "can_{action.verb}")
	setDefault(&c.Resource, "{resource.type}:{resource.id_or_tenant}")
	setDefault(&c.Consistency, "minimize_latency")
	setDefault(&c.OnNotAllowed, "abstain")
	setDefault(&c.FailMode, "abstain")
	setDefault(&c.Timeout, "2s")
	setDefault(&c.CacheTTL, "5s")
	setDefault(&c.TenantType, "tenant")
	setDefault(&c.ParentRelation, "parent")
	if c.CacheSize == 0 {
		c.CacheSize = 10000
	}
	if c.URL == "" || c.Token == "" {
		return errors.New("url and token are required")
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("url %q must be an absolute http(s) URL", c.URL)
	}
	p.base = u.String()
	if err := oneOf("on_not_allowed", c.OnNotAllowed, "abstain", "deny"); err != nil {
		return err
	}
	if err := oneOf("fail_mode", c.FailMode, "abstain", "deny"); err != nil {
		return err
	}
	if err := oneOf("consistency", c.Consistency, "minimize_latency", "fully_consistent", "at_least_as_fresh"); err != nil {
		return err
	}
	if p.timeout, err = positiveDuration("timeout", c.Timeout); err != nil {
		return err
	}
	ttl, err := time.ParseDuration(c.CacheTTL)
	if err != nil || ttl < 0 {
		return fmt.Errorf("cache_ttl %q: must be a non-negative duration", c.CacheTTL)
	}
	if c.CacheSize < 1 {
		return errors.New("cache_size must be positive")
	}
	if p.mapper, err = newMapper(*c); err != nil {
		return err
	}
	if c.Sync != nil {
		setDefault(&c.Sync.MemberSubject, "user:{member.user_id}")
		if p.memberSubject, err = parseTemplate(c.Sync.MemberSubject, memberVars); err != nil {
			return fmt.Errorf("sync.member_subject: %w", err)
		}
		if err := checkTypedID(c.Sync.MemberSubject); err != nil {
			return fmt.Errorf("sync.member_subject: %w", err)
		}
	}
	p.denyNotAllow = c.OnNotAllowed == "deny"
	p.denyOnError = c.FailMode == "deny"
	p.cache = newDecisionCache(ttl, c.CacheSize)
	p.client = &http.Client{Timeout: p.timeout}
	return nil
}

func (p *Plugin) Name() string {
	if p.name == "" {
		return "spicedb"
	}
	return p.name
}

// Authorize implements sdk.Authorizer. It never returns an error: failures
// become the configured fail_mode decision, and denials are logged with
// their reason.
func (p *Plugin) Authorize(ctx context.Context, pr *sdk.Principal, action sdk.Action, res sdk.Resource) (sdk.Decision, error) {
	if n := p.next.Load(); n != nil {
		return n.Authorize(ctx, pr, action, res)
	}
	r := p.Check(ctx, pr, action, res)
	if r.Decision == sdk.Deny {
		subject := ""
		if pr != nil {
			subject = pr.Authenticator + ":" + pr.Subject
		}
		p.log.Info("spicedb denied", "action", action, "resource_type", res.Type, "resource_id", res.ID,
			"tenant_id", res.TenantID, "subject", subject, "reason", r.Reason)
	} else {
		p.log.Debug("spicedb decision", "action", action, "decision", r.Decision, "reason", r.Reason)
	}
	return r.Decision, nil
}

// Check returns the decision for a request with its reason.
func (p *Plugin) Check(ctx context.Context, pr *sdk.Principal, action sdk.Action, res sdk.Resource) Result {
	if n := p.next.Load(); n != nil {
		return n.Check(ctx, pr, action, res)
	}
	if pr == nil {
		return Result{sdk.Abstain, "no principal"}
	}
	c, reason, ok := p.mapper.resolve(pr, action, res)
	if !ok {
		return Result{sdk.Abstain, reason}
	}
	subject, err := parseSubject(c.user)
	if err != nil {
		return Result{sdk.Abstain, "subject: " + err.Error()}
	}
	resource, err := parseObject(c.object)
	if err != nil {
		return Result{sdk.Abstain, "resource: " + err.Error()}
	}
	key := c.user + "\x00" + c.relation + "\x00" + c.object
	allowed, hit := p.cache.get(key)
	if !hit {
		allowed, err = p.check(ctx, subject, c.relation, resource)
		if err != nil {
			return p.failure("check", err)
		}
		p.cache.put(key, allowed)
	}
	desc := fmt.Sprintf("%s#%s@%s", c.object, c.relation, c.user)
	if allowed {
		return Result{sdk.Allow, "spicedb: " + desc}
	}
	if p.denyNotAllow {
		return Result{sdk.Deny, "spicedb: no permission " + desc}
	}
	return Result{sdk.Abstain, "spicedb: no permission " + desc}
}

func (p *Plugin) failure(what string, err error) Result {
	p.log.Warn("spicedb unavailable", "op", what, "fail_mode", p.cfg.FailMode, "err", err)
	if p.denyOnError {
		return Result{sdk.Deny, "spicedb " + what + " failed (fail_mode deny): " + err.Error()}
	}
	return Result{sdk.Abstain, "spicedb " + what + " failed: " + err.Error()}
}

type objectRef struct {
	ObjectType string `json:"objectType"`
	ObjectID   string `json:"objectId"`
}

type subjectRef struct {
	Object           objectRef `json:"object"`
	OptionalRelation string    `json:"optionalRelation,omitempty"`
}

func parseObject(s string) (objectRef, error) {
	typ, id, ok := strings.Cut(s, ":")
	if !ok || typ == "" || id == "" {
		return objectRef{}, fmt.Errorf("%q is not type:id", s)
	}
	return objectRef{ObjectType: typ, ObjectID: id}, nil
}

// parseSubject accepts "type:id" or "type:id#relation".
func parseSubject(s string) (subjectRef, error) {
	obj, rel, _ := strings.Cut(s, "#")
	o, err := parseObject(obj)
	if err != nil {
		return subjectRef{}, err
	}
	return subjectRef{Object: o, OptionalRelation: rel}, nil
}

type zedToken struct {
	Token string `json:"token"`
}

func (p *Plugin) consistency() map[string]any {
	switch p.cfg.Consistency {
	case "fully_consistent":
		return map[string]any{"fullyConsistent": true}
	case "at_least_as_fresh":
		if t := p.lastWrite.Load(); t != nil {
			return map[string]any{"atLeastAsFresh": zedToken{Token: *t}}
		}
	}
	return map[string]any{"minimizeLatency": true}
}

func (p *Plugin) check(ctx context.Context, subject subjectRef, permission string, resource objectRef) (bool, error) {
	req := map[string]any{
		"consistency": p.consistency(),
		"resource":    resource,
		"permission":  permission,
		"subject":     subject,
	}
	var resp struct {
		Permissionship string `json:"permissionship"`
	}
	if err := p.do(ctx, "/v1/permissions/check", req, &resp); err != nil {
		return false, err
	}
	switch resp.Permissionship {
	case "PERMISSIONSHIP_HAS_PERMISSION":
		return true, nil
	case "PERMISSIONSHIP_NO_PERMISSION", "PERMISSIONSHIP_CONDITIONAL_PERMISSION":
		// Conditional means caveat context is missing; Tenarium sends
		// none, so it is not a grant.
		return false, nil
	default:
		return false, fmt.Errorf("unexpected permissionship %q", resp.Permissionship)
	}
}

// apiError is a SpiceDB (gRPC gateway) error response.
type apiError struct {
	Status  int
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *apiError) Error() string {
	return fmt.Sprintf("spicedb: HTTP %d (code %d): %s", e.Status, e.Code, e.Message)
}

func (p *Plugin) do(ctx context.Context, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		e := &apiError{Status: resp.StatusCode}
		if json.Unmarshal(data, e) != nil || e.Message == "" {
			e.Message = strings.TrimSpace(string(data))
		}
		return e
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("spicedb: decode response: %w", err)
	}
	return nil
}

// Health checks that SpiceDB is reachable and accepts the preshared key.
// A missing schema (NOT_FOUND) still counts as healthy.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	err := p.do(ctx, "/v1/schema/read", struct{}{}, nil)
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
		return nil
	}
	return err
}

func setDefault(s *string, v string) {
	if *s == "" {
		*s = v
	}
}

func oneOf(field, v string, allowed ...string) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("%s %q must be one of %q", field, v, allowed)
}

func positiveDuration(field, v string) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s %q: must be a positive duration", field, v)
	}
	return d, nil
}
