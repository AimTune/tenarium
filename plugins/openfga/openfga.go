// Package openfga is an sdk.Authorizer backed by an OpenFGA server
// (https://openfga.dev). Each API request is mapped to a relationship check
//
//	user     = "{principal.kind}:{principal.subject}"   e.g. user:4f1c…
//	relation = relations[action] or "can_{action.verb}" e.g. can_update
//	object   = "{resource.type}:{resource.id_or_tenant}" e.g. tenant:acme-id
//
// and sent to POST /stores/{store_id}/check. Allowed checks return Allow;
// other outcomes abstain unless configured to deny, so OpenFGA can be
// combined with rbac or other authorizers. The core's tenant-scope rule is
// applied before any authorizer and cannot be relaxed by this plugin.
//
// Optionally, a subscription keeps tenant hierarchy and membership tuples
// in sync with Tenarium events, and the tenant ancestry can be sent as
// contextual tuples instead.
package openfga

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
	"sync"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("openfga", func() sdk.Plugin { return &Plugin{} })
}

// Config configures the plugin. Templates use {placeholders}; see README.md.
type Config struct {
	// URL of the OpenFGA HTTP API, e.g. http://openfga:8080.
	URL     string `json:"url"`
	StoreID string `json:"store_id"`
	// AuthorizationModelID pins checks and writes to one model; empty uses
	// the store's latest model.
	AuthorizationModelID string `json:"authorization_model_id"`
	// APIToken is sent as a bearer token (OpenFGA preshared key auth).
	APIToken string `json:"api_token"`

	User         string            `json:"user"`
	Relation     string            `json:"relation"`
	Relations    map[string]string `json:"relations"`
	Object       string            `json:"object"`
	Objects      map[string]string `json:"objects"`
	GlobalObject string            `json:"global_object"`

	// Consistency is "minimize_latency" or "higher_consistency"; empty
	// leaves the server default.
	Consistency string `json:"consistency"`
	// OnNotAllowed is the decision when OpenFGA answers allowed=false:
	// "abstain" (default) or "deny".
	OnNotAllowed string `json:"on_not_allowed"`
	// FailMode is the decision when OpenFGA cannot be asked (unreachable,
	// timeout, bad response): "abstain" (default) or "deny".
	FailMode  string `json:"fail_mode"`
	Timeout   string `json:"timeout"`
	CacheTTL  string `json:"cache_ttl"`
	CacheSize int    `json:"cache_size"`

	// TenantType and ParentRelation name the tenant object type and the
	// relation linking a tenant to its parent (tenant:child#parent@tenant:parent).
	TenantType     string `json:"tenant_type"`
	ParentRelation string `json:"parent_relation"`
	// ContextualParents sends the resource tenant's ancestry as contextual
	// tuples, so hierarchy works without syncing it.
	ContextualParents bool `json:"contextual_parents"`
	// PrincipalTenantRelation, when set, sends the contextual tuple
	// (user, relation, tenant:<principal tenant>) for tenant-scoped callers.
	PrincipalTenantRelation string `json:"principal_tenant_relation"`

	Sync *SyncConfig `json:"sync"`
}

// SyncConfig controls the tuple-writing subscription.
type SyncConfig struct {
	// TenantParents writes tenant:<child>#parent@tenant:<parent> on
	// tenant.created and deletes it on tenant.deleted.
	TenantParents bool `json:"tenant_parents"`
	// Members writes tenant:<id>#<role>@<member_user> for active members.
	Members bool `json:"members"`
	// MemberUser is the user template for members.
	MemberUser string `json:"member_user"`
	// Roles maps membership roles to relations. Empty maps every role to
	// a relation of the same name; otherwise unmapped roles are skipped.
	Roles map[string]string `json:"roles"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "url": {"type": "string", "minLength": 1},
    "store_id": {"type": "string", "minLength": 1},
    "authorization_model_id": {"type": "string"},
    "api_token": {"type": "string"},
    "user": {"type": "string", "minLength": 1},
    "relation": {"type": "string", "minLength": 1},
    "relations": {"type": "object", "additionalProperties": {"type": "string"}},
    "object": {"type": "string", "minLength": 1},
    "objects": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}},
    "global_object": {"type": "string"},
    "consistency": {"enum": ["", "minimize_latency", "higher_consistency"]},
    "on_not_allowed": {"enum": ["abstain", "deny"]},
    "fail_mode": {"enum": ["abstain", "deny"]},
    "timeout": {"type": "string"},
    "cache_ttl": {"type": "string"},
    "cache_size": {"type": "integer", "minimum": 1},
    "tenant_type": {"type": "string", "minLength": 1},
    "parent_relation": {"type": "string", "minLength": 1},
    "contextual_parents": {"type": "boolean"},
    "principal_tenant_relation": {"type": "string"},
    "sync": {
      "type": "object",
      "properties": {
        "tenant_parents": {"type": "boolean"},
        "members": {"type": "boolean"},
        "member_user": {"type": "string", "minLength": 1},
        "roles": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}}
      },
      "additionalProperties": false
    }
  },
  "required": ["url", "store_id"],
  "additionalProperties": false
}`)

// maxDepth bounds tenant ancestry walks.
const maxDepth = 32

// Result is a decision with a human-readable reason.
type Result struct {
	Decision sdk.Decision
	Reason   string
}

type Plugin struct {
	cfg          Config
	name         string
	base         *url.URL
	timeout      time.Duration
	client       *http.Client
	mapper       *mapper
	memberUser   *template
	cache        *decisionCache
	host         sdk.Host
	log          *slog.Logger
	denyNotAllow bool
	denyOnError  bool

	parentMu sync.Mutex
	parents  map[string]string // tenant ID → parent ID; immutable in Tenarium

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
		ID:           "openfga",
		Name:         "OpenFGA",
		Version:      "0.1.0",
		Description:  "Authorizes API actions with OpenFGA relationship checks and keeps tenant tuples in sync.",
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
	p.host = r.Host()
	p.log = r.Logger()
	p.name = r.InstanceName()
	r.Authorizer(p)
	if types := p.syncTypes(); len(types) > 0 {
		r.Subscribe("tuples", sdk.EventFilter{Types: types}, p.syncEvent)
	}
	return nil
}

// syncTypes returns the event types the tuple subscription needs.
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

// Reconfigure applies the server, store, model, token, mapping templates,
// decision modes, timeout, cache and sync templates and roles without a
// restart. The decision and tenant caches start empty so no decision of the
// previous configuration is served. Which events are synced
// (sync.tenant_parents, sync.members) is fixed at startup.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{host: p.host, log: p.log, name: p.name}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if !slices.Equal(n.syncTypes(), p.syncTypes()) {
		return errors.New("sync.tenant_parents and sync.members take effect after a restart")
	}
	if err := n.setup(); err != nil {
		return err
	}
	p.next.Store(n)
	return nil
}

// setup applies defaults, validates p.cfg and builds the client, mapper and
// caches.
func (p *Plugin) setup() error {
	c := &p.cfg
	setDefault(&c.User, "{principal.kind}:{principal.subject}")
	setDefault(&c.Relation, "can_{action.verb}")
	setDefault(&c.Object, "{resource.type}:{resource.id_or_tenant}")
	setDefault(&c.OnNotAllowed, "abstain")
	setDefault(&c.FailMode, "abstain")
	setDefault(&c.Timeout, "2s")
	setDefault(&c.CacheTTL, "5s")
	setDefault(&c.TenantType, "tenant")
	setDefault(&c.ParentRelation, "parent")
	if c.CacheSize == 0 {
		c.CacheSize = 10000
	}
	if c.URL == "" || c.StoreID == "" {
		return errors.New("url and store_id are required")
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("url %q must be an absolute http(s) URL", c.URL)
	}
	p.base = u
	if err := oneOf("on_not_allowed", c.OnNotAllowed, "abstain", "deny"); err != nil {
		return err
	}
	if err := oneOf("fail_mode", c.FailMode, "abstain", "deny"); err != nil {
		return err
	}
	if err := oneOf("consistency", c.Consistency, "", "minimize_latency", "higher_consistency"); err != nil {
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
		setDefault(&c.Sync.MemberUser, "user:{member.user_id}")
		if p.memberUser, err = parseTemplate(c.Sync.MemberUser, memberVars); err != nil {
			return fmt.Errorf("sync.member_user: %w", err)
		}
		if err := checkTypedID(c.Sync.MemberUser); err != nil {
			return fmt.Errorf("sync.member_user: %w", err)
		}
	}
	p.denyNotAllow = c.OnNotAllowed == "deny"
	p.denyOnError = c.FailMode == "deny"
	p.cache = newDecisionCache(ttl, c.CacheSize)
	p.client = &http.Client{Timeout: p.timeout}
	p.parents = map[string]string{}
	return nil
}

func (p *Plugin) Name() string {
	if p.name == "" {
		return "openfga"
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
		p.log.Info("openfga denied", "action", action, "resource_type", res.Type, "resource_id", res.ID,
			"tenant_id", res.TenantID, "subject", subjectOf(pr), "reason", r.Reason)
	} else {
		p.log.Debug("openfga decision", "action", action, "decision", r.Decision, "reason", r.Reason)
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
	// Contextual tuples depend only on the principal's and the resource's
	// tenant, so both are part of the key.
	key := strings.Join([]string{c.user, c.relation, c.object, pr.TenantID, res.TenantID}, "\x00")
	allowed, hit := p.cache.get(key)
	if !hit {
		var ctxTuples []tupleKey
		if p.cfg.PrincipalTenantRelation != "" && pr.TenantID != "" {
			ctxTuples = append(ctxTuples, tupleKey{User: c.user, Relation: p.cfg.PrincipalTenantRelation, Object: p.tenantObject(pr.TenantID)})
		}
		if p.cfg.ContextualParents && res.TenantID != "" {
			chain, err := p.ancestry(ctx, res.TenantID)
			if err != nil {
				return p.failure("tenant ancestry", err)
			}
			ctxTuples = append(ctxTuples, chain...)
		}
		var err error
		allowed, err = p.check(ctx, c, ctxTuples)
		if err != nil {
			return p.failure("check", err)
		}
		p.cache.put(key, allowed)
	}
	desc := fmt.Sprintf("%s %s %s", c.user, c.relation, c.object)
	if allowed {
		return Result{sdk.Allow, "openfga: " + desc}
	}
	if p.denyNotAllow {
		return Result{sdk.Deny, "openfga: no relationship " + desc}
	}
	return Result{sdk.Abstain, "openfga: no relationship " + desc}
}

func (p *Plugin) failure(what string, err error) Result {
	p.log.Warn("openfga unavailable", "op", what, "fail_mode", p.cfg.FailMode, "err", err)
	if p.denyOnError {
		return Result{sdk.Deny, "openfga " + what + " failed (fail_mode deny): " + err.Error()}
	}
	return Result{sdk.Abstain, "openfga " + what + " failed: " + err.Error()}
}

func (p *Plugin) tenantObject(id string) string { return p.cfg.TenantType + ":" + id }

// ancestry returns parent tuples from tenantID up to its root.
func (p *Plugin) ancestry(ctx context.Context, tenantID string) ([]tupleKey, error) {
	var out []tupleKey
	id := tenantID
	for range maxDepth {
		parent, err := p.parentOf(ctx, id)
		if errors.Is(err, sdk.ErrNotFound) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if parent == "" {
			return out, nil
		}
		out = append(out, tupleKey{User: p.tenantObject(parent), Relation: p.cfg.ParentRelation, Object: p.tenantObject(id)})
		id = parent
	}
	return out, nil
}

func (p *Plugin) parentOf(ctx context.Context, id string) (string, error) {
	p.parentMu.Lock()
	parent, ok := p.parents[id]
	p.parentMu.Unlock()
	if ok {
		return parent, nil
	}
	t, err := p.host.GetTenant(ctx, id)
	if err != nil {
		return "", err
	}
	p.parentMu.Lock()
	if len(p.parents) >= 100000 {
		clear(p.parents)
	}
	p.parents[id] = t.ParentID
	p.parentMu.Unlock()
	return t.ParentID, nil
}

type tupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type checkRequest struct {
	TupleKey             tupleKey `json:"tuple_key"`
	ContextualTuples     *tuples  `json:"contextual_tuples,omitempty"`
	AuthorizationModelID string   `json:"authorization_model_id,omitempty"`
	Consistency          string   `json:"consistency,omitempty"`
}

type tuples struct {
	TupleKeys []tupleKey `json:"tuple_keys"`
}

func (p *Plugin) check(ctx context.Context, c check, ctxTuples []tupleKey) (bool, error) {
	req := checkRequest{
		TupleKey:             tupleKey{User: c.user, Relation: c.relation, Object: c.object},
		AuthorizationModelID: p.cfg.AuthorizationModelID,
	}
	if len(ctxTuples) > 0 {
		req.ContextualTuples = &tuples{TupleKeys: ctxTuples}
	}
	switch p.cfg.Consistency {
	case "minimize_latency":
		req.Consistency = "MINIMIZE_LATENCY"
	case "higher_consistency":
		req.Consistency = "HIGHER_CONSISTENCY"
	}
	var resp struct {
		Allowed *bool `json:"allowed"`
	}
	if err := p.do(ctx, http.MethodPost, "/stores/"+url.PathEscape(p.cfg.StoreID)+"/check", req, &resp); err != nil {
		return false, err
	}
	if resp.Allowed == nil {
		return false, errors.New("response has no allowed field")
	}
	return *resp.Allowed, nil
}

// apiError is an OpenFGA error response.
type apiError struct {
	Status  int
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *apiError) Error() string {
	return fmt.Sprintf("openfga: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

func (p *Plugin) do(ctx context.Context, method, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base.String()+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.APIToken)
	}
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
		return fmt.Errorf("openfga: decode response: %w", err)
	}
	return nil
}

// Health checks that the store is reachable.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	return p.do(ctx, http.MethodGet, "/stores/"+url.PathEscape(p.cfg.StoreID), nil, nil)
}

func subjectOf(pr *sdk.Principal) string {
	if pr == nil {
		return ""
	}
	return pr.Authenticator + ":" + pr.Subject
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
