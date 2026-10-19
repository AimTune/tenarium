// Package opa is an sdk.Authorizer that asks an Open Policy Agent server
// (https://www.openpolicyagent.org) for decisions, through
// POST /v1/data/{path} with the input
//
//	{
//	  "principal": {...},                    // sdk.Principal
//	  "action": "tenants:update", "action_resource": "tenants", "action_verb": "update",
//	  "resource": {"type": "tenant", "id": "...", "tenant_id": "..."},
//	  "tenant": {...},                       // include_tenant: the resource's tenant
//	  "tenant_ancestors": ["parent-id", ...] // include_tenant: its ancestors, nearest first
//	}
//
// The policy result may be a boolean or an object {allow, deny, reason}.
// Policies are only evaluated by the server; this plugin embeds no OPA
// engine. The core's tenant-scope rule is applied before any authorizer and
// cannot be relaxed by a policy.
package opa

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
	sdk.Register("opa", func() sdk.Plugin { return &Plugin{} })
}

type Config struct {
	// URL of the OPA server, e.g. http://opa:8181.
	URL string `json:"url"`
	// Path of the decision document under /v1/data, e.g. "tenarium/authz"
	// or "tenarium/authz/allow" (dots are accepted as separators).
	Path string `json:"path"`
	// Token is sent as a bearer token (OPA --authentication=token).
	Token string `json:"token"`
	// IncludeTenant adds the resource's tenant and its ancestors to the
	// input, fetched from Tenarium.
	IncludeTenant bool `json:"include_tenant"`
	// OnNotAllowed is the decision for a false result or an object without
	// allow/deny: "abstain" (default) or "deny".
	OnNotAllowed string `json:"on_not_allowed"`
	// FailMode is the decision when OPA cannot be asked or answers with
	// something unusable: "abstain" (default) or "deny".
	FailMode  string `json:"fail_mode"`
	Timeout   string `json:"timeout"`
	CacheTTL  string `json:"cache_ttl"`
	CacheSize int    `json:"cache_size"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "url": {"type": "string", "minLength": 1},
    "path": {"type": "string", "minLength": 1},
    "token": {"type": "string"},
    "include_tenant": {"type": "boolean"},
    "on_not_allowed": {"enum": ["abstain", "deny"]},
    "fail_mode": {"enum": ["abstain", "deny"]},
    "timeout": {"type": "string"},
    "cache_ttl": {"type": "string"},
    "cache_size": {"type": "integer", "minimum": 1}
  },
  "required": ["url", "path"],
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
	endpoint     string
	base         string
	timeout      time.Duration
	client       *http.Client
	cache        *decisionCache
	host         sdk.Host
	log          *slog.Logger
	denyNotAllow bool
	denyOnError  bool
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
		ID:           "opa",
		Name:         "Open Policy Agent",
		Version:      "0.1.0",
		Description:  "Authorizes API actions by querying an OPA server.",
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
	return nil
}

// setup applies defaults, validates p.cfg and builds the client and cache.
func (p *Plugin) setup() error {
	c := &p.cfg
	setDefault(&c.OnNotAllowed, "abstain")
	setDefault(&c.FailMode, "abstain")
	setDefault(&c.Timeout, "2s")
	setDefault(&c.CacheTTL, "5s")
	if c.CacheSize == 0 {
		c.CacheSize = 10000
	}
	if c.URL == "" || c.Path == "" {
		return errors.New("url and path are required")
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("url %q must be an absolute http(s) URL", c.URL)
	}
	p.base = u.String()
	segs := strings.FieldsFunc(c.Path, func(r rune) bool { return r == '/' || r == '.' })
	if len(segs) == 0 {
		return fmt.Errorf("path %q is empty", c.Path)
	}
	for i, s := range segs {
		if strings.ContainsAny(s, "?#% ") {
			return fmt.Errorf("path %q: invalid segment %q", c.Path, s)
		}
		segs[i] = url.PathEscape(s)
	}
	p.endpoint = p.base + "/v1/data/" + strings.Join(segs, "/")
	if err := oneOf("on_not_allowed", c.OnNotAllowed, "abstain", "deny"); err != nil {
		return err
	}
	if err := oneOf("fail_mode", c.FailMode, "abstain", "deny"); err != nil {
		return err
	}
	if p.timeout, err = time.ParseDuration(c.Timeout); err != nil || p.timeout <= 0 {
		return fmt.Errorf("timeout %q: must be a positive duration", c.Timeout)
	}
	ttl, err := time.ParseDuration(c.CacheTTL)
	if err != nil || ttl < 0 {
		return fmt.Errorf("cache_ttl %q: must be a non-negative duration", c.CacheTTL)
	}
	if c.CacheSize < 1 {
		return errors.New("cache_size must be positive")
	}
	p.denyNotAllow = c.OnNotAllowed == "deny"
	p.denyOnError = c.FailMode == "deny"
	p.cache = newDecisionCache(ttl, c.CacheSize)
	p.client = &http.Client{Timeout: p.timeout}
	return nil
}

// Reconfigure applies every setting (server URL, decision path, token,
// decision modes, timeout and cache) without a restart, so a new policy
// endpoint is used immediately. The decision cache starts empty so no
// decision of the previous configuration is served; requests in flight
// finish with the old settings.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{host: p.host, log: p.log, name: p.name}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if err := n.setup(); err != nil {
		return err
	}
	p.next.Store(n)
	return nil
}

func (p *Plugin) Name() string {
	if p.name == "" {
		return "opa"
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
		p.log.Info("opa denied", "action", action, "resource_type", res.Type, "resource_id", res.ID,
			"tenant_id", res.TenantID, "subject", subject, "reason", r.Reason)
	} else {
		p.log.Debug("opa decision", "action", action, "decision", r.Decision, "reason", r.Reason)
	}
	return r.Decision, nil
}

// Input is the document sent to OPA as "input".
type Input struct {
	Principal       *sdk.Principal `json:"principal"`
	Action          sdk.Action     `json:"action"`
	ActionResource  string         `json:"action_resource"`
	ActionVerb      string         `json:"action_verb"`
	Resource        sdk.Resource   `json:"resource"`
	Tenant          *sdk.Tenant    `json:"tenant,omitempty"`
	TenantAncestors []string       `json:"tenant_ancestors,omitempty"`
}

// Check returns the decision for a request with its reason.
func (p *Plugin) Check(ctx context.Context, pr *sdk.Principal, action sdk.Action, res sdk.Resource) Result {
	if n := p.next.Load(); n != nil {
		return n.Check(ctx, pr, action, res)
	}
	if pr == nil {
		return Result{sdk.Abstain, "no principal"}
	}
	in := Input{Principal: pr, Action: action, Resource: res}
	in.ActionResource, in.ActionVerb, _ = strings.Cut(string(action), ":")
	// The key covers everything except tenant data, which may lag by at
	// most cache_ttl.
	keyBytes, err := json.Marshal(in)
	if err != nil {
		return p.failure("encode input", err)
	}
	key := string(keyBytes)
	if r, ok := p.cache.get(key); ok {
		return r
	}
	if p.cfg.IncludeTenant && res.TenantID != "" {
		if err := p.addTenant(ctx, &in, res.TenantID); err != nil {
			return p.failure("tenant lookup", err)
		}
	}
	raw, err := p.query(ctx, in)
	if err != nil {
		return p.failure("query", err)
	}
	r, err := p.interpret(raw)
	if err != nil {
		return p.failure("result", err)
	}
	p.cache.put(key, r)
	return r
}

func (p *Plugin) addTenant(ctx context.Context, in *Input, tenantID string) error {
	t, err := p.host.GetTenant(ctx, tenantID)
	if errors.Is(err, sdk.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	in.Tenant = &t
	parent := t.ParentID
	for range maxDepth {
		if parent == "" {
			break
		}
		in.TenantAncestors = append(in.TenantAncestors, parent)
		pt, err := p.host.GetTenant(ctx, parent)
		if errors.Is(err, sdk.ErrNotFound) {
			break
		}
		if err != nil {
			return err
		}
		parent = pt.ParentID
	}
	return nil
}

func (p *Plugin) failure(what string, err error) Result {
	p.log.Warn("opa unavailable", "op", what, "fail_mode", p.cfg.FailMode, "err", err)
	if p.denyOnError {
		return Result{sdk.Deny, "opa " + what + " failed (fail_mode deny): " + err.Error()}
	}
	return Result{sdk.Abstain, "opa " + what + " failed: " + err.Error()}
}

// query returns the raw "result" member, or nil if the document is
// undefined.
func (p *Plugin) query(ctx context.Context, in Input) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	b, err := json.Marshal(map[string]any{"input": in})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	p.authHeader(req)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &e) != nil || e.Message == "" {
			e.Message = strings.TrimSpace(string(data))
		}
		return nil, fmt.Errorf("opa: HTTP %d %s: %s", resp.StatusCode, e.Code, e.Message)
	}
	var out struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("opa: decode response: %w", err)
	}
	return out.Result, nil
}

func (p *Plugin) authHeader(req *http.Request) {
	if p.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	}
}

// interpret maps an OPA result to a decision:
//
//   - undefined: abstain (no policy answered);
//   - true: allow; false: on_not_allowed;
//   - {"deny": true | "msg" | ["msg", ...]} with a non-empty value: deny;
//   - {"allow": true}: allow; otherwise on_not_allowed.
//
// "reason" (string or list) is reported with the decision.
func (p *Plugin) interpret(raw json.RawMessage) (Result, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return Result{sdk.Abstain, "opa: decision is undefined"}, nil
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		if b {
			return Result{sdk.Allow, "opa: allowed"}, nil
		}
		return p.notAllowed("opa: policy returned false"), nil
	}
	var obj struct {
		Allow  *bool           `json:"allow"`
		Deny   json.RawMessage `json:"deny"`
		Reason json.RawMessage `json:"reason"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return Result{}, fmt.Errorf("result must be a boolean or an object, got %s", truncate(string(raw)))
	}
	reasons, err := messages(obj.Reason)
	if err != nil {
		return Result{}, fmt.Errorf("reason: %w", err)
	}
	denied, denyMsgs, err := denial(obj.Deny)
	if err != nil {
		return Result{}, fmt.Errorf("deny: %w", err)
	}
	if denied {
		all := slices.Concat(denyMsgs, reasons)
		if len(all) == 0 {
			all = []string{"denied by policy"}
		}
		return Result{sdk.Deny, "opa: " + strings.Join(all, "; ")}, nil
	}
	if obj.Allow != nil && *obj.Allow {
		return Result{sdk.Allow, "opa: allowed"}, nil
	}
	msg := "opa: not allowed"
	if len(reasons) > 0 {
		msg += ": " + strings.Join(reasons, "; ")
	}
	return p.notAllowed(msg), nil
}

func (p *Plugin) notAllowed(reason string) Result {
	if p.denyNotAllow {
		return Result{sdk.Deny, reason}
	}
	return Result{sdk.Abstain, reason}
}

// denial interprets "deny": a boolean, a message or a list (set) of
// messages; an empty list does not deny.
func denial(raw json.RawMessage) (bool, []string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return false, nil, nil
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, nil, nil
	}
	msgs, err := messages(raw)
	if err != nil {
		return false, nil, err
	}
	return len(msgs) > 0, msgs, nil
}

func messages(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s == "" {
			return nil, nil
		}
		return []string{s}, nil
	}
	var list []any
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("must be a string or a list, got %s", truncate(string(raw)))
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		} else {
			b, _ := json.Marshal(v)
			out = append(out, string(b))
		}
	}
	return out, nil
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// Health checks OPA's /health endpoint.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+"/health", nil)
	if err != nil {
		return err
	}
	p.authHeader(req)
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("opa: health: HTTP %d", resp.StatusCode)
	}
	return nil
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
