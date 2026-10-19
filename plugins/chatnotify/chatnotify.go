// Package chatnotify posts messages about Tenarium events to Slack and
// Microsoft Teams.
//
// Each target is a Slack incoming webhook, a Slack bot token with a channel
// (chat.postMessage), a Teams incoming webhook or a Teams Workflows (Power
// Automate) URL. Teams targets receive an Adaptive Card. Every target has
// its own subscription ("notify-<name>"), event filter, message template and
// rate limit, so a slow or failing chat service only affects its own
// target.
//
// Messages are Go text/templates. Built-in templates cover the common
// tenant events; templates (by event type glob) and a per-target template
// override them. Template data is described in README.md.
//
// Rate limiting: each target is a token bucket (rate_limit.per_minute,
// rate_limit.burst). Notifications over the limit are dropped, not retried,
// so a burst of events (e.g. a bulk import) cannot flood a channel or fill
// the retry queue; the next message that is sent says how many were
// suppressed.
//
// Configuration:
//
//	plugins:
//	  - plugin: chat-notify
//	    config:
//	      events: ["tenant.created", "tenant.suspended", "tenant.provisioning_failed"]
//	      templates:
//	        "tenant.quota_exceeded": "{{.Tenant.Name}} hit its {{.Quota.Metric}} limit ({{.Quota.Limit}})"
//	      targets:
//	        - name: ops
//	          type: slack_webhook
//	          url: https://hooks.slack.com/services/T000/B000/XXXX
//	        - name: billing
//	          type: teams_workflow
//	          url: https://prod-00.westeurope.logic.azure.com/workflows/...
//	          events: ["tenant.suspended", "tenant.resumed"]
//	          rate_limit: {per_minute: 10, burst: 5}
package chatnotify

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
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

const version = "0.1.0"

func init() {
	sdk.Register("chat-notify", func() sdk.Plugin { return &Plugin{} })
}

// Target types.
const (
	TypeSlackWebhook  = "slack_webhook"
	TypeSlackBot      = "slack_bot"
	TypeTeamsWebhook  = "teams_webhook"
	TypeTeamsWorkflow = "teams_workflow"
)

// DefaultEvents are notified when neither the target nor the plugin
// configures events.
var DefaultEvents = []string{
	sdk.EventTenantCreated, sdk.EventTenantSuspended, sdk.EventTenantResumed, sdk.EventTenantDeleted,
	sdk.EventTenantProvisioningFailed, sdk.EventTenantDeprovisioningFailed, sdk.EventTenantQuotaExceeded,
	sdk.EventTenantUsageThreshold,
}

// Config is the plugin configuration.
type Config struct {
	// Targets are the chat destinations (at least one).
	Targets []TargetConfig `json:"targets"`
	// Events are glob patterns of event types to notify, for targets that
	// set none. Default: DefaultEvents.
	Events []string `json:"events"`
	// Templates maps event type globs to message templates. The first
	// matching pattern wins, exact types before globs.
	Templates map[string]string `json:"templates"`
	// Title is the template of the message title (Teams card heading,
	// bold first line in Slack). Default: "Tenarium: {{.Event.Type}}".
	Title string `json:"title"`
	// Timeout per request, e.g. "10s" (default).
	Timeout string `json:"timeout"`
}

// TargetConfig is one chat destination.
type TargetConfig struct {
	// Name identifies the target; the subscription is "notify-<name>".
	Name string `json:"name"`
	Type string `json:"type"`
	// URL is the incoming webhook or Workflows URL (not slack_bot).
	URL string `json:"url"`
	// Token and Channel are for slack_bot (xoxb-... token, channel ID or
	// name).
	Token   string `json:"token"`
	Channel string `json:"channel"`
	// APIBase overrides https://slack.com/api for slack_bot.
	APIBase string `json:"api_base"`
	// Events overrides the plugin's events for this target.
	Events []string `json:"events"`
	// Template overrides every message template for this target.
	Template string `json:"template"`
	// RateLimit bounds messages to this target.
	RateLimit *RateLimit `json:"rate_limit"`
}

// RateLimit is a token bucket.
type RateLimit struct {
	// PerMinute is the sustained rate (default 30).
	PerMinute int `json:"per_minute"`
	// Burst is the bucket size (default PerMinute).
	Burst int `json:"burst"`
}

const targetSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["name", "type"],
  "properties": {
    "name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,62}$"},
    "type": {"enum": ["slack_webhook", "slack_bot", "teams_webhook", "teams_workflow"]},
    "url": {"type": "string", "pattern": "^https?://"},
    "token": {"type": "string", "minLength": 1},
    "channel": {"type": "string", "minLength": 1},
    "api_base": {"type": "string", "pattern": "^https?://"},
    "events": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "template": {"type": "string", "minLength": 1},
    "rate_limit": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "per_minute": {"type": "integer", "minimum": 1},
        "burst": {"type": "integer", "minimum": 1}
      }
    }
  },
  "if": {"properties": {"type": {"const": "slack_bot"}}},
  "then": {"required": ["token", "channel"]},
  "else": {"required": ["url"]}
}`

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["targets"],
  "properties": {
    "targets": {"type": "array", "minItems": 1, "items": ` + targetSchema + `},
    "events": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "templates": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}},
    "title": {"type": "string", "minLength": 1},
    "timeout": {"type": "string"}
  }
}`)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Plugin is the chat notification plugin.
type Plugin struct {
	cfg       Config
	client    *http.Client
	log       *slog.Logger
	host      sdk.Host
	now       func() time.Time
	title     *template.Template
	templates []patternTemplate // configured, exact types first
	targets   []*target
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

type patternTemplate struct {
	pattern string
	tmpl    *template.Template
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "chat-notify",
		Name:         "Chat notifications",
		Version:      version,
		Description:  "Posts event notifications to Slack and Microsoft Teams.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	p.log = r.Logger()
	p.host = r.Host()
	if p.now == nil {
		p.now = time.Now
	}
	if err := p.applyConfig(); err != nil {
		return err
	}
	for _, t := range p.targets {
		r.Subscribe("notify-"+t.cfg.Name, sdk.EventFilter{Types: t.events}, t.notify)
	}
	return nil
}

func (p *Plugin) applyConfig() error {
	c := &p.cfg
	if len(c.Targets) == 0 {
		return errors.New("targets: at least one target is required")
	}
	timeout := 10 * time.Second
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
		timeout = d
	}
	p.client = &http.Client{Timeout: timeout}
	if err := validPatterns("events", c.Events); err != nil {
		return err
	}
	var err error
	if p.title, err = parseTemplate("title", cmp.Or(c.Title, "Tenarium: {{.Event.Type}}")); err != nil {
		return err
	}
	// Exact event types take precedence over globs; otherwise sorted for
	// a deterministic choice.
	var exact, globs []patternTemplate
	for pat, text := range c.Templates {
		if _, err := path.Match(pat, ""); err != nil || pat == "" {
			return fmt.Errorf("templates: invalid event pattern %q", pat)
		}
		t, err := parseTemplate("templates["+pat+"]", text)
		if err != nil {
			return err
		}
		if strings.ContainsAny(pat, `*?[\`) {
			globs = append(globs, patternTemplate{pat, t})
		} else {
			exact = append(exact, patternTemplate{pat, t})
		}
	}
	byPattern := func(a, b patternTemplate) int { return strings.Compare(a.pattern, b.pattern) }
	slices.SortFunc(exact, byPattern)
	slices.SortFunc(globs, byPattern)
	p.templates = slices.Concat(exact, globs)

	seen := map[string]bool{}
	for i, tc := range c.Targets {
		field := fmt.Sprintf("targets[%d]", i)
		t, err := p.newTarget(tc, field)
		if err != nil {
			return err
		}
		if seen[tc.Name] {
			return fmt.Errorf("%s: duplicate target name %q", field, tc.Name)
		}
		seen[tc.Name] = true
		p.targets = append(p.targets, t)
	}
	return nil
}

func validPatterns(field string, pats []string) error {
	for _, pat := range pats {
		if _, err := path.Match(pat, ""); err != nil || pat == "" {
			return fmt.Errorf("%s: invalid pattern %q", field, pat)
		}
	}
	return nil
}

func (p *Plugin) newTarget(tc TargetConfig, field string) (*target, error) {
	if !namePattern.MatchString(tc.Name) {
		return nil, fmt.Errorf("%s.name must match %s, got %q", field, namePattern, tc.Name)
	}
	field = "targets." + tc.Name
	switch tc.Type {
	case TypeSlackBot:
		if tc.Token == "" || tc.Channel == "" {
			return nil, fmt.Errorf("%s: slack_bot needs token and channel", field)
		}
		if tc.URL != "" {
			return nil, fmt.Errorf("%s: url does not apply to slack_bot (use api_base to override the API)", field)
		}
		base := cmp.Or(tc.APIBase, "https://slack.com/api")
		if err := checkURL(field+".api_base", base); err != nil {
			return nil, err
		}
		tc.APIBase = strings.TrimRight(base, "/")
	case TypeSlackWebhook, TypeTeamsWebhook, TypeTeamsWorkflow:
		if err := checkURL(field+".url", tc.URL); err != nil {
			return nil, err
		}
		if tc.Token != "" || tc.Channel != "" || tc.APIBase != "" {
			return nil, fmt.Errorf("%s: token, channel and api_base only apply to slack_bot", field)
		}
	default:
		return nil, fmt.Errorf("%s.type must be slack_webhook, slack_bot, teams_webhook or teams_workflow, got %q", field, tc.Type)
	}
	t := &target{p: p, cfg: tc, seen: newSeenSet(1000), drops: &dropCount{}}
	switch {
	case len(tc.Events) > 0:
		t.events = tc.Events
	case len(p.cfg.Events) > 0:
		t.events = p.cfg.Events
	default:
		t.events = DefaultEvents
	}
	if err := validPatterns(field+".events", t.events); err != nil {
		return nil, err
	}
	if tc.Template != "" {
		tmpl, err := parseTemplate(field+".template", tc.Template)
		if err != nil {
			return nil, err
		}
		t.template = tmpl
	}
	perMinute, burst := 30, 0
	if rl := tc.RateLimit; rl != nil {
		if rl.PerMinute < 0 || rl.Burst < 0 {
			return nil, fmt.Errorf("%s.rate_limit: values must be positive", field)
		}
		perMinute = cmp.Or(rl.PerMinute, perMinute)
		burst = rl.Burst
	}
	t.limiter = newBucket(perMinute, cmp.Or(burst, perMinute), p.now)
	return t, nil
}

func checkURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%s must be an absolute http(s) URL", field)
	}
	return nil
}

// Health calls auth.test for Slack bot targets, which checks the token.
// Webhook URLs offer no side-effect-free check, so they are not probed.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	var errs []error
	for _, t := range p.targets {
		if t.cfg.Type != TypeSlackBot {
			continue
		}
		if err := t.slackAPI(ctx, "auth.test", nil); err != nil {
			errs = append(errs, fmt.Errorf("target %s: %w", t.cfg.Name, err))
		}
	}
	return errors.Join(errs...)
}

// target returns the target with the given name, or nil.
func (p *Plugin) target(name string) *target {
	for _, t := range p.targets {
		if t.cfg.Name == name {
			return t
		}
	}
	return nil
}

// Reconfigure applies new URLs, tokens, channels, templates, the title,
// rate limits and the timeout without a restart. The set of target names
// and each target's events (including inherited plugin-level events) are
// fixed at startup. Duplicate suppression and the suppressed count carry
// over; a target keeps its rate limit state unless its rate_limit changes.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{now: p.now, log: p.log, host: p.host}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if err := n.applyConfig(); err != nil {
		return err
	}
	cur := p
	if c := p.next.Load(); c != nil {
		cur = c
	}
	if len(n.targets) != len(cur.targets) {
		return errors.New("adding or removing targets takes effect after a restart")
	}
	for _, t := range n.targets {
		old := cur.target(t.cfg.Name)
		if old == nil {
			return fmt.Errorf("target %q: adding or renaming targets takes effect after a restart", t.cfg.Name)
		}
		if !slices.Equal(t.events, old.events) {
			return fmt.Errorf("target %q: events take effect after a restart", t.cfg.Name)
		}
		t.seen, t.drops = old.seen, old.drops
		if sameRateLimit(t.cfg.RateLimit, old.cfg.RateLimit) {
			t.limiter = old.limiter
		}
	}
	p.next.Store(n)
	return nil
}

func sameRateLimit(a, b *RateLimit) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
