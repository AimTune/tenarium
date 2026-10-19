// Package rabbitmqvhost provisions per-tenant isolation on RabbitMQ: one
// virtual host, one user and the user's permissions on that vhost per
// tenant, through the RabbitMQ Management HTTP API (no AMQP connection).
//
// The vhost and user names come from vhost_template and username_template
// (text/templates over sdk.Tenant, both default "tenant-{{.Slug}}"),
// sanitized to lowercase letters, digits, '.', '_' and '-', at most 64
// characters. Names that are too long are shortened and suffixed with a hash
// of the tenant ID, so two tenants never collide through truncation.
// Templates should only use immutable tenant fields (ID, Slug), since names
// are recomputed on deprovision.
//
// # Passwords
//
// Nothing secret is stored. The password of a tenant user is derived as
// base64url(HMAC-SHA256(password_secret, tenantID)) (see TenantPassword) and
// re-applied on every Provision, so rotating password_secret and
// reprovisioning rotates every tenant password. Applications that know the
// secret derive the password themselves; others fetch it from the
// credentials route.
//
// # Ownership
//
// The vhost carries the tag "tenarium-tenant-id:<id>" and the user the tag
// "tenarium-tenant-id:<id>". A vhost or user marked for another tenant, or
// an unmarked one that already exists, is never adopted by Provision nor
// touched by Deprovision.
//
// # Deprovisioning
//
// on_deprovision is delete (default: user and vhost, with all its queues
// and messages, are deleted), keep (nothing is touched) or retain (the user
// is deleted, so the tenant can no longer connect, but the vhost and its
// messages stay; its ownership tag is replaced by
// "tenarium-retained-tenant-id:<id>", so no tenant can adopt it).
package rabbitmqvhost

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("rabbitmq-tenant", func() sdk.Plugin { return &Plugin{} })
}

// Deprovision actions.
const (
	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"
	DeprovisionRetain = "retain"
)

// Default templates and permissions.
const (
	DefaultVhostTemplate    = "tenant-{{.Slug}}"
	DefaultUsernameTemplate = "tenant-{{.Slug}}"
	DefaultPermission       = ".*"
)

// Backend limit names supported in limits.
const (
	LimitMaxConnections = "max-connections"
	LimitMaxQueues      = "max-queues"
)

// Name length limits.
const (
	minNameLen = 1
	maxNameLen = 64
)

// minSecretLen is the minimum length of password_secret.
const minSecretLen = 16

// Ownership tags. Tags starting with tagReserved are managed by the plugin.
const (
	TagTenantID         = "tenarium-tenant-id:"
	TagRetainedTenantID = "tenarium-retained-tenant-id:"
	TagDeletedAt        = "tenarium-deleted-at:"
	tagReserved         = "tenarium-"
)

// Config is the plugin configuration.
type Config struct {
	// URL is the Management API base URL, e.g. http://rabbitmq:15672.
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	// Timeout per Management API request, e.g. "10s" (default).
	Timeout string `json:"timeout"`
	// TLSInsecureSkipVerify disables certificate verification (testing only).
	TLSInsecureSkipVerify bool `json:"tls_insecure_skip_verify"`
	// VhostTemplate and UsernameTemplate render names from an sdk.Tenant.
	VhostTemplate    string `json:"vhost_template"`
	UsernameTemplate string `json:"username_template"`
	// PasswordSecret is the HMAC key tenant passwords are derived from.
	PasswordSecret string `json:"password_secret"`
	// Permissions on the tenant vhost; each regex defaults to ".*".
	Permissions *Permissions `json:"permissions"`
	// UserTags are extra RabbitMQ user tags, e.g. "management".
	UserTags []string `json:"user_tags"`
	// DefaultQueueType of the vhost: classic, quorum or stream.
	DefaultQueueType string `json:"default_queue_type"`
	// Limits maps a vhost limit (max-connections, max-queues) to a Tenarium
	// entitlement limit name.
	Limits map[string]string `json:"limits"`
	// AMQPURL is the broker URL handed to tenants, e.g.
	// amqps://rabbit.example.com:5671; the vhost is appended as the path.
	AMQPURL string `json:"amqp_url"`
	// OnDeprovision is "delete" (default), "keep" or "retain".
	OnDeprovision string `json:"on_deprovision"`
}

// Permissions are RabbitMQ permission regexes. A nil field means ".*"; an
// empty string grants nothing.
type Permissions struct {
	Configure *string `json:"configure"`
	Write     *string `json:"write"`
	Read      *string `json:"read"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["url", "username", "password", "password_secret"],
  "additionalProperties": false,
  "properties": {
    "url": {"type": "string", "pattern": "^https?://"},
    "username": {"type": "string", "minLength": 1},
    "password": {"type": "string", "minLength": 1},
    "timeout": {"type": "string"},
    "tls_insecure_skip_verify": {"type": "boolean"},
    "vhost_template": {"type": "string", "minLength": 1},
    "username_template": {"type": "string", "minLength": 1},
    "password_secret": {"type": "string", "minLength": 16},
    "permissions": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "configure": {"type": "string"},
        "write": {"type": "string"},
        "read": {"type": "string"}
      }
    },
    "user_tags": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "default_queue_type": {"enum": ["classic", "quorum", "stream"]},
    "limits": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "max-connections": {"type": "string", "minLength": 1},
        "max-queues": {"type": "string", "minLength": 1}
      }
    },
    "amqp_url": {"type": "string", "pattern": "^amqps?://"},
    "on_deprovision": {"enum": ["delete", "keep", "retain"]}
  }
}`)

// Plugin is the rabbitmq-tenant plugin.
type Plugin struct {
	cfg   Config
	vhost *template.Template
	user  *template.Template
	perms permissionBody
	amqp  *url.URL // nil without amqp_url
	api   *client
	host  sdk.Host
	log   *slog.Logger
	now   func() time.Time
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "rabbitmq-tenant",
		Name:         "RabbitMQ Tenant Isolation",
		Version:      "0.1.0",
		Description:  "Provisions a RabbitMQ vhost, user and permissions per tenant via the Management HTTP API.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	timeout := 10 * time.Second
	if p.cfg.Timeout != "" {
		timeout, _ = time.ParseDuration(p.cfg.Timeout) // checked by validate
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if p.cfg.TLSInsecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in
	}
	p.api = &client{
		base: strings.TrimRight(p.cfg.URL, "/"),
		user: p.cfg.Username,
		pass: p.cfg.Password,
		http: &http.Client{Timeout: timeout, Transport: tr},
	}
	p.host = r.Host()
	p.log = r.Logger()
	p.now = time.Now
	r.Provisioner(p)
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
	r.Route("GET /tenants/{tenant}/credentials", http.HandlerFunc(p.serveCredentials))
	return nil
}

// validate checks and defaults the configuration and compiles templates.
func (p *Plugin) validate() error {
	c := &p.cfg
	if c.URL == "" {
		return errors.New("url is required")
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("url must be an http(s) URL of the management API, got %q", c.URL)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("url must not contain credentials, a query or a fragment, got %q", c.URL)
	}
	if c.Username == "" || c.Password == "" {
		return errors.New("username and password are required")
	}
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil {
			return fmt.Errorf("timeout: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("timeout must be positive, got %q", c.Timeout)
		}
	}
	if c.PasswordSecret == "" {
		return errors.New("password_secret is required")
	}
	if len(c.PasswordSecret) < minSecretLen {
		return fmt.Errorf("password_secret must be at least %d characters", minSecretLen)
	}
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDelete
	case DeprovisionDelete, DeprovisionKeep, DeprovisionRetain:
	default:
		return fmt.Errorf("on_deprovision must be delete, keep or retain, got %q", c.OnDeprovision)
	}
	switch c.DefaultQueueType {
	case "", "classic", "quorum", "stream":
	default:
		return fmt.Errorf("default_queue_type must be classic, quorum or stream, got %q", c.DefaultQueueType)
	}
	for _, tag := range c.UserTags {
		switch {
		case tag == "" || strings.ContainsAny(tag, ", \t\r\n"):
			return fmt.Errorf("user_tags: invalid tag %q (no commas or whitespace)", tag)
		case strings.HasPrefix(tag, tagReserved):
			return fmt.Errorf("user_tags: tags starting with %q are reserved", tagReserved)
		case tag == "administrator" || tag == "monitoring":
			// Both see every vhost, which would break tenant isolation.
			return fmt.Errorf("user_tags: %q would give tenant users access beyond their vhost", tag)
		}
	}
	for name, limit := range c.Limits {
		if name != LimitMaxConnections && name != LimitMaxQueues {
			return fmt.Errorf("limits: unknown vhost limit %q (supported: %s, %s)", name, LimitMaxConnections, LimitMaxQueues)
		}
		if limit == "" {
			return fmt.Errorf("limits.%s: entitlement limit name must not be empty", name)
		}
	}
	if c.AMQPURL != "" {
		a, err := url.Parse(c.AMQPURL)
		if err != nil || (a.Scheme != "amqp" && a.Scheme != "amqps") || a.Host == "" {
			return fmt.Errorf("amqp_url must be an amqp(s)://host[:port] URL, got %q", c.AMQPURL)
		}
		if a.User != nil || (a.Path != "" && a.Path != "/") || a.RawQuery != "" || a.Fragment != "" {
			return fmt.Errorf("amqp_url must not contain credentials, a path, a query or a fragment, got %q (the vhost is appended)", c.AMQPURL)
		}
		a.Path = ""
		p.amqp = a
	}
	if c.VhostTemplate == "" {
		c.VhostTemplate = DefaultVhostTemplate
	}
	if c.UsernameTemplate == "" {
		c.UsernameTemplate = DefaultUsernameTemplate
	}
	if p.vhost, err = parseNameTemplate("vhost_template", c.VhostTemplate); err != nil {
		return err
	}
	if p.user, err = parseNameTemplate("username_template", c.UsernameTemplate); err != nil {
		return err
	}
	if user, _ := renderName(p.user, sample1); user == c.Username {
		return fmt.Errorf("username_template renders the admin user name %q", user)
	}
	p.perms = permissionBody{Configure: DefaultPermission, Write: DefaultPermission, Read: DefaultPermission}
	if c.Permissions != nil {
		for _, f := range []struct {
			v   *string
			dst *string
		}{{c.Permissions.Configure, &p.perms.Configure}, {c.Permissions.Write, &p.perms.Write}, {c.Permissions.Read, &p.perms.Read}} {
			if f.v != nil {
				*f.dst = *f.v
			}
		}
	}
	return nil
}

// Sample tenants used to validate templates at Init.
var (
	sample1 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000001", Slug: "example-one", Name: "Example One"}
	sample2 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000002", Slug: "example-two", Name: "Example Two"}
)

// parseNameTemplate compiles a name template and checks that it renders
// distinct, valid names for two sample tenants.
func parseNameTemplate(field, s string) (*template.Template, error) {
	tmpl, err := template.New(field).Option("missingkey=error").Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	n1, err := renderName(tmpl, sample1)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	n2, err := renderName(tmpl, sample2)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if n1 == n2 {
		return nil, fmt.Errorf("%s must depend on the tenant (e.g. {{.Slug}} or {{.ID}})", field)
	}
	return tmpl, nil
}

func renderName(tmpl *template.Template, t sdk.Tenant) (string, error) {
	var b strings.Builder
	if err := tmpl.Execute(&b, t); err != nil {
		return "", err
	}
	name := sanitize(b.String())
	if name == "" {
		return "", fmt.Errorf("renders an empty name for tenant %q", t.ID)
	}
	if len(name) < minNameLen || len(name) > maxNameLen {
		// Truncating alone could map two tenants to one name; a hash of the
		// tenant ID keeps shortened names distinct.
		sum := sha256.Sum256([]byte(t.ID))
		suffix := "-" + hex.EncodeToString(sum[:4])
		name = strings.TrimRight(name[:maxNameLen-len(suffix)], "-._") + suffix
	}
	return name, nil
}

// SanitizeName turns s into a vhost/user name candidate: lowercase, runs of
// characters other than [a-z0-9._-] replaced by a single "-", and leading
// and trailing separators trimmed. It does not enforce the length limit,
// which needs the tenant ID.
func SanitizeName(s string) string { return sanitize(s) }

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_':
			b.WriteRune(r)
		case !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-._")
}

// TenantPassword derives the RabbitMQ password of a tenant user: the
// unpadded base64url encoding of HMAC-SHA256(secret, tenantID), 43
// characters (256 bits). Applications that know the secret compute it the
// same way to connect as the tenant.
func TenantPassword(secret, tenantID string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(tenantID))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// target is what a tenant maps to in RabbitMQ.
type target struct {
	Vhost string
	User  string
}

func (p *Plugin) target(t sdk.Tenant) (target, error) {
	vhost, err := renderName(p.vhost, t)
	if err != nil {
		return target{}, fmt.Errorf("vhost_template: %w", err)
	}
	user, err := renderName(p.user, t)
	if err != nil {
		return target{}, fmt.Errorf("username_template: %w", err)
	}
	if user == p.cfg.Username {
		return target{}, fmt.Errorf("username_template renders the admin user name %q", user)
	}
	return target{Vhost: vhost, User: user}, nil
}

// amqpURL returns the tenant's AMQP URL, with credentials if user is set,
// or "" without amqp_url.
func (p *Plugin) amqpURL(vhost string, user *url.Userinfo) string {
	if p.amqp == nil {
		return ""
	}
	u := *p.amqp
	u.User = user
	u.Path = "/" + vhost
	u.RawPath = "/" + url.PathEscape(vhost)
	return u.String()
}

// TenantInfo is the response of GET /tenants/{tenant}.
type TenantInfo struct {
	Vhost    string `json:"vhost"`
	Username string `json:"username"`
	AMQPURL  string `json:"amqp_url,omitempty"`
}

// Credentials is the response of GET /tenants/{tenant}/credentials.
type Credentials struct {
	Vhost    string `json:"vhost"`
	Username string `json:"username"`
	Password string `json:"password"`
	// URI is amqp_url with credentials and vhost (only with amqp_url).
	URI string `json:"uri,omitempty"`
}

// lookup resolves the route's tenant and checks read access, answering
// "not found" rather than "forbidden" so callers cannot probe other tenants'
// slugs.
func (p *Plugin) lookup(w http.ResponseWriter, r *http.Request) (sdk.Tenant, target, bool) {
	t, err := p.host.GetTenant(r.Context(), r.PathValue("tenant"))
	if errors.Is(err, sdk.ErrNotFound) {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return t, target{}, false
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return t, target{}, false
	}
	res := sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
	if err := p.host.Authorize(r.Context(), sdk.ActionTenantsRead, res); err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return t, target{}, false
	}
	tg, err := p.target(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return t, target{}, false
	}
	return t, tg, true
}

func (p *Plugin) serveTenant(w http.ResponseWriter, r *http.Request) {
	_, tg, ok := p.lookup(w, r)
	if !ok {
		return
	}
	writeJSON(w, TenantInfo{Vhost: tg.Vhost, Username: tg.User, AMQPURL: p.amqpURL(tg.Vhost, nil)})
}

// serveCredentials returns the tenant's password. Reading secrets needs
// tenants:update on top of tenants:read.
func (p *Plugin) serveCredentials(w http.ResponseWriter, r *http.Request) {
	t, tg, ok := p.lookup(w, r)
	if !ok {
		return
	}
	res := sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
	if err := p.host.Authorize(r.Context(), sdk.ActionTenantsUpdate, res); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	pw := TenantPassword(p.cfg.PasswordSecret, t.ID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, Credentials{
		Vhost: tg.Vhost, Username: tg.User, Password: pw,
		URI: p.amqpURL(tg.Vhost, url.UserPassword(tg.User, pw)),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Health calls GET /api/overview.
func (p *Plugin) Health(ctx context.Context) error {
	return p.api.do(ctx, http.MethodGet, "/api/overview", nil, nil)
}

// Stop releases idle HTTP connections.
func (p *Plugin) Stop(context.Context) error {
	if p.api != nil {
		p.api.http.CloseIdleConnections()
	}
	return nil
}

// sortedKeys returns the keys of m in order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
