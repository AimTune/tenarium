// Package hubspot mirrors tenants into HubSpot CRM as companies and,
// optionally, tenant members as contacts associated with their tenant's
// company. It talks to the HubSpot CRM REST API directly with a private app
// access token.
//
// Tenants (subscription "sync"):
//
//   - tenant.created, tenant.updated, tenant.plan_changed, tenant.suspended
//     and tenant.resumed upsert the tenant's company. Companies are matched on
//     a unique-value company property holding the tenant ID
//     (tenant_id_property, default "tenarium_tenant_id"), so redelivered
//     events update the same company instead of creating duplicates. The
//     property must exist in HubSpot as a single-line text company property
//     with "unique values" enabled.
//   - tenant.deleted archives the company (on_delete "archive", the default)
//     or leaves it untouched ("keep").
//
// Members (subscription "members", unless sync_members is false):
//
//   - tenant.member_added and tenant.member_updated upsert a contact by
//     email, make sure the tenant's company exists and associate the contact
//     with it (default association).
//   - tenant.member_removed removes that association. The contact itself is
//     never deleted: it may belong to other companies or carry sales history.
//
// Company properties come from Go text/template templates executed against
// the tenant, contact properties from templates executed against the member
// and its tenant. Rendered values that are empty are not sent, so they never
// clear what HubSpot already holds.
//
// Configuration:
//
//	plugins:
//	  - plugin: hubspot
//	    config:
//	      access_token: pat-na1-...
//	      tenant_id_property: tenarium_tenant_id
//	      properties:
//	        name: "{{.Name}}"
//	        domain: '{{index .Labels "domain"}}'
//	        tenarium_plan: "{{.Plan}}"
//	        tenarium_status: "{{.Status}}"
//	      contact_properties:
//	        jobtitle: "{{.Member.Role}}"
//	      on_delete: archive
package hubspot

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
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
	sdk.Register("hubspot", func() sdk.Plugin { return &Plugin{} })
}

const (
	defaultAPIBase          = "https://api.hubapi.com"
	defaultTenantIDProperty = "tenarium_tenant_id"
	onDeleteArchive         = "archive"
	onDeleteKeep            = "keep"
)

var defaultProperties = map[string]string{"name": "{{.Name}}"}

// propertyName matches HubSpot internal property names.
var propertyName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Config is the plugin configuration.
type Config struct {
	// AccessToken is a private app access token with the
	// crm.objects.companies.read/write scopes (and
	// crm.objects.contacts.read/write when members are synced).
	AccessToken string `json:"access_token"`
	// APIBase defaults to https://api.hubapi.com.
	APIBase string `json:"api_base"`
	// Timeout per API request, e.g. "15s" (default).
	Timeout string `json:"timeout"`
	// TenantIDProperty is the unique-value company property holding the
	// tenant ID (default "tenarium_tenant_id"). It must exist in HubSpot.
	TenantIDProperty string `json:"tenant_id_property"`
	// Properties maps company properties to templates rendered against the
	// tenant. Default: {"name": "{{.Name}}"}. TenantIDProperty is always set.
	Properties map[string]string `json:"properties"`
	// SyncMembers mirrors members as associated contacts (default true).
	SyncMembers *bool `json:"sync_members"`
	// ContactProperties maps contact properties to templates rendered
	// against {Member, Tenant}. The email is always the contact's ID.
	ContactProperties map[string]string `json:"contact_properties"`
	// OnDelete is "archive" (default) or "keep".
	OnDelete string `json:"on_delete"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["access_token"],
  "additionalProperties": false,
  "properties": {
    "access_token": {"type": "string", "minLength": 1},
    "api_base": {"type": "string", "pattern": "^https?://"},
    "timeout": {"type": "string"},
    "tenant_id_property": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
    "properties": {
      "type": "object",
      "propertyNames": {"pattern": "^[a-z][a-z0-9_]*$"},
      "additionalProperties": {"type": "string", "minLength": 1}
    },
    "sync_members": {"type": "boolean"},
    "contact_properties": {
      "type": "object",
      "propertyNames": {"pattern": "^[a-z][a-z0-9_]*$"},
      "additionalProperties": {"type": "string", "minLength": 1}
    },
    "on_delete": {"enum": ["archive", "keep"]}
  }
}`)

// Plugin is the HubSpot CRM plugin.
type Plugin struct {
	cfg          Config
	base         string
	companyTmpl  map[string]*template.Template
	contactTmpl  map[string]*template.Template
	client       *http.Client
	host         sdk.Host
	log          *slog.Logger
	syncsMembers bool
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "hubspot",
		Name:         "HubSpot",
		Version:      version,
		Description:  "Mirrors tenants as HubSpot companies and members as associated contacts.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.applyConfig(); err != nil {
		return err
	}
	p.host = r.Host()
	p.log = r.Logger()
	r.Subscribe("sync", sdk.EventFilter{Types: []string{
		sdk.EventTenantCreated, sdk.EventTenantUpdated, sdk.EventTenantPlanChanged,
		sdk.EventTenantSuspended, sdk.EventTenantResumed, sdk.EventTenantDeleted,
	}}, p.sync)
	if p.syncsMembers {
		r.Subscribe("members", sdk.EventFilter{Types: []string{
			sdk.EventMemberAdded, sdk.EventMemberUpdated, sdk.EventMemberRemoved,
		}}, p.members)
	}
	return nil
}

// applyConfig validates the configuration and fills in defaults.
func (p *Plugin) applyConfig() error {
	c := &p.cfg
	if strings.TrimSpace(c.AccessToken) == "" {
		return errors.New("access_token is required")
	}
	c.APIBase = cmp.Or(c.APIBase, defaultAPIBase)
	u, err := url.Parse(c.APIBase)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("api_base must be an absolute http(s) URL, got %q", c.APIBase)
	}
	p.base = strings.TrimRight(c.APIBase, "/")

	timeout := 15 * time.Second
	if c.Timeout != "" {
		if timeout, err = time.ParseDuration(c.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
	}
	p.client = &http.Client{Timeout: timeout}

	c.TenantIDProperty = cmp.Or(c.TenantIDProperty, defaultTenantIDProperty)
	if !propertyName.MatchString(c.TenantIDProperty) {
		return fmt.Errorf("tenant_id_property: %q is not a HubSpot internal property name (lowercase letters, digits, underscores)", c.TenantIDProperty)
	}
	if c.Properties == nil {
		c.Properties = maps.Clone(defaultProperties)
	}
	if _, ok := c.Properties[c.TenantIDProperty]; ok {
		return fmt.Errorf("properties: %s is the tenant_id_property and is always set to the tenant ID", c.TenantIDProperty)
	}
	if p.companyTmpl, err = compileTemplates("properties", c.Properties); err != nil {
		return err
	}

	p.syncsMembers = c.SyncMembers == nil || *c.SyncMembers
	if _, ok := c.ContactProperties["email"]; ok {
		return errors.New("contact_properties: email is the contact's ID and is always the member's email")
	}
	if len(c.ContactProperties) > 0 && !p.syncsMembers {
		return errors.New("contact_properties requires sync_members")
	}
	if p.contactTmpl, err = compileTemplates("contact_properties", c.ContactProperties); err != nil {
		return err
	}

	c.OnDelete = cmp.Or(c.OnDelete, onDeleteArchive)
	if c.OnDelete != onDeleteArchive && c.OnDelete != onDeleteKeep {
		return fmt.Errorf("on_delete must be archive or keep, got %q", c.OnDelete)
	}
	return nil
}

// compileTemplates parses one template per property.
func compileTemplates(field string, m map[string]string) (map[string]*template.Template, error) {
	out := make(map[string]*template.Template, len(m))
	for _, name := range slices.Sorted(maps.Keys(m)) {
		if !propertyName.MatchString(name) {
			return nil, fmt.Errorf("%s: %q is not a HubSpot internal property name (lowercase letters, digits, underscores)", field, name)
		}
		src := m[name]
		if strings.TrimSpace(src) == "" {
			return nil, fmt.Errorf("%s.%s: template must not be empty", field, name)
		}
		t, err := template.New(name).Option("missingkey=error").Parse(src)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", field, name, err)
		}
		out[name] = t
	}
	return out, nil
}

// render executes every template against data. Empty results are left out,
// so they never clear values held by HubSpot.
func render(tmpls map[string]*template.Template, data any) (map[string]string, error) {
	out := make(map[string]string, len(tmpls))
	for name, t := range tmpls {
		var b strings.Builder
		if err := t.Execute(&b, data); err != nil {
			return nil, fmt.Errorf("render property %s: %w", name, err)
		}
		if v := strings.TrimSpace(b.String()); v != "" {
			out[name] = v
		}
	}
	return out, nil
}

// ContactData is the data contact_properties templates are executed against.
type ContactData struct {
	Member sdk.Member
	Tenant sdk.Tenant
}

// Health checks the token with a cheap authenticated request.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	return p.call(ctx, http.MethodGet, "/crm/v3/objects/companies", url.Values{"limit": {"1"}}, nil, nil)
}

// Reconfigure applies a new access token, API base, timeout, tenant ID
// property, property templates and on_delete without a restart (e.g. token
// rotation). sync_members decides the subscriptions and is fixed at startup.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{host: p.host, log: p.log}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if err := n.applyConfig(); err != nil {
		return err
	}
	if n.syncsMembers != p.syncsMembers {
		return errors.New("sync_members takes effect after a restart")
	}
	p.next.Store(n)
	return nil
}
