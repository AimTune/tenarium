// Package grafanatenant provisions a Grafana organization per tenant through
// the Grafana HTTP API.
//
// The organization name comes from name_template (a text/template over
// sdk.Tenant, default "tenant-{{.Slug}}"). Names are recomputed on
// deprovision, so templates should only use immutable tenant fields (ID,
// Slug). Rendered names are cleaned up (control characters and URL-unsafe
// characters replaced, whitespace collapsed) and names that are too long are
// shortened and suffixed with a hash of the tenant ID.
//
// # Ownership
//
// Grafana organizations have no labels, so ownership is recorded in the
// organization's address: address1 is "tenarium-tenant-id:<id>". An
// organization marked for another tenant is never adopted nor deleted. An
// unmarked organization is adopted only when it is empty: no members other
// than the plugin's own account, no dashboards or folders and no data
// sources (what an interrupted Provision leaves behind). The main
// organization (ID 1) is never touched.
//
// # Deprovisioning
//
// on_deprovision chooses what happens when a tenant is deleted:
//
//   - delete (default): the organization is deleted, with its dashboards,
//     data sources, alert rules and memberships. Grafana users themselves
//     are platform-wide and are not deleted.
//   - keep: nothing is touched; the marker stays, so a new tenant with the
//     same slug cannot adopt the organization.
//   - retain: the organization stays but ownership is released: address1
//     becomes "tenarium-deleted-tenant-id:<id>", address2
//     "tenarium-deleted-at:<RFC3339>", and the organization is renamed to
//     "<name>-deleted-<unix>" so the name is free for a new tenant.
package grafanatenant

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
	"unicode"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("grafana-tenant", func() sdk.Plugin { return &Plugin{} })
}

// Deprovision actions.
const (
	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"
	DeprovisionRetain = "retain"
)

// DefaultNameTemplate names tenant organizations when name_template is unset.
const DefaultNameTemplate = "tenant-{{.Slug}}"

// maxNameLen bounds organization names, leaving room for the
// "-deleted-<unix>" suffix of retained organizations (Grafana allows 190).
const maxNameLen = 100

// Ownership markers stored in the organization's address.
const (
	MarkerOwner     = "tenarium-tenant-id:"
	MarkerDeleted   = "tenarium-deleted-tenant-id:"
	MarkerDeletedAt = "tenarium-deleted-at:"
)

// Grafana organization roles.
const (
	RoleAdmin  = "Admin"
	RoleEditor = "Editor"
	RoleViewer = "Viewer"
	RoleNone   = "None"
)

// QuotaTargets are the Grafana organization quota targets that can be set.
var QuotaTargets = []string{"dashboard", "data_source", "org_user", "api_key", "alert_rule"}

// DefaultRoleMap maps Tenarium member roles to Grafana organization roles.
// role_map entries override or extend it.
var DefaultRoleMap = map[string]string{
	"owner":  RoleAdmin,
	"admin":  RoleAdmin,
	"member": RoleEditor,
}

type Config struct {
	// URL is the Grafana base URL, e.g. http://grafana:3000.
	URL string `json:"url"`
	// Username and Password authenticate as a Grafana server admin.
	Username string `json:"username"`
	Password string `json:"password"`
	// Token is sent as a bearer token instead of basic auth.
	Token string `json:"token"`
	// Timeout bounds each API call (Go duration, default 10s).
	Timeout string `json:"timeout"`
	// NameTemplate renders the organization name from an sdk.Tenant.
	NameTemplate string `json:"name_template"`
	// OnDeprovision is "delete" (default), "keep" or "retain".
	OnDeprovision string `json:"on_deprovision"`
	// RemoveCreator removes the plugin's account from each organization
	// once another admin exists.
	RemoveCreator bool `json:"remove_creator"`
	// SyncMembers mirrors tenant memberships as organization memberships.
	SyncMembers bool `json:"sync_members"`
	// RoleMap maps member roles to Grafana roles (merged over DefaultRoleMap).
	RoleMap map[string]string `json:"role_map"`
	// DefaultRole is used for member roles not in the role map (default Viewer).
	DefaultRole string `json:"default_role"`
	// CreateUsers creates missing Grafana users for members.
	CreateUsers bool `json:"create_users"`
	// Quota maps a quota target to the entitlement limit that sets it.
	Quota map[string]string `json:"quota"`
	// Datasources are created in every organization.
	Datasources []DatasourceConfig `json:"datasources"`
}

// DatasourceConfig describes a data source created in each organization.
// String values (url, database, user and the values of json_data and
// secure_json_data) are text/templates over {Tenant, OrgID, OrgName}.
type DatasourceConfig struct {
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	URL            string            `json:"url"`
	Access         string            `json:"access"`
	Database       string            `json:"database"`
	User           string            `json:"user"`
	IsDefault      bool              `json:"is_default"`
	JSONData       map[string]any    `json:"json_data"`
	SecureJSONData map[string]string `json:"secure_json_data"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "url": {"type": "string", "minLength": 1},
    "username": {"type": "string"},
    "password": {"type": "string"},
    "token": {"type": "string"},
    "timeout": {"type": "string"},
    "name_template": {"type": "string", "minLength": 1},
    "on_deprovision": {"enum": ["delete", "keep", "retain"]},
    "remove_creator": {"type": "boolean"},
    "sync_members": {"type": "boolean"},
    "role_map": {
      "type": "object",
      "additionalProperties": {"enum": ["Admin", "Editor", "Viewer", "None"]}
    },
    "default_role": {"enum": ["Admin", "Editor", "Viewer", "None"]},
    "create_users": {"type": "boolean"},
    "quota": {
      "type": "object",
      "propertyNames": {"enum": ["dashboard", "data_source", "org_user", "api_key", "alert_rule"]},
      "additionalProperties": {"type": "string", "minLength": 1}
    },
    "datasources": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": {"type": "string", "minLength": 1},
          "type": {"type": "string", "minLength": 1},
          "url": {"type": "string"},
          "access": {"enum": ["proxy", "direct"]},
          "database": {"type": "string"},
          "user": {"type": "string"},
          "is_default": {"type": "boolean"},
          "json_data": {"type": "object"},
          "secure_json_data": {"type": "object", "additionalProperties": {"type": "string"}}
        },
        "required": ["name", "type"],
        "additionalProperties": false
      }
    }
  },
  "required": ["url"],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg     Config
	base    *url.URL
	name    *template.Template
	ds      []datasourceTemplates
	roles   map[string]string
	client  *http.Client
	host    sdk.Host
	log     *slog.Logger
	now     func() time.Time
	selfMu  sync.Mutex
	selfID  int64
	hasSelf bool
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "grafana-tenant",
		Name:         "Grafana Tenant Isolation",
		Version:      "0.1.0",
		Description:  "Provisions a Grafana organization per tenant and optionally mirrors members, quotas and data sources.",
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
	p.host = r.Host()
	p.log = r.Logger()
	if p.now == nil {
		p.now = time.Now
	}
	r.Provisioner(p)
	if p.cfg.SyncMembers {
		r.Subscribe("members", sdk.EventFilter{Types: []string{
			sdk.EventMemberAdded, sdk.EventMemberUpdated, sdk.EventMemberRemoved,
		}}, p.syncMember)
	}
	if len(p.cfg.Quota) > 0 {
		r.Subscribe("quota", sdk.EventFilter{Types: []string{
			sdk.EventTenantUpdated, sdk.EventTenantPlanChanged,
		}}, p.syncQuota)
	}
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
	return nil
}

// validate checks and defaults the configuration and compiles templates.
func (p *Plugin) validate() error {
	c := &p.cfg
	if c.URL == "" {
		return errors.New("url is required")
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("url must be an absolute http(s) URL, got %q", c.URL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("url must not have a query or fragment, got %q", c.URL)
	}
	p.base = u
	switch {
	case c.Token != "" && (c.Username != "" || c.Password != ""):
		return errors.New("set either token or username/password, not both")
	case c.Token == "" && (c.Username == "" || c.Password == ""):
		return errors.New("username and password (a Grafana server admin) or token are required")
	}
	timeout := 10 * time.Second
	if c.Timeout != "" {
		if timeout, err = time.ParseDuration(c.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("timeout must be a positive duration, got %q", c.Timeout)
		}
	}
	p.client = &http.Client{Timeout: timeout}
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDelete
	case DeprovisionDelete, DeprovisionKeep, DeprovisionRetain:
	default:
		return fmt.Errorf("on_deprovision must be delete, keep or retain, got %q", c.OnDeprovision)
	}
	if c.DefaultRole == "" {
		c.DefaultRole = RoleViewer
	}
	if !validRole(c.DefaultRole) {
		return fmt.Errorf("default_role must be Admin, Editor, Viewer or None, got %q", c.DefaultRole)
	}
	p.roles = maps.Clone(DefaultRoleMap)
	for k, v := range c.RoleMap {
		if !validRole(v) {
			return fmt.Errorf("role_map.%s must be Admin, Editor, Viewer or None, got %q", k, v)
		}
		p.roles[k] = v
	}
	if !c.SyncMembers {
		if c.CreateUsers {
			return errors.New("create_users requires sync_members")
		}
		if len(c.RoleMap) > 0 {
			return errors.New("role_map requires sync_members")
		}
	}
	for target, limit := range c.Quota {
		if !isQuotaTarget(target) {
			return fmt.Errorf("quota: unknown target %q (want one of %s)", target, strings.Join(QuotaTargets, ", "))
		}
		if limit == "" {
			return fmt.Errorf("quota.%s: limit name is required", target)
		}
	}
	if c.NameTemplate == "" {
		c.NameTemplate = DefaultNameTemplate
	}
	if p.name, err = parseNameTemplate(c.NameTemplate); err != nil {
		return err
	}
	p.ds = nil
	seen := map[string]bool{}
	for i, d := range c.Datasources {
		if d.Name == "" || d.Type == "" {
			return fmt.Errorf("datasources[%d]: name and type are required", i)
		}
		if seen[d.Name] {
			return fmt.Errorf("datasources[%d]: duplicate name %q", i, d.Name)
		}
		seen[d.Name] = true
		switch d.Access {
		case "":
			c.Datasources[i].Access = "proxy"
		case "proxy", "direct":
		default:
			return fmt.Errorf("datasources[%d].access must be proxy or direct, got %q", i, d.Access)
		}
		dt, err := compileDatasource(c.Datasources[i])
		if err != nil {
			return fmt.Errorf("datasources[%d]: %w", i, err)
		}
		p.ds = append(p.ds, dt)
	}
	return nil
}

func validRole(r string) bool {
	switch r {
	case RoleAdmin, RoleEditor, RoleViewer, RoleNone:
		return true
	}
	return false
}

func isQuotaTarget(t string) bool {
	for _, q := range QuotaTargets {
		if q == t {
			return true
		}
	}
	return false
}

// Sample tenants used to validate templates at Init.
var (
	sample1 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000001", Slug: "example-one", Name: "Example One"}
	sample2 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000002", Slug: "example-two", Name: "Example Two"}
)

// parseNameTemplate compiles a name template and checks that it renders
// distinct names for two sample tenants.
func parseNameTemplate(s string) (*template.Template, error) {
	tmpl, err := template.New("name").Option("missingkey=error").Parse(s)
	if err != nil {
		return nil, fmt.Errorf("name_template: %w", err)
	}
	n1, err := renderName(tmpl, sample1)
	if err != nil {
		return nil, fmt.Errorf("name_template: %w", err)
	}
	n2, err := renderName(tmpl, sample2)
	if err != nil {
		return nil, fmt.Errorf("name_template: %w", err)
	}
	if n1 == n2 {
		return nil, errors.New("name_template must depend on the tenant (e.g. {{.Slug}} or {{.ID}})")
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
	if len(name) > maxNameLen {
		// Truncating alone could map two tenants to one name; a hash of the
		// tenant ID keeps shortened names distinct.
		sum := sha256.Sum256([]byte(t.ID))
		suffix := "-" + hex.EncodeToString(sum[:4])
		name = strings.TrimRight(truncate(name, maxNameLen-len(suffix)), "- ") + suffix
	}
	return name, nil
}

// SanitizeName turns s into a safe organization name: control characters
// and characters that are unsafe in URL paths (/ \ ? # %) become "-",
// whitespace runs become one space, and the result is trimmed. The length
// limit, which needs the tenant ID, is applied by renderName.
func SanitizeName(s string) string { return sanitize(s) }

func sanitize(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = true
			continue
		case unicode.IsControl(r) || strings.ContainsRune(`/\?#%`, r) || r == unicode.ReplacementChar:
			r = '-'
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return strings.Trim(b.String(), " -")
}

// truncate shortens s to at most n bytes without splitting a rune.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// OrgName returns the organization name of tenant t.
func (p *Plugin) OrgName(t sdk.Tenant) (string, error) {
	name, err := renderName(p.name, t)
	if err != nil {
		return "", fmt.Errorf("name_template: %w", err)
	}
	return name, nil
}

func (p *Plugin) Name() string { return "grafana-org" }

// TenantInfo is the response of GET /tenants/{tenant}.
type TenantInfo struct {
	OrgName     string `json:"org_name"`
	OrgID       int64  `json:"org_id,omitempty"`
	Provisioned bool   `json:"provisioned"`
	// URL opens Grafana switched to the tenant's organization.
	URL string `json:"url,omitempty"`
}

func (p *Plugin) serveTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, err := p.host.GetTenant(ctx, r.PathValue("tenant"))
	if errors.Is(err, sdk.ErrNotFound) {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Answer "not found" rather than "forbidden" so callers cannot probe
	// other tenants' slugs.
	res := sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
	if err := p.host.Authorize(ctx, sdk.ActionTenantsRead, res); err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}
	name, err := p.OrgName(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info := TenantInfo{OrgName: name}
	o, err := p.orgByName(ctx, name)
	if err != nil {
		http.Error(w, "grafana: "+err.Error(), http.StatusBadGateway)
		return
	}
	if o != nil && o.owner() == t.ID {
		info.OrgID = o.ID
		info.Provisioned = true
		info.URL = p.base.String() + "/?orgId=" + strconv.FormatInt(o.ID, 10)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// Health checks that Grafana is up and that the credentials may manage
// organizations (which requires server admin rights).
func (p *Plugin) Health(ctx context.Context) error {
	status, body, err := p.do(ctx, http.MethodGet, "/api/health", 0, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError("health", status, body)
	}
	status, body, err = p.do(ctx, http.MethodGet, "/api/orgs", 0, nil, "perpage", "1")
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("grafana: credentials cannot list organizations (a server admin is required): %s", http.StatusText(status))
	default:
		return apiError("list organizations", status, body)
	}
}

var (
	_ sdk.Plugin        = (*Plugin)(nil)
	_ sdk.Provisioner   = (*Plugin)(nil)
	_ sdk.HealthChecker = (*Plugin)(nil)
)
