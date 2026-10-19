// Package opensearchtenant gives every tenant its own index prefix on
// OpenSearch or Elasticsearch, talking to the REST API with net/http.
//
// The prefix comes from name_template (a text/template over sdk.Tenant,
// default "tenant_{{.Slug}}"), sanitized to lowercase letters, digits and
// underscores. Hyphens are reserved as the separator between the prefix and
// the rest of an index name: the tenant owns "<prefix>-*", and because no
// prefix contains a hyphen, the pattern of one tenant can never match the
// indices of another ("tenant_acme-*" does not match "tenant_acme_corp-x").
// Names that are too long are shortened and suffixed with a hash of the
// tenant ID.
//
// Provision maintains, depending on the configuration:
//
//   - an index template "tenarium-<prefix>" with index_patterns
//     ["<prefix>-*"], the configured settings and mappings, and _meta
//     {tenarium_tenant_id} as the ownership marker;
//   - an initial index "<prefix>-<create_initial_index>", optionally with a
//     write alias "<prefix>-<initial_alias>";
//   - with security enabled, a role "<prefix>" granting index_permissions on
//     "<prefix>-*", and optionally a user "<prefix>" whose password is
//     TenantPassword(password_secret, tenant ID). On OpenSearch these are
//     Security plugin roles, role mappings and internal users; on
//     Elasticsearch native roles and users.
//
// # Ownership
//
// The index template's _meta, the role's description (OpenSearch) or
// metadata (Elasticsearch) and the user's attributes or metadata record the
// tenant ID. Objects marked for another tenant are never adopted or
// deleted, and objects without a marker are never overwritten: the plugin
// writes every object together with its marker, so an unmarked object was
// not created by it. When no marker of the tenant exists yet, Provision
// refuses to claim a prefix for which indices already exist.
//
// # Deprovisioning
//
//   - delete (default): the tenant's user, role mapping and role are
//     removed, every index matching "<prefix>-*" is deleted by its concrete
//     name (so clusters with action.destructive_requires_name keep working),
//     and the index template goes last.
//   - keep: nothing is touched; the markers stay.
//   - retain: indices are kept, security objects are deleted and the index
//     template's _meta is rewritten to tenarium_deleted_tenant_id and
//     tenarium_deleted_at. Provisioning a new tenant with the same prefix
//     then fails until an operator moves or removes the data.
package opensearchtenant

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("opensearch-tenant", func() sdk.Plugin { return &Plugin{} })
}

// Flavors and deprovision actions.
const (
	FlavorOpenSearch    = "opensearch"
	FlavorElasticsearch = "elasticsearch"

	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"
	DeprovisionRetain = "retain"
)

// DefaultNameTemplate renders the index prefix when name_template is unset.
const DefaultNameTemplate = "tenant_{{.Slug}}"

// DefaultPriority is the default index template priority. It is above the
// priority of typical catch-all templates; composable templates with
// overlapping patterns must not share a priority.
const DefaultPriority = 100

// TemplatePrefix is prepended to the index prefix to name its template.
const TemplatePrefix = "tenarium-"

// maxPrefixLen bounds the prefix so that index names ("<prefix>-...", at
// most 255 bytes), template, role and user names keep plenty of room.
const maxPrefixLen = 64

// Marker keys in index template _meta, role/user metadata and attributes.
const (
	MetaTenantID        = "tenarium_tenant_id"
	MetaDeletedTenantID = "tenarium_deleted_tenant_id"
	MetaDeletedAt       = "tenarium_deleted_at"
	MetaManagedBy       = "managed_by"
	MetaQuotaLimit      = "tenarium_quota_limit"
	MetaQuota           = "tenarium_quota"
)

// Default permissions of the tenant role.
var (
	defaultOpenSearchIndexPermissions   = []string{"crud", "create_index", "indices:admin/mapping/put"}
	defaultOpenSearchClusterPermissions = []string{"cluster_composite_ops"}
	defaultESIndexPrivileges            = []string{"read", "write", "create_index", "view_index_metadata"}
)

type Config struct {
	// URL or URLs of cluster nodes; requests fail over between them.
	URL  string   `json:"url"`
	URLs []string `json:"urls"`
	// Username and Password authenticate with basic auth.
	Username string `json:"username"`
	Password string `json:"password"`
	// APIKey is an Elasticsearch/OpenSearch API key (base64 "id:key"),
	// sent as "Authorization: ApiKey ...". Exclusive with username.
	APIKey string     `json:"api_key"`
	TLS    *TLSConfig `json:"tls"`
	// Timeout of each request, a Go duration (default 30s).
	Timeout string `json:"timeout"`
	// Flavor is "opensearch" (default) or "elasticsearch".
	Flavor string `json:"flavor"`
	// NameTemplate renders the index prefix from an sdk.Tenant.
	NameTemplate  string              `json:"name_template"`
	IndexTemplate IndexTemplateConfig `json:"index_template"`
	// CreateInitialIndex is the suffix of an index created at provisioning
	// ("000001" creates "<prefix>-000001"). Empty creates none.
	CreateInitialIndex string `json:"create_initial_index"`
	// InitialAlias is the suffix of a write alias on the initial index
	// ("write" creates "<prefix>-write").
	InitialAlias string         `json:"initial_alias"`
	Security     SecurityConfig `json:"security"`
	// QuotaFromLimit is the entitlement limit recorded in the template _meta.
	QuotaFromLimit string `json:"quota_from_limit"`
	// OnDeprovision is "delete" (default), "keep" or "retain".
	OnDeprovision string `json:"on_deprovision"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	CAFile             string `json:"ca_file"`
}

type IndexTemplateConfig struct {
	// Enabled defaults to true.
	Enabled  *bool `json:"enabled"`
	Priority *int  `json:"priority"`
	// Shards and Replicas set index.number_of_shards/_replicas.
	Shards   *int `json:"shards"`
	Replicas *int `json:"replicas"`
	// Settings are additional index settings.
	Settings map[string]any `json:"settings"`
	// Mappings is the mappings object of the template.
	Mappings map[string]any `json:"mappings"`
}

type SecurityConfig struct {
	Enabled bool `json:"enabled"`
	// CreateUser creates a user named like the prefix, mapped to the role.
	CreateUser bool `json:"create_user"`
	// PasswordSecret derives user passwords; see TenantPassword.
	PasswordSecret string `json:"password_secret"`
	// IndexPermissions are OpenSearch allowed_actions or Elasticsearch
	// index privileges on "<prefix>-*".
	IndexPermissions []string `json:"index_permissions"`
	// ClusterPermissions are cluster permissions/privileges of the role.
	ClusterPermissions []string `json:"cluster_permissions"`
	// BackendRoles are mapped to the role (OpenSearch only).
	BackendRoles []string `json:"backend_roles"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "url": {"type": "string", "minLength": 1},
    "urls": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1},
    "username": {"type": "string"},
    "password": {"type": "string"},
    "api_key": {"type": "string"},
    "tls": {
      "type": "object",
      "properties": {
        "insecure_skip_verify": {"type": "boolean"},
        "ca_file": {"type": "string"}
      },
      "additionalProperties": false
    },
    "timeout": {"type": "string"},
    "flavor": {"enum": ["opensearch", "elasticsearch"]},
    "name_template": {"type": "string", "minLength": 1},
    "index_template": {
      "type": "object",
      "properties": {
        "enabled": {"type": "boolean"},
        "priority": {"type": "integer", "minimum": 0},
        "shards": {"type": "integer", "minimum": 1},
        "replicas": {"type": "integer", "minimum": 0},
        "settings": {"type": "object"},
        "mappings": {"type": "object"}
      },
      "additionalProperties": false
    },
    "create_initial_index": {"type": "string"},
    "initial_alias": {"type": "string"},
    "security": {
      "type": "object",
      "properties": {
        "enabled": {"type": "boolean"},
        "create_user": {"type": "boolean"},
        "password_secret": {"type": "string"},
        "index_permissions": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "cluster_permissions": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "backend_roles": {"type": "array", "items": {"type": "string", "minLength": 1}}
      },
      "additionalProperties": false
    },
    "quota_from_limit": {"type": "string"},
    "on_deprovision": {"enum": ["delete", "keep", "retain"]}
  },
  "anyOf": [{"required": ["url"]}, {"required": ["urls"]}],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg     Config
	name    *template.Template
	timeout time.Duration
	client  *client
	host    sdk.Host
	log     *slog.Logger
	now     func() time.Time
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "opensearch-tenant",
		Name:         "OpenSearch Tenant Isolation",
		Version:      "0.1.0",
		Description:  "Provisions an index prefix, index template and optional role and user per tenant on OpenSearch or Elasticsearch.",
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
	cl, err := newClient(&p.cfg, p.timeout)
	if err != nil {
		return err
	}
	p.client = cl
	p.host = r.Host()
	p.log = r.Logger()
	p.now = time.Now
	r.Provisioner(p)
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
	return nil
}

// validate checks and defaults the configuration and compiles templates.
func (p *Plugin) validate() error {
	c := &p.cfg
	switch {
	case c.URL != "" && len(c.URLs) > 0:
		return errors.New("set either url or urls, not both")
	case c.URL != "":
		c.URLs = []string{c.URL}
	case len(c.URLs) == 0:
		return errors.New("url is required")
	}
	for _, u := range c.URLs {
		if _, err := parseURL(u); err != nil {
			return err
		}
	}
	if c.APIKey != "" && c.Username != "" {
		return errors.New("set either username/password or api_key, not both")
	}
	if c.Password != "" && c.Username == "" {
		return errors.New("password requires username")
	}
	p.timeout = 30 * time.Second
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("timeout must be a positive duration such as 30s, got %q", c.Timeout)
		}
		p.timeout = d
	}
	switch c.Flavor {
	case "":
		c.Flavor = FlavorOpenSearch
	case FlavorOpenSearch, FlavorElasticsearch:
	default:
		return fmt.Errorf("flavor must be opensearch or elasticsearch, got %q", c.Flavor)
	}
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDelete
	case DeprovisionDelete, DeprovisionKeep, DeprovisionRetain:
	default:
		return fmt.Errorf("on_deprovision must be delete, keep or retain, got %q", c.OnDeprovision)
	}

	it := &c.IndexTemplate
	if it.Enabled == nil {
		enabled := true
		it.Enabled = &enabled
	}
	if it.Priority == nil {
		prio := DefaultPriority
		it.Priority = &prio
	}
	if *it.Priority < 0 {
		return fmt.Errorf("index_template.priority must not be negative, got %d", *it.Priority)
	}
	if it.Shards != nil && *it.Shards < 1 {
		return fmt.Errorf("index_template.shards must be at least 1, got %d", *it.Shards)
	}
	if it.Replicas != nil && *it.Replicas < 0 {
		return fmt.Errorf("index_template.replicas must not be negative, got %d", *it.Replicas)
	}
	if !*it.Enabled && (it.Shards != nil || it.Replicas != nil || len(it.Settings) > 0 || len(it.Mappings) > 0) {
		return errors.New("index_template settings are set but index_template.enabled is false")
	}
	if c.QuotaFromLimit != "" && !*it.Enabled {
		return errors.New("quota_from_limit is recorded in the index template and requires index_template.enabled")
	}

	if c.CreateInitialIndex != "" {
		if err := checkSuffix(c.CreateInitialIndex); err != nil {
			return fmt.Errorf("create_initial_index: %w", err)
		}
	}
	if c.InitialAlias != "" {
		if c.CreateInitialIndex == "" {
			return errors.New("initial_alias requires create_initial_index")
		}
		if err := checkSuffix(c.InitialAlias); err != nil {
			return fmt.Errorf("initial_alias: %w", err)
		}
		if c.InitialAlias == c.CreateInitialIndex {
			return errors.New("initial_alias must differ from create_initial_index")
		}
	}

	s := &c.Security
	if s.Enabled {
		if s.CreateUser && s.PasswordSecret == "" {
			return errors.New("security.password_secret is required with security.create_user")
		}
		if c.Flavor == FlavorElasticsearch && len(s.BackendRoles) > 0 {
			return errors.New("security.backend_roles is only supported by the opensearch flavor; use Elasticsearch role mappings instead")
		}
		if s.IndexPermissions == nil {
			if c.Flavor == FlavorElasticsearch {
				s.IndexPermissions = defaultESIndexPrivileges
			} else {
				s.IndexPermissions = defaultOpenSearchIndexPermissions
			}
		}
		if len(s.IndexPermissions) == 0 {
			return errors.New("security.index_permissions must not be empty")
		}
		if s.ClusterPermissions == nil && c.Flavor == FlavorOpenSearch {
			s.ClusterPermissions = defaultOpenSearchClusterPermissions
		}
	} else if s.CreateUser || s.PasswordSecret != "" || len(s.IndexPermissions) > 0 ||
		len(s.ClusterPermissions) > 0 || len(s.BackendRoles) > 0 {
		return errors.New("security options are set but security.enabled is false")
	}
	if !*it.Enabled && !s.Enabled {
		return errors.New("nothing carries the ownership marker: enable index_template or security")
	}

	if c.NameTemplate == "" {
		c.NameTemplate = DefaultNameTemplate
	}
	var err error
	p.name, err = parseNameTemplate(c.NameTemplate)
	return err
}

// checkSuffix validates an index or alias name suffix.
func checkSuffix(s string) error {
	if len(s) > 64 {
		return errors.New("must be at most 64 characters")
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return fmt.Errorf("%q may only contain lowercase letters, digits, '-' and '_'", s)
		}
	}
	return nil
}

// Sample tenants used to validate the name template at Init.
var (
	sample1 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000001", Slug: "example-one", Name: "Example One"}
	sample2 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000002", Slug: "example-two", Name: "Example Two"}
)

// parseNameTemplate compiles a name template and checks that it renders
// distinct, valid prefixes for two sample tenants.
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
	if len(name) > maxPrefixLen {
		// Truncating alone could map two tenants to one prefix; a hash of
		// the tenant ID keeps shortened prefixes distinct.
		sum := sha256.Sum256([]byte(t.ID))
		suffix := "_" + hex.EncodeToString(sum[:4])
		name = strings.TrimRight(name[:maxPrefixLen-len(suffix)], "_") + suffix
	}
	return name, nil
}

// SanitizeName turns s into an index prefix: lowercase letters, digits and
// underscores; every other character (hyphens included, which separate the
// prefix from the rest of an index name) becomes "_", runs of "_" are
// collapsed and leading and trailing "_" trimmed, so the prefix never starts
// with a character Elasticsearch/OpenSearch reject ("-", "_", "+", ".").
// It does not enforce the length limit, which needs the tenant ID.
func SanitizeName(s string) string { return sanitize(s) }

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if !strings.HasSuffix(b.String(), "_") {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// TenantPassword derives the password of a tenant user: the first 32 hex
// characters of HMAC-SHA256(secret, tenantID). Applications that know the
// secret compute it the same way to connect as the tenant.
func TenantPassword(secret, tenantID string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(tenantID))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// names are the cluster objects of a tenant.
type names struct {
	Prefix   string
	Pattern  string // "<prefix>-*"
	Template string // "tenarium-<prefix>"
	Role     string
	User     string
	Index    string // initial index, "" if none
	Alias    string // initial alias, "" if none
}

func (p *Plugin) names(t sdk.Tenant) (names, error) {
	prefix, err := renderName(p.name, t)
	if err != nil {
		return names{}, fmt.Errorf("name_template: %w", err)
	}
	n := names{Prefix: prefix, Pattern: prefix + "-*", Template: TemplatePrefix + prefix}
	if p.cfg.Security.Enabled {
		n.Role = prefix
		if p.cfg.Security.CreateUser {
			n.User = prefix
		}
	}
	if p.cfg.CreateInitialIndex != "" {
		n.Index = prefix + "-" + p.cfg.CreateInitialIndex
	}
	if p.cfg.InitialAlias != "" {
		n.Alias = prefix + "-" + p.cfg.InitialAlias
	}
	return n, nil
}

func (p *Plugin) Name() string { return "opensearch" }

func (p *Plugin) templateEnabled() bool { return *p.cfg.IndexTemplate.Enabled }

// needsMapping reports whether an OpenSearch role mapping is maintained.
func (p *Plugin) needsMapping() bool {
	s := p.cfg.Security
	return s.Enabled && p.cfg.Flavor == FlavorOpenSearch && (s.CreateUser || len(s.BackendRoles) > 0)
}

// Provision creates or updates the tenant's objects. Every step is
// idempotent; markers are checked before anything is written.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	n, err := p.names(t)
	if err != nil {
		return err
	}
	quota, err := p.quota(ctx, t)
	if err != nil {
		return err
	}
	objs, err := p.inspect(ctx, n)
	if err != nil {
		return err
	}
	owned := false
	for _, o := range objs {
		mine, err := o.claim(t.ID)
		if err != nil {
			return err
		}
		owned = owned || mine
	}
	if !owned {
		// Nothing carries this tenant's marker yet: the prefix may only be
		// claimed if it holds no data.
		idx, err := p.listIndices(ctx, n.Pattern)
		if err != nil {
			return err
		}
		if len(idx) > 0 {
			return fmt.Errorf("indices matching %s already exist (%s) and are not managed by tenarium for this tenant",
				n.Pattern, strings.Join(truncateList(idx, 5), ", "))
		}
	}

	// Marker-carrying objects first, data last, so an interrupted run
	// always leaves a marker behind before any index exists.
	if p.templateEnabled() {
		if err := p.putTemplate(ctx, n, p.liveMeta(t, quota), !objs[kindTemplate].Exists); err != nil {
			return err
		}
	}
	if p.cfg.Security.Enabled {
		if err := p.putRole(ctx, n, t); err != nil {
			return err
		}
		if n.User != "" {
			if err := p.putUser(ctx, n, t); err != nil {
				return err
			}
		}
		if p.needsMapping() {
			if err := p.putMapping(ctx, n, t); err != nil {
				return err
			}
		}
	}
	if n.Index != "" {
		if err := p.createIndex(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

// Deprovision applies on_deprovision. Objects that do not exist are
// treated as already removed; objects of other tenants are left alone.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		return nil
	}
	n, err := p.names(t)
	if err != nil {
		return err
	}
	objs, err := p.inspect(ctx, n)
	if err != nil {
		return err
	}
	owned, foreign := false, false
	for _, o := range objs {
		switch {
		case !o.Exists:
		case o.TenantID == t.ID:
			owned = true
		case o.TenantID != "":
			foreign = true
			p.log.Warn("not deprovisioning an object owned by another tenant",
				"kind", o.Kind, "name", o.Name, "tenant_id", t.ID, "owner", o.TenantID)
		case o.DeletedTenantID != "":
			if o.DeletedTenantID != t.ID {
				p.log.Warn("not deprovisioning an object retained from another tenant",
					"kind", o.Kind, "name", o.Name, "tenant_id", t.ID, "owner", o.DeletedTenantID)
			}
		default:
			p.log.Warn("not deprovisioning an object not managed by tenarium",
				"kind", o.Kind, "name", o.Name, "tenant_id", t.ID)
		}
	}
	if !owned {
		return nil
	}

	// Revoke access first.
	for _, k := range []objectKind{kindUser, kindMapping} {
		if o, ok := objs[k]; ok && o.Exists && o.TenantID == t.ID {
			if err := p.deleteObject(ctx, o); err != nil {
				return err
			}
		}
	}
	if p.cfg.OnDeprovision == DeprovisionDelete {
		if foreign {
			p.log.Warn("not deleting indices of a prefix with objects of another tenant",
				"pattern", n.Pattern, "tenant_id", t.ID)
		} else if err := p.deleteIndices(ctx, n.Pattern); err != nil {
			return err
		}
	}
	// Markers last, so an interrupted run is retried.
	if o, ok := objs[kindRole]; ok && o.Exists && o.TenantID == t.ID {
		if err := p.deleteObject(ctx, o); err != nil {
			return err
		}
	}
	if o, ok := objs[kindTemplate]; ok && o.Exists && o.TenantID == t.ID {
		if p.cfg.OnDeprovision == DeprovisionRetain {
			return p.putTemplate(ctx, n, p.retainedMeta(t), false)
		}
		return p.deleteObject(ctx, o)
	}
	return nil
}

// liveMeta is the template _meta of a live tenant.
func (p *Plugin) liveMeta(t sdk.Tenant, quota *int64) map[string]any {
	m := map[string]any{MetaManagedBy: "tenarium", MetaTenantID: t.ID}
	if quota != nil {
		m[MetaQuotaLimit] = p.cfg.QuotaFromLimit
		m[MetaQuota] = *quota
	}
	return m
}

// retainedMeta is the template _meta after on_deprovision: retain.
func (p *Plugin) retainedMeta(t sdk.Tenant) map[string]any {
	return map[string]any{
		MetaManagedBy:       "tenarium",
		MetaDeletedTenantID: t.ID,
		MetaDeletedAt:       p.now().UTC().Format(time.RFC3339),
	}
}

// quota returns the tenant's quota_from_limit value, or nil when not
// configured or unlimited.
func (p *Plugin) quota(ctx context.Context, t sdk.Tenant) (*int64, error) {
	if p.cfg.QuotaFromLimit == "" {
		return nil, nil
	}
	e, err := p.host.Entitlements(ctx, t.ID)
	if err != nil {
		return nil, fmt.Errorf("entitlements: %w", err)
	}
	if v, ok := e.Limit(p.cfg.QuotaFromLimit); ok {
		return &v, nil
	}
	return nil, nil
}

func truncateList(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("and %d more", len(s)-n))
	}
	return s
}

// TenantInfo is the response of GET /tenants/{tenant}.
type TenantInfo struct {
	Flavor        string   `json:"flavor"`
	URLs          []string `json:"urls"`
	Prefix        string   `json:"prefix"`
	IndexPattern  string   `json:"index_pattern"`
	IndexTemplate string   `json:"index_template,omitempty"`
	InitialIndex  string   `json:"initial_index,omitempty"`
	Alias         string   `json:"alias,omitempty"`
	Role          string   `json:"role,omitempty"`
	User          string   `json:"user,omitempty"`
}

func (p *Plugin) serveTenant(w http.ResponseWriter, r *http.Request) {
	t, err := p.host.GetTenant(r.Context(), r.PathValue("tenant"))
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
	if err := p.host.Authorize(r.Context(), sdk.ActionTenantsRead, res); err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}
	n, err := p.names(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info := TenantInfo{
		Flavor: p.cfg.Flavor, URLs: p.cfg.URLs, Prefix: n.Prefix, IndexPattern: n.Pattern,
		InitialIndex: n.Index, Alias: n.Alias, Role: n.Role, User: n.User,
	}
	if p.templateEnabled() {
		info.IndexTemplate = n.Template
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// Health checks GET _cluster/health and fails when the cluster is red.
func (p *Plugin) Health(ctx context.Context) error {
	var h struct {
		Status string `json:"status"`
	}
	if err := p.client.do(ctx, http.MethodGet, "/_cluster/health", nil, nil, &h); err != nil {
		return err
	}
	if h.Status == "red" {
		return errors.New("cluster health is red")
	}
	return nil
}
