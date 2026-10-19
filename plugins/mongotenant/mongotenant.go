// Package mongotenant provisions a MongoDB database and a database user per
// tenant.
//
// The database name comes from name_template (a text/template over
// sdk.Tenant, default "tenant_{{.Slug}}"), the user name from user_template
// (default: the database name). Rendered names are lowercased (MongoDB
// database names are case-insensitive for uniqueness), characters other than
// [a-z0-9_-] become "_", and names longer than 63 bytes are shortened and
// suffixed with a hash of the tenant ID, so two tenants never collide
// through truncation. Templates should only use immutable tenant fields (ID,
// Slug), since names are recomputed on deprovision.
//
// The user is created in auth_database: the tenant database itself
// (default) or a shared database such as "admin". It is granted roles
// (default [readWrite]) on the tenant database only. Its password is derived
// as hex(HMAC-SHA256(password_secret, tenant_id))[:32] (see TenantPassword),
// so nothing secret is stored; every Provision resets it with updateUser,
// which makes rotating password_secret a matter of re-provisioning.
//
// # Ownership
//
// The database holds a marker collection "_tenarium" with the document
// {_id: "owner", tenant_id, tenant_slug, created_at}; since MongoDB creates
// databases lazily, writing the marker is what creates the database. Users
// carry customData {tenarium_tenant_id: <id>}. A database or user marked for
// another tenant is never adopted nor touched. An unmarked database is
// adopted only when it has no collections (what an interrupted Provision
// leaves behind); an unmarked user is never adopted.
//
// # Deprovisioning
//
// on_deprovision chooses what happens when a tenant is deleted:
//
//   - delete (default): the user is dropped, then the database.
//   - keep: nothing is touched; the markers remain, so a new tenant with the
//     same slug cannot adopt the data.
//   - retain: the user is dropped and the data stays, but ownership is
//     released: the owner marker is replaced by {_id: "retained",
//     deleted_at, deleted_tenant_id}. Provisioning a tenant whose name
//     collides with retained data fails until an operator removes it.
package mongotenant

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
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// ID is the plugin ID.
const ID = "mongodb-tenant"

func init() {
	sdk.Register(ID, func() sdk.Plugin { return &Plugin{} })
}

// Deprovision actions.
const (
	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"
	DeprovisionRetain = "retain"
)

// DefaultNameTemplate names tenant databases when name_template is unset.
const DefaultNameTemplate = "tenant_{{.Slug}}"

// DefaultRole is granted on the tenant database when roles is unset.
const DefaultRole = "readWrite"

// maxNameLen is MongoDB's database name limit (64 bytes, exclusive).
const maxNameLen = 63

// reservedDatabases are MongoDB system databases a tenant must never get.
var reservedDatabases = map[string]bool{"admin": true, "local": true, "config": true}

type Config struct {
	// URI is the connection string of an administrative user.
	URI string `json:"uri"`
	// NameTemplate renders the database name from an sdk.Tenant.
	NameTemplate string `json:"name_template"`
	// UserTemplate renders the user name (default: the database name).
	UserTemplate string `json:"user_template"`
	// AuthDatabase is where users are created; empty means the tenant
	// database itself.
	AuthDatabase string `json:"auth_database"`
	// PasswordSecret derives tenant passwords (see TenantPassword).
	PasswordSecret string `json:"password_secret"`
	// Roles are granted on the tenant database (default [readWrite]).
	Roles []string `json:"roles"`
	// QuotaFromLimit is the entitlement limit recorded in the owner marker.
	QuotaFromLimit string `json:"quota_from_limit"`
	// OnDeprovision is "delete" (default), "keep" or "retain".
	OnDeprovision string `json:"on_deprovision"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "uri": {"type": "string", "pattern": "^mongodb(\\+srv)?://"},
    "name_template": {"type": "string", "minLength": 1},
    "user_template": {"type": "string", "minLength": 1},
    "auth_database": {"type": "string"},
    "password_secret": {"type": "string", "minLength": 16},
    "roles": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1, "uniqueItems": true},
    "quota_from_limit": {"type": "string"},
    "on_deprovision": {"enum": ["delete", "keep", "retain"]}
  },
  "required": ["uri", "password_secret"],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg  Config
	name *template.Template
	user *template.Template
	db   backend
	host sdk.Host
	log  *slog.Logger
	now  func() time.Time
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           ID,
		Name:         "MongoDB Tenant Isolation",
		Version:      "0.1.0",
		Description:  "Provisions a MongoDB database and user per tenant.",
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
	b, err := connect(p.cfg.URI)
	if err != nil {
		return fmt.Errorf("uri: %w", err)
	}
	p.init(b, r)
	return nil
}

// init wires a validated plugin to a backend and registers it.
func (p *Plugin) init(b backend, r sdk.Registrar) {
	p.db = b
	p.host = r.Host()
	p.log = r.Logger()
	p.now = time.Now
	r.Provisioner(p)
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
}

// Stop disconnects from MongoDB.
func (p *Plugin) Stop(ctx context.Context) error {
	if p.db == nil {
		return nil
	}
	return p.db.Close(ctx)
}

// validate checks and defaults the configuration and compiles templates.
func (p *Plugin) validate() error {
	c := &p.cfg
	if c.URI == "" {
		return errors.New("uri is required")
	}
	if _, err := splitURI(c.URI); err != nil {
		return fmt.Errorf("uri: %w", err)
	}
	if c.PasswordSecret == "" {
		return errors.New("password_secret is required")
	}
	if len(c.PasswordSecret) < 16 {
		return errors.New("password_secret must be at least 16 characters")
	}
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDelete
	case DeprovisionDelete, DeprovisionKeep, DeprovisionRetain:
	default:
		return fmt.Errorf("on_deprovision must be delete, keep or retain, got %q", c.OnDeprovision)
	}
	if c.AuthDatabase != "" {
		if err := checkDBName(c.AuthDatabase); err != nil {
			return fmt.Errorf("auth_database: %w", err)
		}
		if c.AuthDatabase == "local" || c.AuthDatabase == "config" {
			return fmt.Errorf("auth_database: users cannot be created in %q", c.AuthDatabase)
		}
	}
	if len(c.Roles) == 0 {
		c.Roles = []string{DefaultRole}
	}
	seen := map[string]bool{}
	for _, r := range c.Roles {
		if r == "" || strings.ContainsAny(r, " \t\r\n.$\x00") {
			return fmt.Errorf("roles: invalid role name %q", r)
		}
		if seen[r] {
			return fmt.Errorf("roles: duplicate role %q", r)
		}
		seen[r] = true
	}
	if c.NameTemplate == "" {
		c.NameTemplate = DefaultNameTemplate
	}
	var err error
	if p.name, err = parseNameTemplate("name_template", c.NameTemplate); err != nil {
		return err
	}
	if c.UserTemplate != "" {
		if p.user, err = parseNameTemplate("user_template", c.UserTemplate); err != nil {
			return err
		}
	}
	if c.AuthDatabase != "" {
		// A tenant database must never coincide with the shared auth
		// database: dropping it would drop every tenant's users.
		for _, s := range []sdk.Tenant{sample1, sample2} {
			if n, _ := renderName(p.name, s); n == c.AuthDatabase {
				return fmt.Errorf("name_template renders the auth_database name %q", n)
			}
		}
	}
	return nil
}

// TenantPassword derives the password of a tenant's user: the first 32 hex
// characters of HMAC-SHA256(secret, tenantID). Applications that know the
// secret compute it the same way to connect as the tenant.
func TenantPassword(secret, tenantID string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(tenantID))
	return hex.EncodeToString(m.Sum(nil))[:32]
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
	if len(name) > maxNameLen {
		// Truncating alone could map two tenants to one name; a hash of the
		// tenant ID keeps shortened names distinct.
		sum := sha256.Sum256([]byte(t.ID))
		suffix := "_" + hex.EncodeToString(sum[:4])
		name = strings.TrimRight(name[:maxNameLen-len(suffix)], "_-") + suffix
	}
	if err := checkDBName(name); err != nil {
		return "", fmt.Errorf("renders invalid name %q for tenant %s: %w", name, t.ID, err)
	}
	if reservedDatabases[name] {
		return "", fmt.Errorf("renders the reserved name %q for tenant %s", name, t.ID)
	}
	return name, nil
}

// SanitizeName turns s into a safe MongoDB database or user name candidate:
// lowercase, characters other than [a-z0-9_-] replaced by "_", runs of "_"
// collapsed and leading/trailing "_" and "-" trimmed. It does not enforce
// the length limit, which needs the tenant ID; see renderName.
func SanitizeName(s string) string { return sanitize(s) }

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-':
			b.WriteRune(r)
		case !strings.HasSuffix(b.String(), "_"):
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_-")
}

// checkDBName applies MongoDB's database naming rules.
func checkDBName(s string) error {
	if s == "" {
		return errors.New("empty database name")
	}
	if len(s) > maxNameLen {
		return fmt.Errorf("database name longer than %d bytes", maxNameLen)
	}
	if strings.ContainsAny(s, "/\\. \"$*<>:|?\x00") {
		return errors.New(`database name must not contain any of /\. "$*<>:|? or spaces`)
	}
	return nil
}

// target is what a tenant maps to in MongoDB.
type target struct {
	Database     string
	User         string
	AuthDatabase string
}

func (p *Plugin) target(t sdk.Tenant) (target, error) {
	db, err := renderName(p.name, t)
	if err != nil {
		return target{}, fmt.Errorf("name_template: %w", err)
	}
	user := db
	if p.user != nil {
		if user, err = renderName(p.user, t); err != nil {
			return target{}, fmt.Errorf("user_template: %w", err)
		}
	}
	auth := p.cfg.AuthDatabase
	if auth == "" {
		auth = db
	}
	if p.cfg.AuthDatabase != "" && db == p.cfg.AuthDatabase {
		return target{}, fmt.Errorf("tenant %s maps to the auth_database %q", t.ID, db)
	}
	return target{Database: db, User: user, AuthDatabase: auth}, nil
}

func (p *Plugin) roles(db string) []role {
	out := make([]role, len(p.cfg.Roles))
	for i, r := range p.cfg.Roles {
		out[i] = role{Role: r, DB: db}
	}
	return out
}

// Health pings the primary.
func (p *Plugin) Health(ctx context.Context) error { return p.db.Ping(ctx) }

// TenantInfo is the response of GET /tenants/{tenant}.
type TenantInfo struct {
	Database     string `json:"database"`
	User         string `json:"user"`
	AuthDatabase string `json:"auth_database"`
	Roles        []role `json:"roles"`
	// URI is a connection string for the tenant user, without password.
	URI string `json:"uri"`
	// Password is only returned with ?include_password=true to callers
	// allowed to update the tenant.
	Password string `json:"password,omitempty"`
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
	tg, err := p.target(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	uri, err := tenantURI(p.cfg.URI, tg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info := TenantInfo{
		Database: tg.Database, User: tg.User, AuthDatabase: tg.AuthDatabase,
		Roles: p.roles(tg.Database), URI: uri,
	}
	if r.URL.Query().Get("include_password") == "true" {
		if err := p.host.Authorize(ctx, sdk.ActionTenantsUpdate, res); err != nil {
			http.Error(w, "forbidden: the password requires tenants:update", http.StatusForbidden)
			return
		}
		info.Password = TenantPassword(p.cfg.PasswordSecret, t.ID)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(info)
}

// uriParts is a MongoDB connection string split into its components.
// net/url cannot parse multi-host strings ("h1:27017,h2:27017").
type uriParts struct {
	Scheme string // "mongodb" or "mongodb+srv"
	Hosts  string
	Query  url.Values
}

func splitURI(s string) (uriParts, error) {
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok || (scheme != "mongodb" && scheme != "mongodb+srv") {
		return uriParts{}, errors.New("must start with mongodb:// or mongodb+srv://")
	}
	hostPart, query, _ := strings.Cut(rest, "?")
	hostPart, _, _ = strings.Cut(hostPart, "/")
	if i := strings.LastIndex(hostPart, "@"); i >= 0 {
		hostPart = hostPart[i+1:]
	}
	if hostPart == "" {
		return uriParts{}, errors.New("missing host")
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return uriParts{}, fmt.Errorf("options: %w", err)
	}
	return uriParts{Scheme: scheme, Hosts: hostPart, Query: q}, nil
}

// tenantURI derives the tenant user's connection string from the admin
// URI: the admin credentials and authentication options are removed, the
// tenant user, database and authSource are set. Other options (tls,
// replicaSet, ...) are kept.
func tenantURI(adminURI string, tg target) (string, error) {
	u, err := splitURI(adminURI)
	if err != nil {
		return "", err
	}
	for _, k := range []string{"authSource", "authMechanism", "authMechanismProperties"} {
		u.Query.Del(k)
	}
	u.Query.Set("authSource", tg.AuthDatabase)
	return fmt.Sprintf("%s://%s@%s/%s?%s", u.Scheme, url.PathEscape(tg.User), u.Hosts,
		url.PathEscape(tg.Database), u.Query.Encode()), nil
}
