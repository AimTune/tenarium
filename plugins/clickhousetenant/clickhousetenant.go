// Package clickhousetenant provisions a ClickHouse database, a user with
// grants on it and, optionally, a settings profile and a quota per tenant.
// It talks to the ClickHouse HTTP interface (port 8123/8443) with the
// standard library only.
//
// The database name comes from name_template (a text/template over
// sdk.Tenant, default "tenant_{{.Slug}}"), the user name from user_template
// (default: the database name). Both are sanitized to [a-z0-9_] and
// shortened to 63 characters with a hash of the tenant ID when longer, so two
// tenants never collide through truncation. Templates should only use
// immutable tenant fields (ID, Slug), since names are recomputed on
// deprovision.
//
// # Credentials
//
// The user's password is derived, never stored: the first 32 hex characters
// of HMAC-SHA256(password_secret, tenant ID) (see TenantPassword). It is set
// with IDENTIFIED WITH sha256_password, and every Provision re-applies it, so
// changing password_secret and re-provisioning rotates all passwords.
//
// # Ownership
//
// The database carries the comment "tenarium:tenant=<id>", written in the
// same CREATE DATABASE statement, so a database is never left unmarked by an
// interrupted Provision. A database marked for another tenant (or carrying
// any foreign comment) is never adopted nor dropped. An unmarked database is
// adopted only when it has no tables. Users, settings profiles and quotas
// cannot carry comments on every ClickHouse version; they belong to the
// tenant when the tenant's database is theirs and the user's DEFAULT
// DATABASE is that database (profiles and quotas: when they apply to that
// user only). An existing user with another default database is never
// modified or dropped.
//
// # Deprovisioning
//
// on_deprovision chooses what happens when a tenant is deleted:
//
//   - delete (default): quota, settings profile and user are dropped, then
//     the database (DROP DATABASE ... SYNC). The database goes last, so an
//     interrupted run is retried safely.
//   - keep: nothing is touched; the database keeps its marker so a new
//     tenant with the same slug cannot adopt it.
//   - retain: access is removed (quota, profile, user dropped) and the data
//     stays, but the database comment becomes
//     "tenarium:deleted-tenant=<id> deleted-at=<RFC3339>". Provisioning a
//     tenant whose name collides with a retained database fails until an
//     operator removes or renames it.
package clickhousetenant

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("clickhouse-tenant", func() sdk.Plugin { return &Plugin{} })
}

// Deprovision actions.
const (
	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"
	DeprovisionRetain = "retain"
)

// DefaultNameTemplate names tenant databases when name_template is unset.
const DefaultNameTemplate = "tenant_{{.Slug}}"

// DefaultQuotaInterval is the quota interval when quota.interval is unset.
const DefaultQuotaInterval = "1 hour"

// DefaultGrants are the privileges granted on the tenant database when
// grants is unset. They deliberately exclude ALTER DATABASE and DROP
// DATABASE, with which a tenant could rewrite or drop the ownership marker.
var DefaultGrants = []string{
	"SELECT", "INSERT", "ALTER TABLE", "ALTER VIEW",
	"CREATE TABLE", "CREATE VIEW", "CREATE DICTIONARY",
	"DROP TABLE", "DROP VIEW", "DROP DICTIONARY",
	"TRUNCATE", "OPTIMIZE", "SHOW", "dictGet",
}

// maxNameLen bounds database and user names.
const maxNameLen = 63

// Ownership marker prefixes (database comments).
const (
	markerPrefix   = "tenarium:tenant="
	retainedPrefix = "tenarium:deleted-tenant="
)

// reservedDatabases and reservedUsers must never be rendered by a template.
var (
	reservedDatabases = []string{"system", "default", "information_schema"}
	reservedUsers     = []string{"default"}
)

// QuotaKeys are the ClickHouse quota limits that can be set.
var QuotaKeys = []string{
	"queries", "query_selects", "query_inserts", "errors",
	"result_rows", "result_bytes", "read_rows", "read_bytes",
	"execution_time", "written_bytes", "failed_sequential_authentications",
}

var (
	grantRe    = regexp.MustCompile(`^[A-Za-z]+( [A-Za-z]+)*$`)
	settingRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	clusterRe  = regexp.MustCompile(`^[A-Za-z0-9_.{}-]+$`)
	engineRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\([^;]*\))?$`)
	intervalRe = regexp.MustCompile(`^([1-9][0-9]*) (second|minute|hour|day|week|month|quarter|year)s?$`)
)

type Config struct {
	// URL of the HTTP interface, e.g. http://clickhouse:8123.
	URL string `json:"url"`
	// Username and Password of the admin account (default user "default").
	Username string `json:"username"`
	Password string `json:"password"`
	// Cluster adds ON CLUSTER '<cluster>' to every DDL statement.
	Cluster string `json:"cluster"`
	// DatabaseEngine is the ENGINE of created databases (server default when
	// empty), e.g. "Atomic" or "Replicated('/clickhouse/db/{uuid}', '{shard}', '{replica}')".
	DatabaseEngine string `json:"database_engine"`
	// NameTemplate renders the database name from an sdk.Tenant.
	NameTemplate string `json:"name_template"`
	// UserTemplate renders the user name (default: the database name).
	UserTemplate string `json:"user_template"`
	// PasswordSecret derives user passwords (see TenantPassword).
	PasswordSecret string `json:"password_secret"`
	// Grants are privileges granted ON <db>.* (default DefaultGrants).
	Grants []string `json:"grants"`
	// SettingsProfile creates a per-tenant settings profile.
	SettingsProfile *ProfileConfig `json:"settings_profile"`
	// Quota creates a per-tenant quota.
	Quota *QuotaConfig `json:"quota"`
	// OnDeprovision is "delete" (default), "keep" or "retain".
	OnDeprovision string `json:"on_deprovision"`
	// TimeoutSeconds bounds each HTTP request (default 30).
	TimeoutSeconds int `json:"timeout_seconds"`
}

// ProfileConfig configures the per-tenant settings profile.
type ProfileConfig struct {
	// Settings are fixed setting values (numbers, strings or booleans).
	Settings map[string]any `json:"settings"`
	// FromLimits maps a setting to an entitlement limit; the tenant's limit
	// overrides Settings, and unlimited tenants keep the Settings value (or
	// the server default).
	FromLimits map[string]string `json:"from_limits"`
	// Lock marks the settings READONLY so the tenant cannot change them
	// (default true).
	Lock *bool `json:"lock"`
}

// QuotaConfig configures the per-tenant quota.
type QuotaConfig struct {
	// Interval is "<n> <unit>", e.g. "1 hour" (default) or "30 days".
	Interval string `json:"interval"`
	// Limits are fixed maxima keyed by QuotaKeys.
	Limits map[string]int64 `json:"limits"`
	// FromLimits maps a quota key to an entitlement limit, overriding Limits.
	FromLimits map[string]string `json:"from_limits"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "url": {"type": "string", "minLength": 1},
    "username": {"type": "string"},
    "password": {"type": "string"},
    "cluster": {"type": "string"},
    "database_engine": {"type": "string"},
    "name_template": {"type": "string", "minLength": 1},
    "user_template": {"type": "string"},
    "password_secret": {"type": "string", "minLength": 16},
    "grants": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1},
    "settings_profile": {
      "type": "object",
      "properties": {
        "settings": {"type": "object", "additionalProperties": {"type": ["number", "string", "boolean"]}},
        "from_limits": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}},
        "lock": {"type": "boolean"}
      },
      "additionalProperties": false
    },
    "quota": {
      "type": "object",
      "properties": {
        "interval": {"type": "string"},
        "limits": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}},
        "from_limits": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}}
      },
      "additionalProperties": false
    },
    "on_deprovision": {"enum": ["delete", "keep", "retain"]},
    "timeout_seconds": {"type": "integer", "minimum": 0}
  },
  "required": ["url", "password_secret"],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg  Config
	name *template.Template
	user *template.Template
	ch   *client
	host sdk.Host
	log  *slog.Logger
	now  func() time.Time
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "clickhouse-tenant",
		Name:         "ClickHouse Tenant Isolation",
		Version:      "0.1.0",
		Description:  "Provisions a ClickHouse database, user, grants and optional settings profile and quota per tenant.",
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
	p.ch = &client{
		url:      p.cfg.URL,
		user:     p.cfg.Username,
		password: p.cfg.Password,
		http:     &http.Client{Timeout: time.Duration(p.cfg.TimeoutSeconds) * time.Second},
	}
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
	if c.URL == "" {
		return errors.New("url is required")
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf("url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("url must be http(s)://host[:port], got %q", c.URL)
	}
	if u.User != nil {
		return errors.New("url must not contain credentials; use username and password")
	}
	if c.Username == "" {
		c.Username = "default"
	}
	if len(c.PasswordSecret) < 16 {
		return errors.New("password_secret is required and must be at least 16 characters")
	}
	if c.Cluster != "" && !clusterRe.MatchString(c.Cluster) {
		return fmt.Errorf("cluster: invalid name %q", c.Cluster)
	}
	if c.DatabaseEngine != "" && (!engineRe.MatchString(c.DatabaseEngine) ||
		strings.Contains(c.DatabaseEngine, "--") || strings.Contains(c.DatabaseEngine, "/*")) {
		return fmt.Errorf("database_engine: invalid engine %q", c.DatabaseEngine)
	}
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDelete
	case DeprovisionDelete, DeprovisionKeep, DeprovisionRetain:
	default:
		return fmt.Errorf("on_deprovision must be delete, keep or retain, got %q", c.OnDeprovision)
	}
	if c.TimeoutSeconds < 0 {
		return fmt.Errorf("timeout_seconds must not be negative, got %d", c.TimeoutSeconds)
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 30
	}
	if c.Grants == nil {
		c.Grants = slices.Clone(DefaultGrants)
	}
	if len(c.Grants) == 0 {
		return errors.New("grants must not be empty")
	}
	for i, g := range c.Grants {
		g = strings.Join(strings.Fields(g), " ")
		if !grantRe.MatchString(g) {
			return fmt.Errorf("grants: %q is not a privilege name", c.Grants[i])
		}
		c.Grants[i] = g
	}
	if err := validateProfile(c.SettingsProfile); err != nil {
		return err
	}
	if err := validateQuota(c.Quota); err != nil {
		return err
	}
	if c.NameTemplate == "" {
		c.NameTemplate = DefaultNameTemplate
	}
	if p.name, err = parseNameTemplate("name_template", c.NameTemplate, reservedDatabases); err != nil {
		return err
	}
	if c.UserTemplate != "" {
		if p.user, err = parseNameTemplate("user_template", c.UserTemplate, reservedUsers); err != nil {
			return err
		}
	} else if _, err := p.target(sample1); err != nil {
		// The database name doubles as user name; check it is not reserved.
		return err
	}
	return nil
}

func validateProfile(pc *ProfileConfig) error {
	if pc == nil {
		return nil
	}
	if pc.Lock == nil {
		lock := true
		pc.Lock = &lock
	}
	for k, v := range pc.Settings {
		if !settingRe.MatchString(k) {
			return fmt.Errorf("settings_profile.settings: invalid setting name %q", k)
		}
		if _, err := settingLiteral(v); err != nil {
			return fmt.Errorf("settings_profile.settings.%s: %w", k, err)
		}
	}
	for k, limit := range pc.FromLimits {
		if !settingRe.MatchString(k) {
			return fmt.Errorf("settings_profile.from_limits: invalid setting name %q", k)
		}
		if limit == "" {
			return fmt.Errorf("settings_profile.from_limits.%s: limit name is empty", k)
		}
	}
	return nil
}

func validateQuota(qc *QuotaConfig) error {
	if qc == nil {
		return nil
	}
	if qc.Interval == "" {
		qc.Interval = DefaultQuotaInterval
	}
	qc.Interval = strings.ToLower(strings.Join(strings.Fields(qc.Interval), " "))
	if !intervalRe.MatchString(qc.Interval) {
		return fmt.Errorf("quota.interval must be \"<n> <second|minute|hour|day|week|month|quarter|year>\", got %q", qc.Interval)
	}
	for k, v := range qc.Limits {
		if !slices.Contains(QuotaKeys, k) {
			return fmt.Errorf("quota.limits: unknown key %q (valid: %s)", k, strings.Join(QuotaKeys, ", "))
		}
		if v < 0 {
			return fmt.Errorf("quota.limits.%s must not be negative", k)
		}
	}
	for k, limit := range qc.FromLimits {
		if !slices.Contains(QuotaKeys, k) {
			return fmt.Errorf("quota.from_limits: unknown key %q (valid: %s)", k, strings.Join(QuotaKeys, ", "))
		}
		if limit == "" {
			return fmt.Errorf("quota.from_limits.%s: limit name is empty", k)
		}
	}
	return nil
}

// settingLiteral renders a settings value as a ClickHouse literal.
func settingLiteral(v any) (string, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return "1", nil
		}
		return "0", nil
	case string:
		return quoteString(x), nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return "", errors.New("must be finite")
		}
		if x == math.Trunc(x) && math.Abs(x) < 1<<63 {
			return strconv.FormatInt(int64(x), 10), nil
		}
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case json.Number:
		if _, err := x.Float64(); err != nil {
			return "", err
		}
		return x.String(), nil
	default:
		return "", fmt.Errorf("unsupported value type %T", v)
	}
}

// Sample tenants used to validate templates at Init.
var (
	sample1 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000001", Slug: "example-one", Name: "Example One"}
	sample2 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000002", Slug: "example-two", Name: "Example Two"}
)

// parseNameTemplate compiles a name template and checks that it renders
// distinct, valid names for two sample tenants.
func parseNameTemplate(field, s string, reserved []string) (*template.Template, error) {
	tmpl, err := template.New(field).Option("missingkey=error").Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	n1, err := renderName(tmpl, sample1, reserved)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	n2, err := renderName(tmpl, sample2, reserved)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if n1 == n2 {
		return nil, fmt.Errorf("%s must depend on the tenant (e.g. {{.Slug}} or {{.ID}})", field)
	}
	return tmpl, nil
}

func renderName(tmpl *template.Template, t sdk.Tenant, reserved []string) (string, error) {
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
		name = name[:maxNameLen-9] + "_" + hex.EncodeToString(sum[:4])
	}
	if slices.Contains(reserved, name) {
		return "", fmt.Errorf("renders the reserved name %q for tenant %s", name, t.ID)
	}
	return name, nil
}

// SanitizeName turns s into a ClickHouse name made of [a-z0-9_]: lowercase,
// other characters replaced by "_", and a leading digit prefixed with "_".
// It does not enforce the length limit, which needs the tenant ID.
func SanitizeName(s string) string { return sanitize(s) }

func sanitize(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out[0] >= '0' && out[0] <= '9' {
		out = "_" + out
	}
	return out
}

// TenantPassword derives the ClickHouse password of a tenant's user: the
// first 32 hex characters of HMAC-SHA256(secret, tenantID). Applications
// that know the secret compute it the same way to connect as the tenant.
func TenantPassword(secret, tenantID string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(tenantID))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// target is what a tenant maps to in ClickHouse. The settings profile and
// quota are named like the user.
type target struct {
	Database string
	User     string
}

func (p *Plugin) target(t sdk.Tenant) (target, error) {
	db, err := renderName(p.name, t, reservedDatabases)
	if err != nil {
		return target{}, fmt.Errorf("name_template: %w", err)
	}
	tg := target{Database: db, User: db}
	if p.user != nil {
		if tg.User, err = renderName(p.user, t, reservedUsers); err != nil {
			return target{}, fmt.Errorf("user_template: %w", err)
		}
	} else if slices.Contains(reservedUsers, db) {
		return target{}, fmt.Errorf("name_template: renders the reserved user name %q; set user_template", db)
	}
	return tg, nil
}

func (p *Plugin) Name() string { return "clickhouse" }

// TenantInfo is the response of GET /tenants/{tenant}. It never includes
// the password.
type TenantInfo struct {
	Database        string `json:"database"`
	User            string `json:"user"`
	URL             string `json:"url"`
	Cluster         string `json:"cluster,omitempty"`
	SettingsProfile string `json:"settings_profile,omitempty"`
	Quota           string `json:"quota,omitempty"`
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
	tg, err := p.target(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info := TenantInfo{Database: tg.Database, User: tg.User, URL: p.cfg.URL, Cluster: p.cfg.Cluster}
	if p.cfg.SettingsProfile != nil {
		info.SettingsProfile = tg.User
	}
	if p.cfg.Quota != nil {
		info.Quota = tg.User
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// Health runs SELECT 1 with the admin credentials.
func (p *Plugin) Health(ctx context.Context) error {
	_, err := p.ch.exec(ctx, "SELECT 1", nil)
	return err
}
