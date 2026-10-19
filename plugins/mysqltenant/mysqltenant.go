// Package mysqltenant provisions a database and a login user per tenant on
// MySQL 8 or MariaDB, for the SaaS application's data plane (not
// Tenarium's own database).
//
// The database name comes from name_template (a text/template over
// sdk.Tenant, default "tenant_{{.Slug}}"), the user name from user_template
// (default: the database name). Both are sanitized to [a-z0-9_]; names
// longer than MySQL's limits (64 characters for databases, 32 for users)
// are shortened and suffixed with a hash of the tenant ID, so two tenants
// never collide through truncation. Templates should only use immutable
// tenant fields (ID, Slug), since names are recomputed on deprovision.
//
// # Credentials
//
// No credential is stored. A tenant user's password is derived from
// password_secret: hex(HMAC-SHA256(password_secret, tenant ID))[:32] (see
// TenantPassword). Applications that know the secret compute it the same
// way. Every Provision resets the password, so rotating password_secret and
// re-provisioning rotates all tenant passwords.
//
// # Ownership
//
// Every database the plugin creates holds a one-row marker table
// _tenarium_owner naming its tenant. Users carry the attribute
// {"tenarium_tenant_id": "<id>"} (CREATE USER ... ATTRIBUTE, MySQL
// 8.0.21+). On servers without user attributes (MariaDB, older MySQL) the
// user is recorded in the database's marker row instead. Resources that
// belong to another tenant are never adopted by Provision nor touched by
// Deprovision. An unmarked database is adopted only when it has no tables
// (what an interrupted Provision leaves behind); an unmarked user is never
// adopted.
//
// # Deprovisioning
//
// on_deprovision chooses what happens when a tenant is deleted:
//
//   - delete (default): the user and the database are dropped.
//   - keep: nothing is touched; the markers stay, so a new tenant with the
//     same slug cannot adopt the data.
//   - retain: the user is dropped (nobody can log in any more) but the
//     database stays; its marker row is stamped with deleted_at, which
//     releases ownership. Provisioning a new tenant whose database name
//     collides with retained data fails until an operator removes it.
package mysqltenant

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/go-sql-driver/mysql"
)

func init() {
	sdk.Register("mysql-tenant", func() sdk.Plugin { return &Plugin{} })
}

// Deprovision actions.
const (
	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"
	DeprovisionRetain = "retain"
)

// DefaultNameTemplate names tenant databases when name_template is unset.
const DefaultNameTemplate = "tenant_{{.Slug}}"

// Defaults.
const (
	DefaultUserHost = "%"
	DefaultCharset  = "utf8mb4"
)

// MySQL identifier limits.
const (
	maxDatabaseLen = 64
	maxUserLen     = 32 // MySQL 8; MariaDB allows 80
)

// minSecretLen is the minimum length of password_secret.
const minSecretLen = 16

// Marker tables inside every tenant database.
const (
	ownerTable      = "_tenarium_owner"
	migrationsTable = "_tenarium_migrations"
)

// AttrTenantID is the user attribute naming the owning tenant.
const AttrTenantID = "tenarium_tenant_id"

// Resource limit options of CREATE/ALTER USER, keyed by their config name.
var resourceOptions = map[string]string{
	"max_queries_per_hour":     "MAX_QUERIES_PER_HOUR",
	"max_updates_per_hour":     "MAX_UPDATES_PER_HOUR",
	"max_connections_per_hour": "MAX_CONNECTIONS_PER_HOUR",
	"max_user_connections":     "MAX_USER_CONNECTIONS",
}

// resourceOrder fixes the order of resource options in statements.
var resourceOrder = []string{"max_queries_per_hour", "max_updates_per_hour", "max_connections_per_hour", "max_user_connections"}

type Config struct {
	// DSN is an admin connection in go-sql-driver/mysql format, e.g.
	// "root:pw@tcp(db:3306)/".
	DSN string `json:"dsn"`
	// NameTemplate renders the database name from an sdk.Tenant.
	NameTemplate string `json:"name_template"`
	// CreateUser creates a login user per tenant (default true).
	CreateUser *bool `json:"create_user"`
	// UserTemplate renders the user name (default: the database name).
	UserTemplate string `json:"user_template"`
	// UserHost is the host part of the user account (default "%").
	UserHost string `json:"user_host"`
	// PasswordSecret derives tenant passwords; required with create_user.
	PasswordSecret string `json:"password_secret"`
	// Privileges granted on `<database>`.* (default ALL PRIVILEGES).
	Privileges []string `json:"privileges"`
	// Charset and Collation of new databases.
	Charset   string `json:"charset"`
	Collation string `json:"collation"`
	// Limits maps a user resource option (max_user_connections, ...) to the
	// entitlement limit providing its value.
	Limits map[string]string `json:"limits"`
	// MigrationsDir holds *.sql files applied on Provision.
	MigrationsDir string `json:"migrations_dir"`
	// OnDeprovision is "delete" (default), "keep" or "retain".
	OnDeprovision string `json:"on_deprovision"`
	// ConnectAddress is the host:port applications use, reported by the
	// tenant route (default: the address of dsn).
	ConnectAddress string `json:"connect_address"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "dsn": {"type": "string", "minLength": 1},
    "name_template": {"type": "string", "minLength": 1},
    "create_user": {"type": "boolean"},
    "user_template": {"type": "string", "minLength": 1},
    "user_host": {"type": "string", "minLength": 1, "maxLength": 255},
    "password_secret": {"type": "string", "minLength": 16},
    "privileges": {"type": "array", "minItems": 1, "items": {"type": "string", "pattern": "^[A-Za-z ]+$"}},
    "charset": {"type": "string", "pattern": "^[A-Za-z0-9_]+$"},
    "collation": {"type": "string", "pattern": "^[A-Za-z0-9_]+$"},
    "limits": {
      "type": "object",
      "properties": {
        "max_queries_per_hour": {"type": "string", "minLength": 1},
        "max_updates_per_hour": {"type": "string", "minLength": 1},
        "max_connections_per_hour": {"type": "string", "minLength": 1},
        "max_user_connections": {"type": "string", "minLength": 1}
      },
      "additionalProperties": false
    },
    "migrations_dir": {"type": "string"},
    "on_deprovision": {"enum": ["delete", "keep", "retain"]},
    "connect_address": {"type": "string"}
  },
  "required": ["dsn"],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg    Config
	dsn    *mysql.Config
	name   *template.Template
	user   *template.Template
	privs  string
	db     *sql.DB
	host   sdk.Host
	log    *slog.Logger
	now    func() time.Time
	attrMu sync.Mutex
	attrs  *bool // whether the server supports user attributes; nil = unknown
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "mysql-tenant",
		Name:         "MySQL Tenant Isolation",
		Version:      "0.1.0",
		Description:  "Provisions a MySQL/MariaDB database and login user per tenant.",
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
	if p.cfg.MigrationsDir != "" {
		if _, err := loadMigrations(p.cfg.MigrationsDir); err != nil {
			return err
		}
	}
	conn, err := mysql.NewConnector(p.adminConfig())
	if err != nil {
		return fmt.Errorf("dsn: %w", err)
	}
	p.db = sql.OpenDB(conn)
	p.db.SetMaxOpenConns(8)
	p.db.SetMaxIdleConns(2)
	p.db.SetConnMaxLifetime(5 * time.Minute)
	p.host = r.Host()
	p.log = r.Logger()
	p.now = time.Now
	r.Provisioner(p)
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
	return nil
}

// adminConfig returns the driver configuration of the admin pool.
func (p *Plugin) adminConfig() *mysql.Config {
	c := p.dsn.Clone()
	// Admin statements are single statements; never allow stacking.
	c.MultiStatements = false
	return c
}

var (
	privilegeRe = regexp.MustCompile(`^[A-Z]+( [A-Z]+)*$`)
	charsetRe   = regexp.MustCompile(`^[a-z0-9_]+$`)
	// userHostRe accepts host names, IP addresses, netmasks and wildcards.
	userHostRe = regexp.MustCompile(`^[A-Za-z0-9.%_:/\-]+$`)
)

// validate checks and defaults the configuration and compiles templates.
func (p *Plugin) validate() error {
	c := &p.cfg
	if c.DSN == "" {
		return errors.New("dsn is required")
	}
	dsn, err := mysql.ParseDSN(c.DSN)
	if err != nil {
		return fmt.Errorf("dsn: %w", err)
	}
	p.dsn = dsn
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDelete
	case DeprovisionDelete, DeprovisionKeep, DeprovisionRetain:
	default:
		return fmt.Errorf("on_deprovision must be delete, keep or retain, got %q", c.OnDeprovision)
	}
	if c.CreateUser == nil {
		yes := true
		c.CreateUser = &yes
	}
	if c.NameTemplate == "" {
		c.NameTemplate = DefaultNameTemplate
	}
	if p.name, err = parseNameTemplate("name_template", c.NameTemplate, maxDatabaseLen); err != nil {
		return err
	}
	if c.Charset == "" {
		c.Charset = DefaultCharset
	}
	c.Charset = strings.ToLower(c.Charset)
	c.Collation = strings.ToLower(c.Collation)
	if !charsetRe.MatchString(c.Charset) {
		return fmt.Errorf("charset %q is invalid", c.Charset)
	}
	if c.Collation != "" && !charsetRe.MatchString(c.Collation) {
		return fmt.Errorf("collation %q is invalid", c.Collation)
	}
	if c.ConnectAddress != "" {
		if _, _, err := net.SplitHostPort(c.ConnectAddress); err != nil {
			return fmt.Errorf("connect_address must be host:port: %w", err)
		}
	}

	if !*c.CreateUser {
		for opt, set := range map[string]bool{
			"user_template":   c.UserTemplate != "",
			"user_host":       c.UserHost != "",
			"password_secret": c.PasswordSecret != "",
			"privileges":      len(c.Privileges) > 0,
			"limits":          len(c.Limits) > 0,
		} {
			if set {
				return fmt.Errorf("%s requires create_user", opt)
			}
		}
		return nil
	}
	if len(c.PasswordSecret) < minSecretLen {
		return fmt.Errorf("password_secret is required with create_user and must be at least %d characters", minSecretLen)
	}
	tmpl := c.UserTemplate
	if tmpl == "" {
		tmpl = c.NameTemplate
	}
	if p.user, err = parseNameTemplate("user_template", tmpl, maxUserLen); err != nil {
		return err
	}
	if c.UserHost == "" {
		c.UserHost = DefaultUserHost
	}
	if !userHostRe.MatchString(c.UserHost) {
		return fmt.Errorf("user_host %q is invalid", c.UserHost)
	}
	if len(c.Privileges) == 0 {
		c.Privileges = []string{"ALL PRIVILEGES"}
	}
	privs := make([]string, len(c.Privileges))
	for i, priv := range c.Privileges {
		priv = strings.Join(strings.Fields(strings.ToUpper(priv)), " ")
		if !privilegeRe.MatchString(priv) {
			return fmt.Errorf("privileges: %q is not a privilege name", c.Privileges[i])
		}
		privs[i] = priv
	}
	p.privs = strings.Join(privs, ", ")
	for opt, limit := range c.Limits {
		if _, ok := resourceOptions[opt]; !ok {
			return fmt.Errorf("limits: unknown option %q", opt)
		}
		if limit == "" {
			return fmt.Errorf("limits.%s: entitlement limit name is required", opt)
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
// distinct names for two sample tenants.
func parseNameTemplate(field, s string, maxLen int) (*template.Template, error) {
	tmpl, err := template.New(field).Option("missingkey=error").Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	n1, err := renderName(tmpl, sample1, maxLen)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	n2, err := renderName(tmpl, sample2, maxLen)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if n1 == n2 {
		return nil, fmt.Errorf("%s must depend on the tenant (e.g. {{.Slug}} or {{.ID}})", field)
	}
	return tmpl, nil
}

// reservedNames are system databases and accounts that a template must
// never render.
var reservedNames = map[string]bool{
	"mysql": true, "information_schema": true, "performance_schema": true, "sys": true,
	"root": true, "mariadb_sys": true, "mysql_sys": true,
}

func renderName(tmpl *template.Template, t sdk.Tenant, maxLen int) (string, error) {
	var b strings.Builder
	if err := tmpl.Execute(&b, t); err != nil {
		return "", err
	}
	name := sanitize(b.String())
	if strings.Trim(name, "_") == "" {
		return "", fmt.Errorf("renders an empty name for tenant %q", t.ID)
	}
	if len(name) > maxLen {
		// Truncating alone could map two tenants to one name; a hash of the
		// tenant ID keeps shortened names distinct.
		sum := sha256.Sum256([]byte(t.ID))
		name = name[:maxLen-9] + "_" + hex.EncodeToString(sum[:4])
	}
	if reservedNames[name] {
		return "", fmt.Errorf("renders the reserved name %q for tenant %q", name, t.ID)
	}
	return name, nil
}

// SanitizeName turns s into a lowercase MySQL name: characters other than
// [a-z0-9_] become "_". It does not enforce length limits, which need the
// tenant ID (see renderName).
func SanitizeName(s string) string { return sanitize(s) }

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// TenantPassword returns the password of a tenant's user: the first 32 hex
// characters of HMAC-SHA256(secret, tenantID). Applications that know the
// secret compute it the same way to connect as the tenant.
func TenantPassword(secret, tenantID string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(tenantID))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// quoteIdent quotes a MySQL identifier with backticks.
func quoteIdent(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

// quoteString returns s as a single-quoted SQL string literal. Backslashes
// and control characters are rejected rather than escaped, because their
// escaping depends on the NO_BACKSLASH_ESCAPES SQL mode; every value the
// plugin quotes comes from a restricted character set anyway.
func quoteString(s string) (string, error) {
	for _, r := range s {
		if r == '\\' || r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("refusing to quote string with backslash or control character")
		}
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'", nil
}

// tenantIDRe restricts tenant IDs embedded in SQL literals (Tenarium IDs are
// UUIDs).
var tenantIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,255}$`)

// target is what a tenant maps to in MySQL.
type target struct {
	Database string
	User     string // empty without create_user
	Host     string // host part of the user account
}

// account returns 'user'@'host'.
func (tg target) account() (string, error) {
	u, err := quoteString(tg.User)
	if err != nil {
		return "", err
	}
	h, err := quoteString(tg.Host)
	if err != nil {
		return "", err
	}
	return u + "@" + h, nil
}

func (p *Plugin) target(t sdk.Tenant) (target, error) {
	if !tenantIDRe.MatchString(t.ID) {
		return target{}, fmt.Errorf("tenant ID %q contains unsupported characters", t.ID)
	}
	db, err := renderName(p.name, t, maxDatabaseLen)
	if err != nil {
		return target{}, fmt.Errorf("name_template: %w", err)
	}
	tg := target{Database: db}
	if !*p.cfg.CreateUser {
		return tg, nil
	}
	if tg.User, err = renderName(p.user, t, maxUserLen); err != nil {
		return target{}, fmt.Errorf("user_template: %w", err)
	}
	if strings.EqualFold(tg.User, p.dsn.User) {
		return target{}, fmt.Errorf("user_template renders the admin user %q", tg.User)
	}
	tg.Host = p.cfg.UserHost
	return tg, nil
}

func (p *Plugin) Name() string { return "mysql" }

// address returns the network and address applications connect to.
func (p *Plugin) address() (network, addr string) {
	if p.cfg.ConnectAddress != "" {
		return "tcp", p.cfg.ConnectAddress
	}
	return p.dsn.Net, p.dsn.Addr
}

// TenantInfo is the response of GET /tenants/{tenant}.
type TenantInfo struct {
	Database string `json:"database"`
	User     string `json:"user,omitempty"`
	UserHost string `json:"user_host,omitempty"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	// DSN is a go-sql-driver/mysql DSN; it includes the password only when
	// revealed.
	DSN      string `json:"dsn"`
	Password string `json:"password,omitempty"`
}

func (p *Plugin) tenantInfo(tg target, password string) TenantInfo {
	network, addr := p.address()
	info := TenantInfo{Database: tg.Database, User: tg.User, UserHost: tg.Host, Host: addr}
	if host, port, err := net.SplitHostPort(addr); err == nil && network == "tcp" {
		info.Host = host
		info.Port, _ = strconv.Atoi(port)
	}
	c := mysql.NewConfig()
	c.Net, c.Addr, c.DBName, c.User, c.Passwd = network, addr, tg.Database, tg.User, password
	info.DSN = c.FormatDSN()
	info.Password = password
	return info
}

// serveTenant returns a tenant's database and user. The password (and a
// DSN including it) is returned only with ?reveal=true to callers allowed
// to update the tenant.
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
	reveal, _ := strconv.ParseBool(r.URL.Query().Get("reveal"))
	if reveal {
		if !*p.cfg.CreateUser {
			http.Error(w, "no tenant user is configured", http.StatusBadRequest)
			return
		}
		if err := p.host.Authorize(ctx, sdk.ActionTenantsUpdate, res); err != nil {
			http.Error(w, "revealing credentials requires tenants:update", http.StatusForbidden)
			return
		}
	}
	tg, err := p.target(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	password := ""
	if reveal {
		password = TenantPassword(p.cfg.PasswordSecret, t.ID)
	}
	w.Header().Set("Content-Type", "application/json")
	if reveal {
		w.Header().Set("Cache-Control", "no-store")
	}
	_ = json.NewEncoder(w).Encode(p.tenantInfo(tg, password))
}

// Health pings the server.
func (p *Plugin) Health(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

// Stop closes the connection pool.
func (p *Plugin) Stop(context.Context) error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}
