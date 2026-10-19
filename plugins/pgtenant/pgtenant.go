// Package pgtenant provisions per-tenant PostgreSQL isolation for the SaaS
// application's data plane (not Tenarium's own database).
//
// Two isolation modes are supported:
//
//   - schema (default): one schema per tenant inside the database named by
//     dsn.
//   - database: one database per tenant in the cluster named by dsn.
//
// The schema or database name comes from name_template (a text/template over
// sdk.Tenant, default "tenant_{{.Slug}}"), sanitized to a lowercase
// identifier of at most 63 bytes. Templates should only use immutable tenant
// fields (ID, Slug), since the name is recomputed on deprovision.
//
// With create_role, a NOLOGIN role of the same name is created and made the
// owner of the schema or database. No credentials are generated or stored:
// applications connect with their own login roles that are granted the
// tenant role (or SET ROLE to it). Migrations then run as that role, so the
// objects they create are owned by it; the admin connection must be allowed
// to SET ROLE to roles it creates (true for superusers).
//
// migrations_dir holds *.sql files applied in filename order on every
// Provision, one transaction per file. Applied files are recorded in
// tenarium_schema_migrations inside the tenant schema or database, so only new
// files run. Files are text/templates with these fields:
//
//	{{.Schema}}   quoted tenant schema ("public" in database mode)
//	{{.Database}} quoted tenant database (empty in schema mode)
//	{{.Name}}     unquoted schema/database name
//	{{.TenantID}} tenant ID (raw, not escaped)
//	{{.Slug}}     tenant slug (raw, not escaped)
//
// on_deprovision chooses what happens when a tenant is deleted: "drop"
// (default) drops the schema/database and role, "keep" leaves everything in
// place, "rename" renames schema/database and role to
// "<name>_deleted_<unix>" so the data can be recovered.
package pgtenant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func init() {
	sdk.Register("postgres-tenant", func() sdk.Plugin { return &Plugin{} })
}

// Isolation modes and deprovision actions.
const (
	ModeSchema   = "schema"
	ModeDatabase = "database"

	DeprovisionDrop   = "drop"
	DeprovisionKeep   = "keep"
	DeprovisionRename = "rename"
)

// DefaultNameTemplate names tenant schemas/databases when name_template is
// unset.
const DefaultNameTemplate = "tenant_{{.Slug}}"

// maxIdentLen is PostgreSQL's NAMEDATALEN-1.
const maxIdentLen = 63

const migrationsTable = "tenarium_schema_migrations"

type Config struct {
	// DSN is an admin connection to the target cluster.
	DSN string `json:"dsn"`
	// Mode is "schema" (default) or "database".
	Mode string `json:"mode"`
	// NameTemplate renders the schema/database name from an sdk.Tenant.
	NameTemplate string `json:"name_template"`
	// CreateRole creates a NOLOGIN role owning the tenant's schema/database.
	CreateRole bool `json:"create_role"`
	// MigrationsDir holds *.sql files applied on Provision.
	MigrationsDir string `json:"migrations_dir"`
	// OnDeprovision is "drop" (default), "keep" or "rename".
	OnDeprovision string `json:"on_deprovision"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "dsn": {"type": "string", "minLength": 1},
    "mode": {"enum": ["schema", "database"]},
    "name_template": {"type": "string", "minLength": 1},
    "create_role": {"type": "boolean"},
    "migrations_dir": {"type": "string"},
    "on_deprovision": {"enum": ["drop", "keep", "rename"]}
  },
  "required": ["dsn"],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg  Config
	name *template.Template
	pool *pgxpool.Pool
	host sdk.Host
	log  *slog.Logger
	now  func() time.Time
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "postgres-tenant",
		Name:         "PostgreSQL Tenant Isolation",
		Version:      "0.1.0",
		Description:  "Provisions a PostgreSQL schema or database (and optional role) per tenant.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(ctx context.Context, r sdk.Registrar) error {
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
	pool, err := pgxpool.New(ctx, p.cfg.DSN)
	if err != nil {
		return fmt.Errorf("dsn: %w", err)
	}
	p.pool = pool
	p.host = r.Host()
	p.log = r.Logger()
	p.now = time.Now
	r.Provisioner(p)
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
	return nil
}

// validate checks and defaults the configuration and compiles the name
// template.
func (p *Plugin) validate() error {
	c := &p.cfg
	if c.DSN == "" {
		return errors.New("dsn is required")
	}
	switch c.Mode {
	case "":
		c.Mode = ModeSchema
	case ModeSchema, ModeDatabase:
	default:
		return fmt.Errorf("mode must be schema or database, got %q", c.Mode)
	}
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDrop
	case DeprovisionDrop, DeprovisionKeep, DeprovisionRename:
	default:
		return fmt.Errorf("on_deprovision must be drop, keep or rename, got %q", c.OnDeprovision)
	}
	if c.NameTemplate == "" {
		c.NameTemplate = DefaultNameTemplate
	}
	tmpl, err := parseNameTemplate(c.NameTemplate)
	if err != nil {
		return err
	}
	p.name = tmpl
	return nil
}

// parseNameTemplate compiles a name template and checks that it renders a
// usable name for a sample tenant.
func parseNameTemplate(s string) (*template.Template, error) {
	tmpl, err := template.New("name").Option("missingkey=error").Parse(s)
	if err != nil {
		return nil, fmt.Errorf("name_template: %w", err)
	}
	sample := sdk.Tenant{ID: "00000000-0000-0000-0000-000000000000", Slug: "example", Name: "Example"}
	if _, err := renderName(tmpl, sample); err != nil {
		return nil, fmt.Errorf("name_template: %w", err)
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
	if len(name) > maxIdentLen {
		// Truncating alone could map two tenants to one name; a hash of the
		// tenant ID keeps shortened names distinct.
		sum := sha256.Sum256([]byte(t.ID))
		name = name[:maxIdentLen-9] + "_" + hex.EncodeToString(sum[:4])
	}
	return name, nil
}

// SanitizeIdent turns s into a lowercase PostgreSQL identifier: characters
// other than [a-z0-9_] become "_", a leading digit gets a "_" prefix and the
// result is cut to 63 bytes. It returns "" if s is empty.
func SanitizeIdent(s string) string {
	return truncate(sanitize(s), maxIdentLen)
}

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

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func quote(name string) string { return pgx.Identifier{name}.Sanitize() }

// target is what a tenant maps to in PostgreSQL.
type target struct {
	Name string // schema or database name
	Role string // owning role; empty without create_role
}

func (p *Plugin) target(t sdk.Tenant) (target, error) {
	name, err := renderName(p.name, t)
	if err != nil {
		return target{}, fmt.Errorf("name_template: %w", err)
	}
	tg := target{Name: name}
	if p.cfg.CreateRole {
		tg.Role = name
	}
	return tg, nil
}

func (p *Plugin) Name() string { return "postgres-" + p.cfg.Mode }

// Provision creates the role, schema or database and applies pending
// migrations. Every step is idempotent.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	if tg.Role != "" {
		if err := p.ensureRole(ctx, tg.Role, t); err != nil {
			return err
		}
	}
	if p.cfg.Mode == ModeDatabase {
		err = p.ensureDatabase(ctx, tg, t)
	} else {
		err = p.ensureSchema(ctx, tg, t)
	}
	if err != nil {
		return err
	}
	return p.migrate(ctx, t, tg)
}

// Every role, schema and database the plugin creates carries a comment
// naming its tenant. Objects that belong to another tenant are never
// adopted on Provision nor touched on Deprovision, so a name clash (or a
// slug reused after on_deprovision: keep) cannot hand one tenant's data to
// another or destroy it.
func ownerMark(t sdk.Tenant) string { return "tenarium tenant " + t.ID }

type objectKind struct {
	ddl     string // keyword for COMMENT ON
	comment string // query returning the comment of the named object
}

var (
	kindRole = objectKind{"ROLE",
		`SELECT shobj_description(oid, 'pg_authid') FROM pg_roles WHERE rolname = $1`}
	kindSchema = objectKind{"SCHEMA",
		`SELECT obj_description(oid, 'pg_namespace') FROM pg_namespace WHERE nspname = $1`}
	kindDatabase = objectKind{"DATABASE",
		`SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname = $1`}
)

// owner returns whether the object exists and its owner mark ("" if
// unmarked).
func (p *Plugin) owner(ctx context.Context, k objectKind, name string) (exists bool, mark string, err error) {
	var c *string
	err = p.pool.QueryRow(ctx, k.comment, name).Scan(&c)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	if c != nil {
		mark = *c
	}
	return true, mark, nil
}

// claim marks an existing object as t's, failing if another tenant owns it.
// Unmarked objects are adopted: they are left behind by a provisioning run
// that stopped between CREATE and COMMENT.
func (p *Plugin) claim(ctx context.Context, k objectKind, name string, t sdk.Tenant) error {
	_, mark, err := p.owner(ctx, k, name)
	if err != nil {
		return err
	}
	want := ownerMark(t)
	switch mark {
	case want:
		return nil
	case "":
		_, err := p.pool.Exec(ctx, "COMMENT ON "+k.ddl+" "+quote(name)+" IS '"+strings.ReplaceAll(want, "'", "''")+"'")
		return err
	default:
		return fmt.Errorf("%s %s already exists and belongs to another tenant (%q)", strings.ToLower(k.ddl), name, mark)
	}
}

// mine reports whether name exists and belongs to t. Unmarked objects
// count as t's so deprovisioning finishes after an interrupted provision.
func (p *Plugin) mine(ctx context.Context, k objectKind, name string, t sdk.Tenant) (bool, error) {
	exists, mark, err := p.owner(ctx, k, name)
	if err != nil || !exists {
		return false, err
	}
	if mark != "" && mark != ownerMark(t) {
		p.log.Warn("not deprovisioning an object owned by another tenant",
			"kind", strings.ToLower(k.ddl), "name", name, "tenant_id", t.ID, "owner", mark)
		return false, nil
	}
	return true, nil
}

func (p *Plugin) exists(ctx context.Context, query, name string) (bool, error) {
	var ok bool
	err := p.pool.QueryRow(ctx, query, name).Scan(&ok)
	return ok, err
}

const (
	roleExists     = `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`
	databaseExists = `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`
	schemaExists   = `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`
)

// ignoreCode returns nil if err is a PostgreSQL error with the given code
// (used to tolerate concurrent creation).
func ignoreCode(err error, code string) error {
	if pe, ok := errors.AsType[*pgconn.PgError](err); ok && pe.Code == code {
		return nil
	}
	return err
}

func (p *Plugin) ensureRole(ctx context.Context, role string, t sdk.Tenant) error {
	ok, err := p.exists(ctx, roleExists, role)
	if err != nil {
		return err
	}
	if !ok {
		_, err = p.pool.Exec(ctx, "CREATE ROLE "+quote(role)+" NOLOGIN")
		if err = ignoreCode(err, "42710"); err != nil { // duplicate_object
			return fmt.Errorf("create role %s: %w", role, err)
		}
	}
	return p.claim(ctx, kindRole, role, t)
}

func (p *Plugin) ensureSchema(ctx context.Context, tg target, t sdk.Tenant) error {
	sql := "CREATE SCHEMA IF NOT EXISTS " + quote(tg.Name)
	if tg.Role != "" {
		sql += " AUTHORIZATION " + quote(tg.Role)
	}
	if _, err := p.pool.Exec(ctx, sql); err != nil {
		return fmt.Errorf("create schema %s: %w", tg.Name, err)
	}
	// Check ownership before touching anything else about the schema.
	if err := p.claim(ctx, kindSchema, tg.Name, t); err != nil {
		return err
	}
	if tg.Role != "" {
		// Repair ownership if the schema predates the role.
		if _, err := p.pool.Exec(ctx, "ALTER SCHEMA "+quote(tg.Name)+" OWNER TO "+quote(tg.Role)); err != nil {
			return fmt.Errorf("alter schema %s owner: %w", tg.Name, err)
		}
	}
	return nil
}

func (p *Plugin) ensureDatabase(ctx context.Context, tg target, t sdk.Tenant) error {
	ok, err := p.exists(ctx, databaseExists, tg.Name)
	if err != nil {
		return err
	}
	if !ok {
		// CREATE DATABASE cannot run inside a transaction; pool.Exec without
		// arguments runs it as a standalone simple-protocol statement.
		sql := "CREATE DATABASE " + quote(tg.Name)
		if tg.Role != "" {
			sql += " OWNER " + quote(tg.Role)
		}
		_, err = p.pool.Exec(ctx, sql)
		if err = ignoreCode(err, "42P04"); err != nil { // duplicate_database
			return fmt.Errorf("create database %s: %w", tg.Name, err)
		}
	}
	if err := p.claim(ctx, kindDatabase, tg.Name, t); err != nil {
		return err
	}
	if tg.Role != "" {
		if _, err := p.pool.Exec(ctx, "ALTER DATABASE "+quote(tg.Name)+" OWNER TO "+quote(tg.Role)); err != nil {
			return fmt.Errorf("alter database %s owner: %w", tg.Name, err)
		}
	}
	return nil
}

// Deprovision applies on_deprovision. A tenant whose schema/database or role
// does not exist is treated as already deprovisioned.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		return nil
	}
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	if p.cfg.OnDeprovision == DeprovisionRename {
		return p.rename(ctx, tg, t)
	}
	return p.drop(ctx, tg, t)
}

func (p *Plugin) dataKind() objectKind {
	if p.cfg.Mode == ModeDatabase {
		return kindDatabase
	}
	return kindSchema
}

func (p *Plugin) drop(ctx context.Context, tg target, t sdk.Tenant) error {
	ok, err := p.mine(ctx, p.dataKind(), tg.Name, t)
	if err != nil {
		return err
	}
	if ok {
		if p.cfg.Mode == ModeDatabase {
			if _, err := p.pool.Exec(ctx, "DROP DATABASE IF EXISTS "+quote(tg.Name)+" WITH (FORCE)"); err != nil {
				return fmt.Errorf("drop database %s: %w", tg.Name, err)
			}
		} else if _, err := p.pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+quote(tg.Name)+" CASCADE"); err != nil {
			return fmt.Errorf("drop schema %s: %w", tg.Name, err)
		}
	}
	if tg.Role == "" {
		return nil
	}
	if ok, err = p.mine(ctx, kindRole, tg.Role, t); err != nil || !ok {
		return err
	}
	// DROP OWNED removes leftover objects and grants in the admin database
	// that would otherwise block DROP ROLE.
	if _, err := p.pool.Exec(ctx, "DROP OWNED BY "+quote(tg.Role)); err != nil {
		return fmt.Errorf("drop owned by %s: %w", tg.Role, err)
	}
	if _, err := p.pool.Exec(ctx, "DROP ROLE IF EXISTS "+quote(tg.Role)); err != nil {
		return fmt.Errorf("drop role %s: %w", tg.Role, err)
	}
	return nil
}

// deletedName returns "<name>_deleted_<unix>", shortening name to fit.
func (p *Plugin) deletedName(name string) string {
	suffix := "_deleted_" + strconv.FormatInt(p.now().Unix(), 10)
	return truncate(name, maxIdentLen-len(suffix)) + suffix
}

func (p *Plugin) rename(ctx context.Context, tg target, t sdk.Tenant) error {
	newName := p.deletedName(tg.Name)
	if p.cfg.Mode == ModeDatabase {
		ok, err := p.mine(ctx, kindDatabase, tg.Name, t)
		if err != nil {
			return err
		}
		if ok {
			// A database with open sessions cannot be renamed.
			if _, err := p.pool.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
				WHERE datname = $1 AND pid <> pg_backend_pid()`, tg.Name); err != nil {
				return fmt.Errorf("terminate sessions on %s: %w", tg.Name, err)
			}
			if _, err := p.pool.Exec(ctx, "ALTER DATABASE "+quote(tg.Name)+" RENAME TO "+quote(newName)); err != nil {
				return fmt.Errorf("rename database %s: %w", tg.Name, err)
			}
		}
	} else {
		ok, err := p.mine(ctx, kindSchema, tg.Name, t)
		if err != nil {
			return err
		}
		if ok {
			if _, err := p.pool.Exec(ctx, "ALTER SCHEMA "+quote(tg.Name)+" RENAME TO "+quote(newName)); err != nil {
				return fmt.Errorf("rename schema %s: %w", tg.Name, err)
			}
		}
	}
	if tg.Role == "" {
		return nil
	}
	// Rename the role too, so a new tenant with the same slug gets a fresh
	// role instead of inheriting ownership of the archived data.
	ok, err := p.mine(ctx, kindRole, tg.Role, t)
	if err != nil || !ok {
		return err
	}
	if _, err := p.pool.Exec(ctx, "ALTER ROLE "+quote(tg.Role)+" RENAME TO "+quote(p.deletedName(tg.Role))); err != nil {
		return fmt.Errorf("rename role %s: %w", tg.Role, err)
	}
	return nil
}

// migration is one SQL file from migrations_dir.
type migration struct {
	name string
	tmpl *template.Template
}

// loadMigrations reads and parses dir/*.sql in filename order.
func loadMigrations(dir string) ([]migration, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("migrations_dir: %w", err)
	}
	slices.Sort(paths)
	out := make([]migration, 0, len(paths))
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("migrations_dir: %w", err)
		}
		name := filepath.Base(path)
		tmpl, err := template.New(name).Option("missingkey=error").Parse(string(b))
		if err != nil {
			return nil, fmt.Errorf("migration %s: %w", name, err)
		}
		out = append(out, migration{name: name, tmpl: tmpl})
	}
	return out, nil
}

// migrationData is the template data of migration files.
type migrationData struct {
	Schema   string
	Database string
	Name     string
	TenantID string
	Slug     string
}

// migrate applies pending migrations. Files are re-read on every call so new
// files are picked up without a restart.
func (p *Plugin) migrate(ctx context.Context, t sdk.Tenant, tg target) error {
	if p.cfg.MigrationsDir == "" {
		return nil
	}
	migs, err := loadMigrations(p.cfg.MigrationsDir)
	if err != nil || len(migs) == 0 {
		return err
	}
	data := migrationData{Name: tg.Name, TenantID: t.ID, Slug: t.Slug}
	schema := tg.Name
	run := func(fn func(pgx.Tx) error) error { return pgx.BeginFunc(ctx, p.pool, fn) }
	if p.cfg.Mode == ModeDatabase {
		schema = "public"
		data.Database = quote(tg.Name)
		cc, err := pgx.ParseConfig(p.cfg.DSN)
		if err != nil {
			return err
		}
		cc.Database = tg.Name
		conn, err := pgx.ConnectConfig(ctx, cc)
		if err != nil {
			return fmt.Errorf("connect to %s: %w", tg.Name, err)
		}
		defer conn.Close(context.Background())
		run = func(fn func(pgx.Tx) error) error { return pgx.BeginFunc(ctx, conn, fn) }
	}
	data.Schema = quote(schema)
	table := data.Schema + "." + quote(migrationsTable)

	for _, m := range migs {
		var sql bytes.Buffer
		if err := m.tmpl.Execute(&sql, data); err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		err := run(func(tx pgx.Tx) error {
			// Serialize concurrent provisioning of the same tenant.
			if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", "tenarium-migrate:"+tg.Name); err != nil {
				return err
			}
			if tg.Role != "" {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+quote(tg.Role)); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, "SET LOCAL search_path TO "+data.Schema); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS "+table+
				" (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"); err != nil {
				return err
			}
			var applied bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+table+" WHERE name = $1)", m.name).Scan(&applied); err != nil || applied {
				return err
			}
			if _, err := tx.Exec(ctx, sql.String()); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO "+table+" (name) VALUES ($1)", m.name)
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s on %s: %w", m.name, tg.Name, err)
		}
	}
	return nil
}

// TenantInfo is the response of GET /tenants/{tenant}.
type TenantInfo struct {
	Mode     string `json:"mode"`
	Schema   string `json:"schema,omitempty"`
	Database string `json:"database,omitempty"`
	Role     string `json:"role,omitempty"`
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
	info := TenantInfo{Mode: p.cfg.Mode, Role: tg.Role}
	if p.cfg.Mode == ModeDatabase {
		info.Database = tg.Name
	} else {
		info.Schema = tg.Name
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// Health pings the target cluster.
func (p *Plugin) Health(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

// Stop closes the connection pool.
func (p *Plugin) Stop(context.Context) error {
	if p.pool != nil {
		p.pool.Close()
	}
	return nil
}
