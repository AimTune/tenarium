package mysqltenant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/go-sql-driver/mysql"
)

// migrationLockTimeout is how long (seconds) a Provision waits for a
// concurrent migration run of the same tenant.
const migrationLockTimeout = 60

// migration is one SQL file from migrations_dir.
type migration struct {
	name string
	tmpl *template.Template
}

// loadMigrations reads and parses dir/*.sql in filename order.
func loadMigrations(dir string) ([]migration, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("migrations_dir: %w", err)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		return nil, err
	}
	slices.Sort(paths)
	out := make([]migration, 0, len(paths))
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("migrations_dir: %w", err)
		}
		name := filepath.Base(path)
		if len(name) > 255 {
			return nil, fmt.Errorf("migration %s: file name longer than 255 characters", name)
		}
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
	Database string // backtick-quoted database name
	Name     string // unquoted database name
	User     string // unquoted user name (empty without create_user)
	Account  string // 'user'@'host' (empty without create_user)
	TenantID string
	Slug     string
}

// migrate applies pending migrations as the admin user on a connection
// whose default database is the tenant's. Files are re-read on every call
// so new files are picked up without a restart.
//
// MySQL DDL is not transactional: a file that fails halfway leaves its
// earlier statements applied and is run again in full next time, so
// migrations should be idempotent (IF NOT EXISTS, ...).
func (p *Plugin) migrate(ctx context.Context, t sdk.Tenant, tg target) error {
	if p.cfg.MigrationsDir == "" {
		return nil
	}
	migs, err := loadMigrations(p.cfg.MigrationsDir)
	if err != nil || len(migs) == 0 {
		return err
	}
	data := migrationData{Database: quoteIdent(tg.Database), Name: tg.Database, User: tg.User, TenantID: t.ID, Slug: t.Slug}
	if tg.User != "" {
		if data.Account, err = tg.account(); err != nil {
			return err
		}
	}

	c := p.dsn.Clone()
	c.DBName = tg.Database
	c.MultiStatements = true // a migration file may hold several statements
	connector, err := mysql.NewConnector(c)
	if err != nil {
		return err
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", tg.Database, err)
	}
	defer conn.Close()

	// Serialize concurrent provisioning of the same tenant. Lock names are
	// limited to 64 characters.
	sum := sha256.Sum256([]byte(tg.Database))
	lock := "tenarium_migrate_" + hex.EncodeToString(sum[:16])
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", lock, migrationLockTimeout).Scan(&got); err != nil {
		return fmt.Errorf("migration lock on %s: %w", tg.Database, err)
	}
	if !got.Valid || got.Int64 != 1 {
		return fmt.Errorf("migration lock on %s: timed out", tg.Database)
	}
	defer func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), "DO RELEASE_LOCK(?)", lock) }()

	table := quoteIdent(migrationsTable)
	if _, err := conn.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+table+
		" (name VARCHAR(255) NOT NULL PRIMARY KEY, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"); err != nil {
		return fmt.Errorf("create %s in %s: %w", migrationsTable, tg.Database, err)
	}
	for _, m := range migs {
		var n int
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE name = ?", m.name).Scan(&n); err != nil {
			return fmt.Errorf("migration %s on %s: %w", m.name, tg.Database, err)
		}
		if n > 0 {
			continue
		}
		var script bytes.Buffer
		if err := m.tmpl.Execute(&script, data); err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		if strings.TrimSpace(script.String()) != "" {
			if _, err := conn.ExecContext(ctx, script.String()); err != nil {
				return fmt.Errorf("migration %s on %s: %w", m.name, tg.Database, err)
			}
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO "+table+" (name) VALUES (?)", m.name); err != nil {
			return fmt.Errorf("record migration %s on %s: %w", m.name, tg.Database, err)
		}
	}
	return nil
}
