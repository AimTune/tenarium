package mysqltenant

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/go-sql-driver/mysql"
)

// MySQL error numbers.
const (
	errCannotUser    = 1396 // ER_CANNOT_USER: CREATE USER on an existing user
	errUnknownDB     = 1049 // ER_BAD_DB_ERROR
	errNoSuchTable   = 1146 // ER_NO_SUCH_TABLE
	errUnknownThread = 1094 // ER_NO_SUCH_THREAD
)

func isMySQLError(err error, numbers ...uint16) bool {
	var me *mysql.MySQLError
	if !errors.As(err, &me) {
		return false
	}
	for _, n := range numbers {
		if me.Number == n {
			return true
		}
	}
	return false
}

// Provision creates or claims the tenant's database and user, applies the
// user's password, resource limits and grants, then runs pending
// migrations. Every step is idempotent.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	limits, err := p.resourceLimits(ctx, t)
	if err != nil {
		return err
	}
	if err := p.ensureDatabase(ctx, tg, t); err != nil {
		return err
	}
	if tg.User != "" {
		if err := p.ensureUser(ctx, tg, t, limits); err != nil {
			return err
		}
	}
	return p.migrate(ctx, t, tg)
}

// Deprovision applies on_deprovision. Resources that do not exist are
// treated as already deprovisioned.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		return nil
	}
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	// The user goes first: without user attributes its ownership is
	// recorded in the database's marker.
	if tg.User != "" {
		if err := p.dropUser(ctx, tg, t); err != nil {
			return err
		}
	}
	if p.cfg.OnDeprovision == DeprovisionRetain {
		return p.releaseDatabase(ctx, tg, t)
	}
	return p.dropDatabase(ctx, tg, t)
}

// resourceLimits returns the user resource options configured in limits
// with their values from the tenant's entitlements. Absent limits mean
// unlimited (0).
func (p *Plugin) resourceLimits(ctx context.Context, t sdk.Tenant) (string, error) {
	if len(p.cfg.Limits) == 0 {
		return "", nil
	}
	e, err := p.host.Entitlements(ctx, t.ID)
	if err != nil {
		return "", fmt.Errorf("entitlements: %w", err)
	}
	var b strings.Builder
	for _, opt := range resourceOrder {
		name, ok := p.cfg.Limits[opt]
		if !ok {
			continue
		}
		v, _ := e.Limit(name)
		v = max(0, min(v, math.MaxUint32))
		b.WriteString(" " + resourceOptions[opt] + " " + strconv.FormatInt(v, 10))
	}
	return b.String(), nil
}

// owner is the marker row of a tenant database.
type owner struct {
	TenantID string
	// User is "user@host" of the tenant user, recorded on servers without
	// user attributes.
	User      sql.NullString
	DeletedAt sql.NullString
}

func ownerSQL(db string) string { return quoteIdent(db) + "." + quoteIdent(ownerTable) }

// readOwner returns the marker of database db, or nil if the database or
// its marker does not exist.
func (p *Plugin) readOwner(ctx context.Context, db string) (*owner, error) {
	var o owner
	err := p.db.QueryRowContext(ctx, "SELECT tenant_id, db_user, deleted_at FROM "+ownerSQL(db)+" WHERE id = 1").
		Scan(&o.TenantID, &o.User, &o.DeletedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows), isMySQLError(err, errNoSuchTable, errUnknownDB):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read owner of database %s: %w", db, err)
	}
	return &o, nil
}

func (p *Plugin) databaseExists(ctx context.Context, db string) (bool, error) {
	var n int
	err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?", db).Scan(&n)
	return n > 0, err
}

// dataTables counts the tables and views of db other than the marker.
func (p *Plugin) dataTables(ctx context.Context, db string) (int, error) {
	var n int
	err := p.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME <> ?", db, ownerTable).Scan(&n)
	return n, err
}

func (p *Plugin) ensureDatabase(ctx context.Context, tg target, t sdk.Tenant) error {
	db := tg.Database
	exists, err := p.databaseExists(ctx, db)
	if err != nil {
		return fmt.Errorf("database %s: %w", db, err)
	}
	if !exists {
		ddl := "CREATE DATABASE IF NOT EXISTS " + quoteIdent(db) + " CHARACTER SET " + p.cfg.Charset
		if p.cfg.Collation != "" {
			ddl += " COLLATE " + p.cfg.Collation
		}
		if _, err := p.db.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("create database %s: %w", db, err)
		}
	}
	// Check ownership before touching anything else in the database.
	o, err := p.readOwner(ctx, db)
	if err != nil {
		return err
	}
	if o != nil {
		return checkOwner(db, o, t)
	}
	// Unmarked databases are adopted only when empty: those are left by a
	// Provision that stopped between CREATE DATABASE and writing the marker.
	n, err := p.dataTables(ctx, db)
	if err != nil {
		return fmt.Errorf("database %s: %w", db, err)
	}
	if n > 0 {
		return fmt.Errorf("database %s already exists, is not empty and is not managed by tenarium", db)
	}
	if _, err := p.db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+ownerSQL(db)+` (
		id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
		tenant_id VARCHAR(255) NOT NULL,
		db_user VARCHAR(512) NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL DEFAULT NULL
	)`); err != nil {
		return fmt.Errorf("create owner marker in %s: %w", db, err)
	}
	//nolint:gosec // G202: ownerSQL quotes the sanitized database name
	if _, err := p.db.ExecContext(ctx, "INSERT IGNORE INTO "+ownerSQL(db)+" (id, tenant_id) VALUES (1, ?)", t.ID); err != nil {
		return fmt.Errorf("write owner marker in %s: %w", db, err)
	}
	// Re-read: a concurrent Provision may have claimed it first.
	if o, err = p.readOwner(ctx, db); err != nil {
		return err
	}
	if o == nil {
		return fmt.Errorf("owner marker of database %s disappeared", db)
	}
	return checkOwner(db, o, t)
}

// checkOwner fails unless marker o says t owns db.
func checkOwner(db string, o *owner, t sdk.Tenant) error {
	switch {
	case o.DeletedAt.Valid:
		return fmt.Errorf("database %s holds data retained from deleted tenant %s (deleted at %s); drop or rename it before provisioning a tenant with this name",
			db, o.TenantID, o.DeletedAt.String)
	case o.TenantID != t.ID:
		return fmt.Errorf("database %s already exists and belongs to another tenant (%s)", db, o.TenantID)
	}
	return nil
}

// userAttributes reports whether the server supports user attributes
// (MySQL 8.0.21+). The answer is cached once known.
func (p *Plugin) userAttributes(ctx context.Context) (bool, error) {
	p.attrMu.Lock()
	defer p.attrMu.Unlock()
	if p.attrs != nil {
		return *p.attrs, nil
	}
	var n int
	if err := p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = 'information_schema' AND TABLE_NAME = 'USER_ATTRIBUTES'`).Scan(&n); err != nil {
		return false, fmt.Errorf("detect user attribute support: %w", err)
	}
	ok := n > 0
	p.attrs = &ok
	return ok, nil
}

func (p *Plugin) userExists(ctx context.Context, tg target) (bool, error) {
	var n int
	err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mysql.user WHERE User = ? AND Host = ?", tg.User, tg.Host).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("user %s@%s: %w", tg.User, tg.Host, err)
	}
	return n > 0, nil
}

// userMark returns the tenarium_tenant_id attribute of the user ("" if
// unset).
func (p *Plugin) userMark(ctx context.Context, tg target) (string, error) {
	var raw sql.NullString
	err := p.db.QueryRowContext(ctx,
		"SELECT ATTRIBUTE FROM information_schema.USER_ATTRIBUTES WHERE USER = ? AND HOST = ?", tg.User, tg.Host).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !raw.Valid) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read attributes of user %s@%s: %w", tg.User, tg.Host, err)
	}
	var attrs map[string]any
	if err := json.Unmarshal([]byte(raw.String), &attrs); err != nil {
		// Non-JSON attributes are not tenarium's.
		return "", nil
	}
	id, _ := attrs[AttrTenantID].(string)
	return id, nil
}

// userKey is how a user is recorded in the database marker.
func userKey(tg target) string { return tg.User + "@" + tg.Host }

// redact removes secret from err's message (server errors may quote the
// statement).
func redact(err error, secret string) error {
	if err == nil || secret == "" || !strings.Contains(err.Error(), secret) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "***"))
}

func (p *Plugin) ensureUser(ctx context.Context, tg target, t sdk.Tenant, limits string) error {
	acct, err := tg.account()
	if err != nil {
		return err
	}
	password := TenantPassword(p.cfg.PasswordSecret, t.ID)
	pw, err := quoteString(password)
	if err != nil {
		return err
	}
	attrs, err := p.userAttributes(ctx)
	if err != nil {
		return err
	}
	exists, err := p.userExists(ctx, tg)
	if err != nil {
		return err
	}
	if attrs {
		if !exists {
			mark, _ := json.Marshal(map[string]string{AttrTenantID: t.ID})
			lit, err := quoteString(string(mark))
			if err != nil {
				return err
			}
			// The attribute is set atomically with the user, so an unmarked
			// user is never the result of an interrupted Provision.
			_, err = p.db.ExecContext(ctx, "CREATE USER "+acct+" IDENTIFIED BY "+pw+" ATTRIBUTE "+lit)
			if err != nil && !isMySQLError(err, errCannotUser) {
				return fmt.Errorf("create user %s: %w", userKey(tg), redact(err, password))
			}
		}
		mark, err := p.userMark(ctx, tg)
		if err != nil {
			return err
		}
		switch mark {
		case t.ID:
		case "":
			return fmt.Errorf("user %s already exists and is not managed by tenarium", userKey(tg))
		default:
			return fmt.Errorf("user %s already exists and belongs to another tenant (%s)", userKey(tg), mark)
		}
	} else {
		// Without user attributes, the user is recorded in the database
		// marker (owned by t: ensureDatabase ran first).
		key := userKey(tg)
		o, err := p.readOwner(ctx, tg.Database)
		if err != nil {
			return err
		}
		if o == nil || o.TenantID != t.ID {
			return fmt.Errorf("owner marker of database %s is missing", tg.Database)
		}
		if !exists {
			// Record the user before creating it, so an interrupted run
			// adopts it next time.
			//nolint:gosec // G202: ownerSQL quotes the sanitized database name
			if _, err := p.db.ExecContext(ctx, "UPDATE "+ownerSQL(tg.Database)+" SET db_user = ? WHERE id = 1 AND tenant_id = ?", key, t.ID); err != nil {
				return fmt.Errorf("record user in %s: %w", tg.Database, err)
			}
			_, err = p.db.ExecContext(ctx, "CREATE USER "+acct+" IDENTIFIED BY "+pw)
			if isMySQLError(err, errCannotUser) {
				// Someone else created it in the meantime; do not claim it.
				//nolint:gosec // G202: ownerSQL quotes the sanitized database name
				_, _ = p.db.ExecContext(ctx, "UPDATE "+ownerSQL(tg.Database)+" SET db_user = NULL WHERE id = 1 AND tenant_id = ?", t.ID)
				return fmt.Errorf("user %s was created concurrently and is not managed by tenarium", key)
			}
			if err != nil {
				return fmt.Errorf("create user %s: %w", key, redact(err, password))
			}
		} else if !o.User.Valid || o.User.String != key {
			return fmt.Errorf("user %s already exists and is not managed by tenarium", key)
		}
	}

	// Reset the password on every run so rotating password_secret works,
	// and apply the current resource limits.
	alter := "ALTER USER " + acct + " IDENTIFIED BY " + pw
	if limits != "" {
		alter += " WITH" + limits
	}
	if _, err := p.db.ExecContext(ctx, alter); err != nil {
		return fmt.Errorf("alter user %s: %w", userKey(tg), redact(err, password))
	}
	if _, err := p.db.ExecContext(ctx, "GRANT "+p.privs+" ON "+quoteIdent(tg.Database)+".* TO "+acct); err != nil {
		return fmt.Errorf("grant on %s to %s: %w", tg.Database, userKey(tg), err)
	}
	return nil
}

// userMine reports whether the tenant user exists and belongs to t.
func (p *Plugin) userMine(ctx context.Context, tg target, t sdk.Tenant) (bool, error) {
	exists, err := p.userExists(ctx, tg)
	if err != nil || !exists {
		return false, err
	}
	attrs, err := p.userAttributes(ctx)
	if err != nil {
		return false, err
	}
	var owner string
	if attrs {
		if owner, err = p.userMark(ctx, tg); err != nil {
			return false, err
		}
	} else {
		o, err := p.readOwner(ctx, tg.Database)
		if err != nil {
			return false, err
		}
		if o != nil && !o.DeletedAt.Valid && o.User.Valid && o.User.String == userKey(tg) {
			owner = o.TenantID
		}
	}
	if owner != t.ID {
		p.log.Warn("not deprovisioning a user not owned by the tenant",
			"user", userKey(tg), "tenant_id", t.ID, "owner", owner)
		return false, nil
	}
	return true, nil
}

func (p *Plugin) dropUser(ctx context.Context, tg target, t sdk.Tenant) error {
	ok, err := p.userMine(ctx, tg, t)
	if err != nil || !ok {
		return err
	}
	acct, err := tg.account()
	if err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, "DROP USER IF EXISTS "+acct); err != nil {
		return fmt.Errorf("drop user %s: %w", userKey(tg), err)
	}
	// DROP USER does not end open sessions.
	p.killSessions(ctx, tg.User)
	return nil
}

// killSessions terminates the connections of user, best effort (it needs
// the PROCESS and CONNECTION_ADMIN privileges).
func (p *Plugin) killSessions(ctx context.Context, user string) {
	rows, err := p.db.QueryContext(ctx, "SELECT ID FROM information_schema.PROCESSLIST WHERE USER = ?", user)
	if err != nil {
		p.log.Warn("list sessions", "user", user, "error", err)
		return
	}
	defer rows.Close()
	var ids []uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		p.log.Warn("list sessions", "user", user, "error", err)
	}
	for _, id := range ids {
		if _, err := p.db.ExecContext(ctx, "KILL CONNECTION "+strconv.FormatUint(id, 10)); err != nil && !isMySQLError(err, errUnknownThread) {
			p.log.Warn("kill session", "user", user, "id", id, "error", err)
		}
	}
}

func (p *Plugin) dropDatabase(ctx context.Context, tg target, t sdk.Tenant) error {
	db := tg.Database
	exists, err := p.databaseExists(ctx, db)
	if err != nil || !exists {
		return err
	}
	o, err := p.readOwner(ctx, db)
	if err != nil {
		return err
	}
	switch {
	case o != nil && o.TenantID != t.ID:
		p.log.Warn("not deprovisioning a database owned by another tenant",
			"database", db, "tenant_id", t.ID, "owner", o.TenantID)
		return nil
	case o == nil:
		// Unmarked: only an empty database (an interrupted Provision) is
		// removed; unmarked data is never destroyed.
		n, err := p.dataTables(ctx, db)
		if err != nil {
			return err
		}
		if n > 0 {
			p.log.Warn("not deprovisioning an unmarked, non-empty database", "database", db, "tenant_id", t.ID)
			return nil
		}
	}
	if _, err := p.db.ExecContext(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(db)); err != nil {
		return fmt.Errorf("drop database %s: %w", db, err)
	}
	return nil
}

// releaseDatabase keeps the database but stamps its marker with
// deleted_at, which releases ownership.
func (p *Plugin) releaseDatabase(ctx context.Context, tg target, t sdk.Tenant) error {
	db := tg.Database
	o, err := p.readOwner(ctx, db)
	if err != nil || o == nil {
		return err
	}
	if o.TenantID != t.ID {
		p.log.Warn("not retaining a database owned by another tenant",
			"database", db, "tenant_id", t.ID, "owner", o.TenantID)
		return nil
	}
	if o.DeletedAt.Valid {
		return nil
	}
	//nolint:gosec // G202: ownerSQL quotes the sanitized database name
	if _, err := p.db.ExecContext(ctx, "UPDATE "+ownerSQL(db)+
		" SET deleted_at = CURRENT_TIMESTAMP WHERE id = 1 AND tenant_id = ? AND deleted_at IS NULL", t.ID); err != nil {
		return fmt.Errorf("release database %s: %w", db, err)
	}
	return nil
}
