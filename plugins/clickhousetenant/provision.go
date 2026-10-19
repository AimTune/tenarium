package clickhousetenant

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// ownerMark is the database comment of a tenant's database.
func ownerMark(t sdk.Tenant) string { return markerPrefix + t.ID }

// retainedMark is the database comment of a retained database.
func retainedMark(t sdk.Tenant, at time.Time) string {
	return retainedPrefix + t.ID + " deleted-at=" + at.UTC().Format(time.RFC3339)
}

// dbState is the ownership state of a tenant's database name.
type dbState int

const (
	dbMissing dbState = iota
	dbMine
	dbRetainedMine
	dbUnmarked
	dbForeign
)

// onCluster returns " ON CLUSTER '<cluster>'" or "".
func (p *Plugin) onCluster() string {
	if p.cfg.Cluster == "" {
		return ""
	}
	return " ON CLUSTER " + quoteString(p.cfg.Cluster)
}

// databaseComment returns whether the database exists and its comment.
func (p *Plugin) databaseComment(ctx context.Context, name string) (exists bool, comment string, err error) {
	rows, err := queryRows[struct {
		Comment string `json:"comment"`
	}](ctx, p.ch, "SELECT comment FROM system.databases WHERE name = {name:String}", map[string]string{"name": name})
	if err != nil || len(rows) == 0 {
		return false, "", err
	}
	return true, rows[0].Comment, nil
}

func (p *Plugin) dbState(ctx context.Context, name string, t sdk.Tenant) (dbState, string, error) {
	exists, comment, err := p.databaseComment(ctx, name)
	switch {
	case err != nil:
		return 0, "", err
	case !exists:
		return dbMissing, "", nil
	case comment == ownerMark(t):
		return dbMine, comment, nil
	case strings.HasPrefix(comment, retainedPrefix+t.ID+" "):
		return dbRetainedMine, comment, nil
	case comment == "":
		return dbUnmarked, "", nil
	default:
		return dbForeign, comment, nil
	}
}

// codeSyntaxError is ClickHouse's SYNTAX_ERROR.
const codeSyntaxError = 62

// setComment rewrites a database comment. Servers without ALTER DATABASE
// ... MODIFY COMMENT (e.g. 23.8) answer with a syntax error, reported with
// a hint: adopting unmarked databases and on_deprovision: retain need a
// newer ClickHouse.
func (p *Plugin) setComment(ctx context.Context, db, comment string) error {
	q := "ALTER DATABASE " + quoteIdent(db) + p.onCluster() + " MODIFY COMMENT " + quoteString(comment)
	_, err := p.ch.exec(ctx, q, nil)
	if ce, ok := errors.AsType[*Error](err); ok && ce.Code == codeSyntaxError {
		return fmt.Errorf("this ClickHouse version cannot change database comments (ALTER DATABASE ... MODIFY COMMENT); "+
			"adopting unmarked databases and on_deprovision: retain need a newer server: %w", err)
	}
	return err
}

// databaseEmpty reports whether the database has no tables.
func (p *Plugin) databaseEmpty(ctx context.Context, name string) (bool, error) {
	rows, err := queryRows[struct {
		Name string `json:"name"`
	}](ctx, p.ch, "SELECT name FROM system.tables WHERE database = {db:String} LIMIT 1", map[string]string{"db": name})
	return len(rows) == 0, err
}

// userDefaultDatabase returns whether the user exists and its default
// database.
func (p *Plugin) userDefaultDatabase(ctx context.Context, name string) (exists bool, db string, err error) {
	rows, err := queryRows[struct {
		DefaultDatabase string `json:"default_database"`
	}](ctx, p.ch, "SELECT default_database FROM system.users WHERE name = {name:String}", map[string]string{"name": name})
	if err != nil || len(rows) == 0 {
		return false, "", err
	}
	return true, rows[0].DefaultDatabase, nil
}

// appliesTo returns whether the settings profile or quota (table is
// system.settings_profiles or system.quotas) exists and whom it applies to.
func (p *Plugin) appliesTo(ctx context.Context, table, name string) (exists bool, to []string, err error) {
	rows, err := queryRows[struct {
		ApplyToAll  any      `json:"apply_to_all"`
		ApplyToList []string `json:"apply_to_list"`
	}](ctx, p.ch, "SELECT apply_to_all, apply_to_list FROM "+table+" WHERE name = {name:String}", map[string]string{"name": name})
	if err != nil || len(rows) == 0 {
		return false, nil, err
	}
	if v := fmt.Sprint(rows[0].ApplyToAll); v == "1" || v == "true" {
		return true, []string{"ALL"}, nil
	}
	return true, rows[0].ApplyToList, nil
}

// Provision creates or claims the tenant's database, creates or updates its
// user (password, default database, grants) and applies the settings
// profile and quota. Every step is idempotent.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	if err := p.ensureDatabase(ctx, tg, t); err != nil {
		return err
	}
	if err := p.ensureUser(ctx, tg, t); err != nil {
		return err
	}
	var limits map[string]int64
	if (p.cfg.SettingsProfile != nil && len(p.cfg.SettingsProfile.FromLimits) > 0) ||
		(p.cfg.Quota != nil && len(p.cfg.Quota.FromLimits) > 0) {
		e, err := p.host.Entitlements(ctx, t.ID)
		if err != nil {
			return fmt.Errorf("entitlements: %w", err)
		}
		limits = e.Limits
	}
	if p.cfg.SettingsProfile != nil {
		if err := p.ensureProfile(ctx, tg, limits); err != nil {
			return err
		}
	}
	if p.cfg.Quota != nil {
		if err := p.ensureQuota(ctx, tg, limits); err != nil {
			return err
		}
	}
	return nil
}

func (p *Plugin) ensureDatabase(ctx context.Context, tg target, t sdk.Tenant) error {
	state, comment, err := p.dbState(ctx, tg.Database, t)
	if err != nil {
		return fmt.Errorf("database %s: %w", tg.Database, err)
	}
	if state == dbMissing {
		// The marker is part of CREATE, so the database is never left
		// unmarked. IF NOT EXISTS tolerates a concurrent creation, whose
		// marker is checked below.
		q := "CREATE DATABASE IF NOT EXISTS " + quoteIdent(tg.Database) + p.onCluster()
		if p.cfg.DatabaseEngine != "" {
			q += " ENGINE = " + p.cfg.DatabaseEngine
		}
		q += " COMMENT " + quoteString(ownerMark(t))
		if _, err := p.ch.exec(ctx, q, nil); err != nil {
			return fmt.Errorf("create database %s: %w", tg.Database, err)
		}
		if state, comment, err = p.dbState(ctx, tg.Database, t); err != nil {
			return fmt.Errorf("database %s: %w", tg.Database, err)
		}
	}
	switch state {
	case dbMine:
		return nil
	case dbUnmarked:
		empty, err := p.databaseEmpty(ctx, tg.Database)
		if err != nil {
			return fmt.Errorf("database %s: %w", tg.Database, err)
		}
		if !empty {
			return fmt.Errorf("database %s already exists, is not managed by tenarium and is not empty; not adopting it", tg.Database)
		}
		if err := p.setComment(ctx, tg.Database, ownerMark(t)); err != nil {
			return fmt.Errorf("claim database %s: %w", tg.Database, err)
		}
		p.log.Info("adopted empty unmarked database", "database", tg.Database, "tenant_id", t.ID)
		return nil
	case dbRetainedMine:
		return fmt.Errorf("database %s holds data retained after this tenant was deprovisioned (%q); remove or rename it first", tg.Database, comment)
	case dbMissing:
		return fmt.Errorf("database %s was not created", tg.Database)
	default:
		return fmt.Errorf("database %s already exists and belongs to someone else (comment %q)", tg.Database, comment)
	}
}

func (p *Plugin) ensureUser(ctx context.Context, tg target, t sdk.Tenant) error {
	exists, defaultDB, err := p.userDefaultDatabase(ctx, tg.User)
	if err != nil {
		return fmt.Errorf("user %s: %w", tg.User, err)
	}
	auth := " IDENTIFIED WITH sha256_password BY " + quoteString(TenantPassword(p.cfg.PasswordSecret, t.ID)) +
		" DEFAULT DATABASE " + quoteIdent(tg.Database)
	if !exists {
		q := "CREATE USER IF NOT EXISTS " + quoteIdent(tg.User) + p.onCluster() + auth
		if _, err := p.ch.exec(ctx, q, nil); err != nil {
			return fmt.Errorf("create user %s: %w", tg.User, err)
		}
		// A concurrently created user is only ours if it points at our
		// database.
		if exists, defaultDB, err = p.userDefaultDatabase(ctx, tg.User); err != nil {
			return fmt.Errorf("user %s: %w", tg.User, err)
		}
		if !exists {
			return fmt.Errorf("user %s was not created", tg.User)
		}
	}
	if defaultDB != tg.Database {
		return fmt.Errorf("user %s already exists with default database %q, not the tenant database %s; not taking it over", tg.User, defaultDB, tg.Database)
	}
	// Re-apply the password so a changed password_secret rotates it.
	if _, err := p.ch.exec(ctx, "ALTER USER "+quoteIdent(tg.User)+p.onCluster()+auth, nil); err != nil {
		return fmt.Errorf("alter user %s: %w", tg.User, err)
	}
	q := "GRANT" + p.onCluster() + " " + strings.Join(p.cfg.Grants, ", ") + " ON " + quoteIdent(tg.Database) + ".* TO " +
		quoteIdent(tg.User) + " WITH REPLACE OPTION"
	if _, err := p.ch.exec(ctx, q, nil); err != nil {
		return fmt.Errorf("grant on %s to %s: %w", tg.Database, tg.User, err)
	}
	return nil
}

// checkAppliesTo fails unless the profile/quota is missing or applies only
// to user (or to nobody, left over after its user was dropped).
func (p *Plugin) checkAppliesTo(ctx context.Context, kind, table, name, user string) error {
	exists, to, err := p.appliesTo(ctx, table, name)
	if err != nil {
		return fmt.Errorf("%s %s: %w", kind, name, err)
	}
	if exists && !ownsApply(to, user) {
		return fmt.Errorf("%s %s already exists and applies to %v, not only to user %s; not taking it over", kind, name, to, user)
	}
	return nil
}

func ownsApply(to []string, user string) bool {
	return len(to) == 0 || (len(to) == 1 && to[0] == user)
}

// resolve merges fixed values with entitlement limits (which win).
func resolve[V any](fixed map[string]V, from map[string]string, limits map[string]int64, conv func(int64) V) map[string]V {
	out := maps.Clone(fixed)
	if out == nil {
		out = map[string]V{}
	}
	for key, limit := range from {
		if v, ok := limits[limit]; ok {
			out[key] = conv(v)
		}
	}
	return out
}

func (p *Plugin) ensureProfile(ctx context.Context, tg target, limits map[string]int64) error {
	pc := p.cfg.SettingsProfile
	if err := p.checkAppliesTo(ctx, "settings profile", "system.settings_profiles", tg.User, tg.User); err != nil {
		return err
	}
	settings := resolve(pc.Settings, pc.FromLimits, limits, func(v int64) any { return v })
	q := "CREATE SETTINGS PROFILE OR REPLACE " + quoteIdent(tg.User) + p.onCluster()
	if len(settings) > 0 {
		var parts []string
		for _, k := range slices.Sorted(maps.Keys(settings)) {
			lit, err := settingLiteral(settings[k])
			if err != nil {
				return fmt.Errorf("settings_profile.%s: %w", k, err)
			}
			part := k + " = " + lit
			if *pc.Lock {
				part += " READONLY"
			}
			parts = append(parts, part)
		}
		q += " SETTINGS " + strings.Join(parts, ", ")
	}
	q += " TO " + quoteIdent(tg.User)
	if _, err := p.ch.exec(ctx, q, nil); err != nil {
		return fmt.Errorf("settings profile %s: %w", tg.User, err)
	}
	return nil
}

func (p *Plugin) ensureQuota(ctx context.Context, tg target, limits map[string]int64) error {
	qc := p.cfg.Quota
	if err := p.checkAppliesTo(ctx, "quota", "system.quotas", tg.User, tg.User); err != nil {
		return err
	}
	maxima := resolve(qc.Limits, qc.FromLimits, limits, func(v int64) int64 { return v })
	q := "CREATE QUOTA OR REPLACE " + quoteIdent(tg.User) + p.onCluster() + " FOR INTERVAL " + qc.Interval
	if len(maxima) == 0 {
		// Unlimited tenant: still track usage (visible in system.quotas_usage).
		q += " TRACKING ONLY"
	} else {
		var parts []string
		for _, k := range slices.Sorted(maps.Keys(maxima)) {
			parts = append(parts, fmt.Sprintf("%s = %d", k, maxima[k]))
		}
		q += " MAX " + strings.Join(parts, ", ")
	}
	q += " TO " + quoteIdent(tg.User)
	if _, err := p.ch.exec(ctx, q, nil); err != nil {
		return fmt.Errorf("quota %s: %w", tg.User, err)
	}
	return nil
}

// Deprovision applies on_deprovision. A tenant whose database and user do
// not exist is treated as already deprovisioned.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		return nil
	}
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	state, comment, err := p.dbState(ctx, tg.Database, t)
	if err != nil {
		return fmt.Errorf("database %s: %w", tg.Database, err)
	}
	switch state {
	case dbUnmarked, dbForeign:
		p.log.Warn("not deprovisioning a database tenarium does not own for this tenant",
			"database", tg.Database, "tenant_id", t.ID, "comment", comment)
		return nil
	}
	// Access objects first, the database (holding the marker) last.
	if err := p.dropAccess(ctx, tg, t); err != nil {
		return err
	}
	switch {
	case state != dbMine:
		return nil
	case p.cfg.OnDeprovision == DeprovisionRetain:
		if err := p.setComment(ctx, tg.Database, retainedMark(t, p.now())); err != nil {
			return fmt.Errorf("retain database %s: %w", tg.Database, err)
		}
		return nil
	default:
		if _, err := p.ch.exec(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(tg.Database)+p.onCluster()+" SYNC", nil); err != nil {
			return fmt.Errorf("drop database %s: %w", tg.Database, err)
		}
		return nil
	}
}

// dropAccess drops the tenant's quota, settings profile and user, but only
// if the user is the tenant's (its default database is the tenant
// database) and the profile and quota apply to that user only.
func (p *Plugin) dropAccess(ctx context.Context, tg target, t sdk.Tenant) error {
	exists, defaultDB, err := p.userDefaultDatabase(ctx, tg.User)
	if err != nil {
		return fmt.Errorf("user %s: %w", tg.User, err)
	}
	if exists && defaultDB != tg.Database {
		p.log.Warn("not dropping a user that does not belong to the tenant",
			"user", tg.User, "default_database", defaultDB, "tenant_id", t.ID)
		return nil
	}
	for _, obj := range []struct{ kind, table, ddl string }{
		{"quota", "system.quotas", "QUOTA"},
		{"settings profile", "system.settings_profiles", "SETTINGS PROFILE"},
	} {
		found, to, err := p.appliesTo(ctx, obj.table, tg.User)
		if err != nil {
			return fmt.Errorf("%s %s: %w", obj.kind, tg.User, err)
		}
		if !found {
			continue
		}
		if !ownsApply(to, tg.User) {
			p.log.Warn("not dropping a "+obj.kind+" that applies to others", "name", tg.User, "applies_to", to, "tenant_id", t.ID)
			continue
		}
		if _, err := p.ch.exec(ctx, "DROP "+obj.ddl+" IF EXISTS "+quoteIdent(tg.User)+p.onCluster(), nil); err != nil {
			return fmt.Errorf("drop %s %s: %w", obj.kind, tg.User, err)
		}
	}
	if exists {
		if _, err := p.ch.exec(ctx, "DROP USER IF EXISTS "+quoteIdent(tg.User)+p.onCluster(), nil); err != nil {
			return fmt.Errorf("drop user %s: %w", tg.User, err)
		}
	}
	return nil
}
