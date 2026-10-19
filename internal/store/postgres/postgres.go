// Package postgres implements store.Store on PostgreSQL (13+).
package postgres

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const (
	notifyChannel = "tenarium_events"
	// Arbitrary constants identifying Tenarium's advisory locks.
	lockEvents     int64 = 0x7465_6e61_0001
	lockMigrations int64 = 0x7465_6e61_0002
)

type Store struct {
	pool *pgxpool.Pool
	// read, if set, is a read replica for list queries (UseReadReplica).
	read *pgxpool.Pool
}

var (
	_ store.Store    = (*Store)(nil)
	_ store.Notifier = (*Store)(nil)
)

// Open connects to dsn and applies pending migrations.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: %w", err)
	}
	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error {
	s.pool.Close()
	if s.read != nil {
		s.read.Close()
	}
	return nil
}

// migrate applies embedded migrations in filename order, each in its own
// transaction, under an advisory lock so concurrent instances don't race.
func (s *Store) migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockMigrations); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockMigrations) //nolint:errcheck

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS tenarium_migrations (
		version int PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	files, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	slices.Sort(files)
	for _, f := range files {
		name := strings.TrimPrefix(f, "migrations/")
		version, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("bad migration name %q", name)
		}
		var applied bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenarium_migrations WHERE version=$1)`, version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, err := migrationFS.ReadFile(f)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			_, err := tx.Exec(ctx, `INSERT INTO tenarium_migrations (version, name) VALUES ($1, $2)`, version, name)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// querier is satisfied by both the pool and a transaction.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (s *Store) InTx(ctx context.Context, fn func(tx store.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(t pgx.Tx) error {
		return fn(&tx{q: t})
	})
}

// --- helpers ------------------------------------------------------------------

func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return store.ErrAlreadyExists
	}
	return err
}

// js encodes v as a JSON object for a jsonb column; nil maps become {}.
func js(v any) string {
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return "{}"
	}
	return string(b)
}

func unjs(b []byte, v any) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return json.Unmarshal(b, v)
}

func nullUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// --- tenants ------------------------------------------------------------------

const tenantCols = `id::text, slug, name, COALESCE(parent_id::text, ''), status, status_reason, plan,
	labels, settings, features, limits, version, created_at, updated_at, deleted_at, plan_revision, add_ons, region, billing_anchor, branding, maintenance`

func scanTenant(row pgx.Row) (sdk.Tenant, error) {
	var (
		t                                  sdk.Tenant
		labels, settings, features, limits []byte
		status                             string
		deletedAt                          *time.Time
		anchor                             *time.Time
		branding, maint                    []byte
	)
	err := row.Scan(&t.ID, &t.Slug, &t.Name, &t.ParentID, &status, &t.StatusReason, &t.Plan,
		&labels, &settings, &features, &limits, &t.Version, &t.CreatedAt, &t.UpdatedAt, &deletedAt, &t.PlanRevision, &t.AddOns, &t.Region, &anchor, &branding, &maint)
	if err != nil {
		return sdk.Tenant{}, mapErr(err)
	}
	t.Status = sdk.TenantStatus(status)
	if len(t.AddOns) == 0 {
		t.AddOns = nil
	}
	t.CreatedAt, t.UpdatedAt = t.CreatedAt.UTC(), t.UpdatedAt.UTC()
	if deletedAt != nil {
		d := deletedAt.UTC()
		t.DeletedAt = &d
	}
	if anchor != nil {
		a := anchor.UTC()
		t.BillingAnchor = &a
	}
	if err := errors.Join(unjs(labels, &t.Labels), unjs(settings, &t.Settings),
		unjs(features, &t.Features), unjs(limits, &t.Limits), optUnjs(branding, &t.Branding), optUnjs(maint, &t.Maintenance)); err != nil {
		return sdk.Tenant{}, err
	}
	return t, nil
}

func getTenant(ctx context.Context, q querier, where string, arg any) (sdk.Tenant, error) {
	return scanTenant(q.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE `+where, arg))
}

func (s *Store) GetTenant(ctx context.Context, id string) (sdk.Tenant, error) {
	if !isUUID(id) {
		return sdk.Tenant{}, store.ErrNotFound
	}
	return getTenant(ctx, s.pool, `id = $1`, id)
}

func (s *Store) GetTenantBySlug(ctx context.Context, slug string) (sdk.Tenant, error) {
	return getTenant(ctx, s.pool, `slug = $1 AND status <> 'deleted'`, slug)
}

func (s *Store) ListTenants(ctx context.Context, q store.ListTenantsQuery) ([]sdk.Tenant, error) {
	var (
		conds []string
		args  []any
	)
	add := func(cond string, arg any) {
		args = append(args, arg)
		conds = append(conds, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if !q.IncludeDeleted {
		conds = append(conds, `status <> 'deleted'`)
	}
	if q.Status != "" {
		add(`status = ?`, string(q.Status))
	}
	if q.Plan != "" {
		add(`plan = ?`, q.Plan)
	}
	if q.ParentID != "" {
		if !isUUID(q.ParentID) {
			return nil, nil
		}
		add(`parent_id = ?`, q.ParentID)
	}
	if len(q.Labels) > 0 {
		add(`labels @> ?::jsonb`, js(q.Labels))
	}
	if q.IDs != nil {
		ids := slices.DeleteFunc(slices.Clone(q.IDs), func(id string) bool { return !isUUID(id) })
		add(`id = ANY(?::uuid[])`, ids)
	}
	if q.After != "" {
		if !isUUID(q.After) {
			return nil, nil
		}
		add(`id > ?`, q.After)
	}
	sql := `SELECT ` + tenantCols + ` FROM tenants`
	if len(conds) > 0 {
		sql += ` WHERE ` + strings.Join(conds, " AND ")
	}
	sql += ` ORDER BY id`
	if q.Limit > 0 {
		args = append(args, q.Limit)
		sql += ` LIMIT $` + strconv.Itoa(len(args))
	}
	rows, err := s.reader().Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sdk.Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// --- plans --------------------------------------------------------------------

const planCols = `id, name, description, features, limits, version, created_at, updated_at`

func scanPlan(row pgx.Row) (sdk.Plan, error) {
	var (
		p                sdk.Plan
		features, limits []byte
	)
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &features, &limits, &p.Version, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return sdk.Plan{}, mapErr(err)
	}
	p.CreatedAt, p.UpdatedAt = p.CreatedAt.UTC(), p.UpdatedAt.UTC()
	return p, errors.Join(unjs(features, &p.Features), unjs(limits, &p.Limits))
}

func (s *Store) GetPlan(ctx context.Context, id string) (sdk.Plan, error) {
	return scanPlan(s.pool.QueryRow(ctx, `SELECT `+planCols+` FROM plans WHERE id = $1`, id))
}

func (s *Store) ListPlans(ctx context.Context) ([]sdk.Plan, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+planCols+` FROM plans ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []sdk.Plan{}
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// --- members ------------------------------------------------------------------

const memberCols = `id::text, tenant_id::text, user_id, email, role, status, invited_by, version, created_at, updated_at`

func scanMember(row pgx.Row) (sdk.Member, error) {
	var (
		m      sdk.Member
		status string
	)
	if err := row.Scan(&m.ID, &m.TenantID, &m.UserID, &m.Email, &m.Role, &status, &m.InvitedBy, &m.Version, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return sdk.Member{}, mapErr(err)
	}
	m.Status = sdk.MemberStatus(status)
	m.CreatedAt, m.UpdatedAt = m.CreatedAt.UTC(), m.UpdatedAt.UTC()
	return m, nil
}

func (s *Store) GetMember(ctx context.Context, tenantID, memberID string) (sdk.Member, error) {
	if !isUUID(tenantID) || !isUUID(memberID) {
		return sdk.Member{}, store.ErrNotFound
	}
	return scanMember(s.pool.QueryRow(ctx, `SELECT `+memberCols+` FROM members WHERE tenant_id = $1 AND id = $2`, tenantID, memberID))
}

func (s *Store) ListMembers(ctx context.Context, tenantID string) ([]sdk.Member, error) {
	if !isUUID(tenantID) {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+memberCols+` FROM members WHERE tenant_id = $1 ORDER BY id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sdk.Member
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// --- usage --------------------------------------------------------------------

// --- events, cursors, leases ------------------------------------------------------

func (s *Store) ReadEvents(ctx context.Context, after int64, limit int) ([]sdk.Event, error) {
	sql := `SELECT seq, id::text, type, source, subject, tenant_id, actor, time, data, traceparent, tracestate, dataschema FROM events WHERE seq > $1 ORDER BY seq`
	args := []any{after}
	if limit > 0 {
		sql += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sdk.Event
	for rows.Next() {
		var (
			e    sdk.Event
			data []byte
		)
		if err := rows.Scan(&e.Seq, &e.ID, &e.Type, &e.Source, &e.Subject, &e.TenantID, &e.Actor, &e.Time, &data, &e.TraceParent, &e.TraceState, &e.DataSchema); err != nil {
			return nil, err
		}
		e.Time = e.Time.UTC()
		if len(data) > 0 {
			e.Data = json.RawMessage(data)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) LastEventSeq(ctx context.Context) (int64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(seq), 0) FROM events`).Scan(&seq)
	return seq, err
}

func (s *Store) GetCursor(ctx context.Context, sub string) (int64, bool, error) {
	var seq int64
	err := s.pool.QueryRow(ctx, `SELECT seq FROM cursors WHERE subscription = $1`, sub).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return seq, err == nil, err
}

func (s *Store) SetCursor(ctx context.Context, sub string, seq int64) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO cursors (subscription, seq, updated_at) VALUES ($1, $2, now())
		ON CONFLICT (subscription) DO UPDATE SET seq = GREATEST(cursors.seq, EXCLUDED.seq), updated_at = now()`, sub, seq)
	return err
}

func (s *Store) AcquireLease(ctx context.Context, name, owner string, ttl time.Duration, preferred bool) (bool, error) {
	tag, err := s.pool.Exec(ctx, `INSERT INTO leases (name, owner, expires_at, preferred) VALUES ($1, $2, now() + $3::interval, $4)
		ON CONFLICT (name) DO UPDATE SET owner = EXCLUDED.owner, expires_at = EXCLUDED.expires_at, preferred = EXCLUDED.preferred
		WHERE leases.owner = EXCLUDED.owner OR leases.expires_at < now() OR (EXCLUDED.preferred AND NOT leases.preferred)`,
		name, owner, fmt.Sprintf("%d milliseconds", ttl.Milliseconds()), preferred)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) ReleaseLease(ctx context.Context, name, owner string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM leases WHERE name = $1 AND owner = $2`, name, owner)
	return err
}

// Listen implements store.Notifier with LISTEN/NOTIFY.
func (s *Store) Listen(ctx context.Context, fn func()) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `LISTEN `+notifyChannel); err != nil {
		return err
	}
	for {
		if _, err := conn.Conn().WaitForNotification(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// The connection is in an unknown state; drop it from the pool.
			_ = conn.Conn().Close(context.WithoutCancel(ctx))
			return err
		}
		fn()
	}
}

// --- dead letters -------------------------------------------------------------

func scanDeadLetter(row pgx.Row) (store.DeadLetter, error) {
	var (
		dl  store.DeadLetter
		evt []byte
	)
	if err := row.Scan(&dl.ID, &dl.Subscription, &evt, &dl.Error, &dl.Attempts, &dl.FailedAt); err != nil {
		return store.DeadLetter{}, mapErr(err)
	}
	dl.FailedAt = dl.FailedAt.UTC()
	return dl, json.Unmarshal(evt, &dl.Event)
}

const dlCols = `id::text, subscription, event, error, attempts, failed_at`

func (s *Store) AddDeadLetter(ctx context.Context, dl store.DeadLetter) error {
	evt, err := json.Marshal(dl.Event)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO dead_letters (id, subscription, event, error, attempts, failed_at)
		VALUES ($1, $2, $3::jsonb, $4, $5, $6)`, dl.ID, dl.Subscription, string(evt), dl.Error, dl.Attempts, dl.FailedAt)
	return mapErr(err)
}

func (s *Store) GetDeadLetter(ctx context.Context, id string) (store.DeadLetter, error) {
	if !isUUID(id) {
		return store.DeadLetter{}, store.ErrNotFound
	}
	return scanDeadLetter(s.pool.QueryRow(ctx, `SELECT `+dlCols+` FROM dead_letters WHERE id = $1`, id))
}

func (s *Store) ListDeadLetters(ctx context.Context, sub string, limit int) ([]store.DeadLetter, error) {
	sql := `SELECT ` + dlCols + ` FROM dead_letters WHERE ($1 = '' OR subscription = $1) ORDER BY failed_at, id`
	args := []any{sub}
	if limit > 0 {
		sql += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.DeadLetter
	for rows.Next() {
		dl, err := scanDeadLetter(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dl)
	}
	return out, rows.Err()
}

func (s *Store) DeleteDeadLetter(ctx context.Context, id string) error {
	if !isUUID(id) {
		return store.ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM dead_letters WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

// --- idempotency --------------------------------------------------------------

func (s *Store) GetIdempotency(ctx context.Context, key string) (store.IdempotencyRecord, error) {
	var r store.IdempotencyRecord
	err := s.pool.QueryRow(ctx, `SELECT key, request_hash, status_code, body, created_at FROM idempotency_keys WHERE key = $1`, key).
		Scan(&r.Key, &r.RequestHash, &r.StatusCode, &r.Body, &r.CreatedAt)
	return r, mapErr(err)
}

func (s *Store) PutIdempotency(ctx context.Context, r store.IdempotencyRecord) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO idempotency_keys (key, request_hash, status_code, body, created_at)
		VALUES ($1, $2, $3, $4, $5)`, r.Key, r.RequestHash, r.StatusCode, r.Body, r.CreatedAt)
	return mapErr(err)
}

// --- transaction ----------------------------------------------------------------

type tx struct {
	q querier
}

func (t *tx) GetTenant(ctx context.Context, id string) (sdk.Tenant, error) {
	if !isUUID(id) {
		return sdk.Tenant{}, store.ErrNotFound
	}
	return getTenant(ctx, t.q, `id = $1 FOR UPDATE`, id)
}

func (t *tx) CreateTenant(ctx context.Context, tn sdk.Tenant) error {
	_, err := t.q.Exec(ctx, `INSERT INTO tenants (id, slug, name, parent_id, status, status_reason, plan,
		labels, settings, features, limits, version, created_at, updated_at, deleted_at, plan_revision, add_ons, region, billing_anchor, branding, maintenance)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb, $12, $13, $14, $15, $16, $17, $18, $19, $20::jsonb, $21::jsonb)`,
		tn.ID, tn.Slug, tn.Name, nullUUID(tn.ParentID), string(tn.Status), tn.StatusReason, tn.Plan,
		js(tn.Labels), js(tn.Settings), js(tn.Features), js(tn.Limits), tn.Version, tn.CreatedAt, tn.UpdatedAt, tn.DeletedAt,
		tn.PlanRevision, nonNilStrings(tn.AddOns), tn.Region, tn.BillingAnchor, optJS(tn.Branding), optJS(tn.Maintenance))
	return mapErr(err)
}

func (t *tx) UpdateTenant(ctx context.Context, tn sdk.Tenant, expectedVersion int64) error {
	tag, err := t.q.Exec(ctx, `UPDATE tenants SET name = $3, status = $4, status_reason = $5, plan = $6,
		labels = $7::jsonb, settings = $8::jsonb, features = $9::jsonb, limits = $10::jsonb,
		version = $11, updated_at = $12, deleted_at = $13, plan_revision = $14, add_ons = $15, region = $16, billing_anchor = $17,
		branding = $18::jsonb, maintenance = $19::jsonb
		WHERE id = $1 AND version = $2`,
		tn.ID, expectedVersion, tn.Name, string(tn.Status), tn.StatusReason, tn.Plan,
		js(tn.Labels), js(tn.Settings), js(tn.Features), js(tn.Limits), tn.Version, tn.UpdatedAt, tn.DeletedAt,
		tn.PlanRevision, nonNilStrings(tn.AddOns), tn.Region, tn.BillingAnchor, optJS(tn.Branding), optJS(tn.Maintenance))
	if err != nil {
		return mapErr(err)
	}
	return t.checkVersioned(ctx, tag, `tenants`, `id = $1`, tn.ID)
}

// checkVersioned turns a zero-row versioned update into ErrNotFound or
// ErrConflict.
func (t *tx) checkVersioned(ctx context.Context, tag pgconn.CommandTag, table, where string, args ...any) error {
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := t.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE `+where+`)`, args...).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return store.ErrNotFound
	}
	return store.ErrConflict
}

func (t *tx) CountLiveChildren(ctx context.Context, id string) (int, error) {
	var n int
	err := t.q.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE parent_id = $1 AND status <> 'deleted'`, id).Scan(&n)
	return n, err
}

func (t *tx) CreatePlan(ctx context.Context, p sdk.Plan) error {
	_, err := t.q.Exec(ctx, `INSERT INTO plans (id, name, description, features, limits, version, created_at, updated_at)
		VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8)`,
		p.ID, p.Name, p.Description, js(p.Features), js(p.Limits), p.Version, p.CreatedAt, p.UpdatedAt)
	return mapErr(err)
}

func (t *tx) UpdatePlan(ctx context.Context, p sdk.Plan, expectedVersion int64) error {
	tag, err := t.q.Exec(ctx, `UPDATE plans SET name = $3, description = $4, features = $5::jsonb, limits = $6::jsonb,
		version = $7, updated_at = $8 WHERE id = $1 AND version = $2`,
		p.ID, expectedVersion, p.Name, p.Description, js(p.Features), js(p.Limits), p.Version, p.UpdatedAt)
	if err != nil {
		return mapErr(err)
	}
	return t.checkVersioned(ctx, tag, `plans`, `id = $1`, p.ID)
}

func (t *tx) DeletePlan(ctx context.Context, id string) error {
	tag, err := t.q.Exec(ctx, `DELETE FROM plans WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (t *tx) CountTenantsOnPlan(ctx context.Context, planID string) (int, error) {
	var n int
	err := t.q.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE plan = $1 AND status <> 'deleted'`, planID).Scan(&n)
	return n, err
}

func (t *tx) CreateMember(ctx context.Context, m sdk.Member) error {
	_, err := t.q.Exec(ctx, `INSERT INTO members (id, tenant_id, user_id, email, role, status, invited_by, version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		m.ID, m.TenantID, m.UserID, m.Email, m.Role, string(m.Status), m.InvitedBy, m.Version, m.CreatedAt, m.UpdatedAt)
	return mapErr(err)
}

func (t *tx) UpdateMember(ctx context.Context, m sdk.Member, expectedVersion int64) error {
	tag, err := t.q.Exec(ctx, `UPDATE members SET user_id = $4, email = $5, role = $6, status = $7, version = $8, updated_at = $9
		WHERE tenant_id = $1 AND id = $2 AND version = $3`,
		m.TenantID, m.ID, expectedVersion, m.UserID, m.Email, m.Role, string(m.Status), m.Version, m.UpdatedAt)
	if err != nil {
		return mapErr(err)
	}
	return t.checkVersioned(ctx, tag, `members`, `tenant_id = $1 AND id = $2`, m.TenantID, m.ID)
}

func (t *tx) DeleteMember(ctx context.Context, tenantID, memberID string) error {
	tag, err := t.q.Exec(ctx, `DELETE FROM members WHERE tenant_id = $1 AND id = $2`, tenantID, memberID)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (t *tx) CountMembers(ctx context.Context, tenantID string) (int, error) {
	var n int
	err := t.q.QueryRow(ctx, `SELECT count(*) FROM members WHERE tenant_id = $1`, tenantID).Scan(&n)
	return n, err
}

// AppendEvents takes a transaction-scoped advisory lock before drawing
// sequence numbers. Writers therefore commit in seq order, and a reader that
// has seen seq N can never later observe a commit with a smaller seq — the
// gap problem of naive bigserial outboxes. The lock only serialises the
// short tail of write transactions.
func (t *tx) AppendEvents(ctx context.Context, events ...sdk.Event) ([]sdk.Event, error) {
	if len(events) == 0 {
		return nil, nil
	}
	if _, err := t.q.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockEvents); err != nil {
		return nil, err
	}
	out := make([]sdk.Event, len(events))
	for i, e := range events {
		var data any
		if len(e.Data) > 0 {
			data = string(e.Data)
		}
		err := t.q.QueryRow(ctx, `INSERT INTO events (seq, id, type, source, subject, tenant_id, actor, time, data, traceparent, tracestate, dataschema)
			VALUES (nextval('events_seq'), $1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11) RETURNING seq`,
			e.ID, e.Type, e.Source, e.Subject, e.TenantID, e.Actor, e.Time, data, e.TraceParent, e.TraceState, e.DataSchema).Scan(&e.Seq)
		if err != nil {
			return nil, mapErr(err)
		}
		out[i] = e
	}
	if _, err := t.q.Exec(ctx, `SELECT pg_notify($1, '')`, notifyChannel); err != nil {
		return nil, err
	}
	return out, nil
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// optJS stores a nil pointer as SQL NULL instead of "{}".
func optJS[T any](p *T) any {
	if p == nil {
		return nil
	}
	return js(p)
}

// optUnjs leaves *p nil for NULL.
func optUnjs[T any](b []byte, p **T) error {
	if len(b) == 0 || string(b) == "null" {
		*p = nil
		return nil
	}
	*p = new(T)
	return json.Unmarshal(b, *p)
}

// UseReadReplica sends the list queries of the API (tenants, users, the
// event log and audit trail) to a read replica, to take load off the
// primary in large or multi-region deployments. Those lists may then lag
// behind recent writes by the replication delay; single-object reads,
// writes and everything that enforces limits or orders events stay on the
// primary.
func (s *Store) UseReadReplica(ctx context.Context, dsn string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return fmt.Errorf("postgres read replica: %w", err)
	}
	s.read = pool
	return nil
}

func (s *Store) reader() *pgxpool.Pool {
	if s.read != nil {
		return s.read
	}
	return s.pool
}
