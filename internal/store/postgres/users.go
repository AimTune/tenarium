package postgres

import (
	"cmp"
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/jackc/pgx/v5"
)

const userCols = `id::text, email, name, status, email_verified, roles, directory, external_id,
	attributes, version, created_at, updated_at, last_login_at`

func scanUser(row pgx.Row) (sdk.User, error) {
	var (
		u            sdk.User
		status       string
		roles, attrs []byte
		lastLogin    *time.Time
	)
	err := row.Scan(&u.ID, &u.Email, &u.Name, &status, &u.EmailVerified, &roles, &u.Directory, &u.ExternalID,
		&attrs, &u.Version, &u.CreatedAt, &u.UpdatedAt, &lastLogin)
	if err != nil {
		return sdk.User{}, mapErr(err)
	}
	u.Status = sdk.UserStatus(status)
	u.CreatedAt, u.UpdatedAt = u.CreatedAt.UTC(), u.UpdatedAt.UTC()
	if lastLogin != nil {
		t := lastLogin.UTC()
		u.LastLoginAt = &t
	}
	return u, errors.Join(unjs(roles, &u.Roles), unjs(attrs, &u.Attributes))
}

// jsList encodes a slice for a jsonb column; nil becomes [].
func jsList(v []string) string {
	if v == nil {
		return "[]"
	}
	return js(v)
}

func getUser(ctx context.Context, q querier, where string, args ...any) (sdk.User, error) {
	return scanUser(q.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE `+where, args...))
}

func (s *Store) GetUser(ctx context.Context, id string) (sdk.User, error) {
	if !isUUID(id) {
		return sdk.User{}, store.ErrNotFound
	}
	return getUser(ctx, s.pool, `id = $1`, id)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (sdk.User, error) {
	return getUser(ctx, s.pool, `lower(email) = lower($1)`, email)
}

func (s *Store) GetUserByExternalID(ctx context.Context, directory, externalID string) (sdk.User, error) {
	if externalID == "" {
		return sdk.User{}, store.ErrNotFound
	}
	return getUser(ctx, s.pool, `directory = $1 AND external_id = $2`, directory, externalID)
}

func (s *Store) ListUsers(ctx context.Context, q store.ListUsersQuery) ([]sdk.User, error) {
	var (
		conds []string
		args  []any
	)
	add := func(cond string, arg any) {
		args = append(args, arg)
		conds = append(conds, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if q.Status != "" {
		add(`status = ?`, string(q.Status))
	}
	if q.Search != "" {
		add(`(email ILIKE ? OR name ILIKE ?)`, "%"+escapeLike(q.Search)+"%")
	}
	if q.After != "" {
		if !isUUID(q.After) {
			return nil, nil
		}
		add(`id > ?`, q.After)
	}
	sql := `SELECT ` + userCols + ` FROM users`
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
	var out []sdk.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func listMembersOfUser(ctx context.Context, q querier, userID string, lock bool) ([]sdk.Member, error) {
	if userID == "" {
		return nil, nil
	}
	sql := `SELECT ` + memberCols + ` FROM members WHERE user_id = $1 ORDER BY id`
	if lock {
		sql += ` FOR UPDATE`
	}
	rows, err := q.Query(ctx, sql, userID)
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

func (s *Store) ListMembershipsOfUser(ctx context.Context, userID string) ([]sdk.Member, error) {
	return listMembersOfUser(ctx, s.pool, userID, false)
}

func (s *Store) GetCredentials(ctx context.Context, userID string) (store.Credentials, error) {
	if !isUUID(userID) {
		return store.Credentials{}, store.ErrNotFound
	}
	var c store.Credentials
	err := s.pool.QueryRow(ctx, `SELECT password_hash, failed_logins, locked_until FROM users WHERE id = $1`, userID).
		Scan(&c.PasswordHash, &c.FailedLogins, &c.LockedUntil)
	return c, mapErr(err)
}

func (s *Store) RecordLoginFailure(ctx context.Context, userID string, maxFailures int, lockFor time.Duration, now time.Time) (bool, error) {
	if !isUUID(userID) {
		return false, store.ErrNotFound
	}
	var locked bool
	err := s.pool.QueryRow(ctx, `
		UPDATE users SET
			failed_logins = CASE WHEN $2 > 0 AND failed_logins + 1 >= $2 THEN 0 ELSE failed_logins + 1 END,
			locked_until  = CASE WHEN $2 > 0 AND failed_logins + 1 >= $2 THEN $3::timestamptz ELSE locked_until END
		WHERE id = $1
		RETURNING $2 > 0 AND failed_logins = 0`, userID, maxFailures, now.Add(lockFor)).Scan(&locked)
	return locked, mapErr(err)
}

func (s *Store) RecordLoginSuccess(ctx context.Context, userID string, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = $2 WHERE id = $1`, userID, now)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) CreateActionToken(ctx context.Context, t store.ActionToken) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO action_tokens (hash, kind, user_id, expires_at, created_at, data) VALUES ($1, $2, $3, $4, $5, $6)`,
		t.Hash, t.Kind, t.UserID, t.ExpiresAt, t.CreatedAt, t.Data)
	return mapErr(err)
}

func (s *Store) ConsumeActionToken(ctx context.Context, hash, kind string, now time.Time) (store.ActionToken, error) {
	t := store.ActionToken{Hash: hash}
	err := s.pool.QueryRow(ctx, `
		UPDATE action_tokens SET used_at = $3
		WHERE hash = $1 AND kind = $2 AND used_at IS NULL AND expires_at > $3
		RETURNING kind, user_id::text, expires_at, created_at, data`, hash, kind, now).
		Scan(&t.Kind, &t.UserID, &t.ExpiresAt, &t.CreatedAt, &t.Data)
	return t, mapErr(err)
}

func (s *Store) CreateRefreshToken(ctx context.Context, t store.RefreshToken) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO refresh_tokens (hash, user_id, tenant_id, family, expires_at, created_at, user_agent, ip, client_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, t.Hash, t.UserID, t.TenantID, t.Family, t.ExpiresAt, t.CreatedAt, t.UserAgent, t.IP, t.ClientID)
	return mapErr(err)
}

func (s *Store) RotateRefreshToken(ctx context.Context, oldHash string, next store.RefreshToken, now time.Time) (store.RefreshToken, error) {
	var (
		old     store.RefreshToken
		reused  bool
		outcome error
	)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var rotatedAt, revokedAt *time.Time
		err := tx.QueryRow(ctx, `SELECT user_id::text, tenant_id, family, expires_at, created_at, rotated_at, revoked_at, user_agent, ip, client_id
			FROM refresh_tokens WHERE hash = $1 FOR UPDATE`, oldHash).
			Scan(&old.UserID, &old.TenantID, &old.Family, &old.ExpiresAt, &old.CreatedAt, &rotatedAt, &revokedAt, &old.UserAgent, &old.IP, &old.ClientID)
		if err != nil {
			return mapErr(err)
		}
		old.Hash = oldHash
		switch {
		case revokedAt != nil || !now.Before(old.ExpiresAt):
			outcome = store.ErrNotFound
			return nil
		case rotatedAt != nil:
			// A rotated token came back: it was copied. Revoke the family
			// and commit that before reporting the reuse.
			reused = true
			_, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $2 WHERE family = $1 AND revoked_at IS NULL`, old.Family, now)
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET rotated_at = $2 WHERE hash = $1`, oldHash, now); err != nil {
			return err
		}
		ua, ip := cmp.Or(next.UserAgent, old.UserAgent), cmp.Or(next.IP, old.IP)
		_, err = tx.Exec(ctx, `INSERT INTO refresh_tokens (hash, user_id, tenant_id, family, expires_at, created_at, user_agent, ip, client_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, next.Hash, old.UserID, old.TenantID, old.Family, next.ExpiresAt, next.CreatedAt, ua, ip, old.ClientID)
		return mapErr(err)
	})
	switch {
	case err != nil:
		return store.RefreshToken{}, err
	case reused:
		return store.RefreshToken{}, store.ErrTokenReused
	case outcome != nil:
		return store.RefreshToken{}, outcome
	}
	return old, nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, hash string) error {
	_, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = now()
		WHERE family = (SELECT family FROM refresh_tokens WHERE hash = $1) AND revoked_at IS NULL`, hash)
	return err
}

func (s *Store) RevokeUserRefreshTokens(ctx context.Context, userID string) error {
	if !isUUID(userID) {
		return nil
	}
	_, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

func (s *Store) ListSigningKeys(ctx context.Context) ([]store.SigningKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, algorithm, private_pem, created_at FROM signing_keys ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.SigningKey
	for rows.Next() {
		var k store.SigningKey
		if err := rows.Scan(&k.ID, &k.Algorithm, &k.PrivatePEM, &k.CreatedAt); err != nil {
			return nil, err
		}
		k.CreatedAt = k.CreatedAt.UTC()
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) AddSigningKey(ctx context.Context, k store.SigningKey) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO signing_keys (id, algorithm, private_pem, created_at) VALUES ($1, $2, $3, $4)`,
		k.ID, k.Algorithm, k.PrivatePEM, k.CreatedAt)
	return mapErr(err)
}

// --- transaction ------------------------------------------------------------

func (t *tx) ListMembersOfUser(ctx context.Context, userID string) ([]sdk.Member, error) {
	return listMembersOfUser(ctx, t.q, userID, true)
}

func (t *tx) GetUser(ctx context.Context, id string) (sdk.User, error) {
	if !isUUID(id) {
		return sdk.User{}, store.ErrNotFound
	}
	return getUser(ctx, t.q, `id = $1 FOR UPDATE`, id)
}

func (t *tx) CreateUser(ctx context.Context, u sdk.User) error {
	_, err := t.q.Exec(ctx, `INSERT INTO users (id, email, name, status, email_verified, roles, directory, external_id,
		attributes, version, created_at, updated_at, last_login_at)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9::jsonb, $10, $11, $12, $13)`,
		u.ID, u.Email, u.Name, string(u.Status), u.EmailVerified, jsList(u.Roles), u.Directory, u.ExternalID,
		js(u.Attributes), u.Version, u.CreatedAt, u.UpdatedAt, u.LastLoginAt)
	return mapErr(err)
}

func (t *tx) UpdateUser(ctx context.Context, u sdk.User, expectedVersion int64) error {
	tag, err := t.q.Exec(ctx, `UPDATE users SET email = $3, name = $4, status = $5, email_verified = $6, roles = $7::jsonb,
		external_id = $8, attributes = $9::jsonb, version = $10, updated_at = $11
		WHERE id = $1 AND version = $2`,
		u.ID, expectedVersion, u.Email, u.Name, string(u.Status), u.EmailVerified, jsList(u.Roles),
		u.ExternalID, js(u.Attributes), u.Version, u.UpdatedAt)
	if err != nil {
		return mapErr(err)
	}
	return t.checkVersioned(ctx, tag, `users`, `id = $1`, u.ID)
}

func (t *tx) DeleteUser(ctx context.Context, id string) error {
	if !isUUID(id) {
		return store.ErrNotFound
	}
	tag, err := t.q.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (t *tx) SetPasswordHash(ctx context.Context, userID, hash string) error {
	tag, err := t.q.Exec(ctx, `UPDATE users SET password_hash = $2, failed_logins = 0, locked_until = NULL WHERE id = $1`, userID, hash)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) DeleteSigningKey(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM signing_keys WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) ListSessions(ctx context.Context, userID string, now time.Time) ([]store.Session, error) {
	if !isUUID(userID) {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT t.family, t.user_id::text, t.tenant_id, t.user_agent, t.ip,
			(SELECT min(f.created_at) FROM refresh_tokens f WHERE f.family = t.family), t.created_at, t.expires_at
		FROM refresh_tokens t
		WHERE t.user_id = $1 AND t.revoked_at IS NULL AND t.rotated_at IS NULL AND t.expires_at > $2
		ORDER BY t.created_at DESC`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Session
	for rows.Next() {
		var x store.Session
		if err := rows.Scan(&x.ID, &x.UserID, &x.TenantID, &x.UserAgent, &x.IP, &x.CreatedAt, &x.LastUsedAt, &x.ExpiresAt); err != nil {
			return nil, err
		}
		x.CreatedAt, x.LastUsedAt, x.ExpiresAt = x.CreatedAt.UTC(), x.LastUsedAt.UTC(), x.ExpiresAt.UTC()
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) RevokeSession(ctx context.Context, userID, sessionID string, now time.Time) error {
	if !isUUID(userID) {
		return store.ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $3
		WHERE family = $2 AND user_id = $1 AND revoked_at IS NULL`, userID, sessionID, now)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) ReplaceSigningKeyPEM(ctx context.Context, id string, old, next []byte) error {
	tag, err := s.pool.Exec(ctx, `UPDATE signing_keys SET private_pem = $3 WHERE id = $1 AND private_pem = $2`, id, old, next)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM signing_keys WHERE id = $1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return store.ErrNotFound
	}
	return store.ErrConflict
}
