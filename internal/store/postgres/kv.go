package postgres

import (
	"context"
	"time"
)

func (s *Store) KVGet(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := s.pool.QueryRow(ctx, `SELECT value FROM kv WHERE key = $1`, key).Scan(&v)
	return v, mapErr(err)
}

func (s *Store) KVPut(ctx context.Context, key string, value []byte) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO kv (key, value, updated_at) VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = now()`, key, value)
	return err
}

func (s *Store) KVPutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	tag, err := s.pool.Exec(ctx, `INSERT INTO kv (key, value, updated_at) VALUES ($1, $2, now()) ON CONFLICT (key) DO NOTHING`, key, value)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) KVDelete(ctx context.Context, key string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM kv WHERE key = $1`, key)
	return err
}

func (s *Store) KVKeys(ctx context.Context, prefix string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT key FROM kv WHERE starts_with(key, $1) ORDER BY key`, prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) KVCompareAndSwap(ctx context.Context, key string, old, next []byte) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE kv SET value = $3, updated_at = now() WHERE key = $1 AND value = $2`, key, old, next)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) IncrementRateCounter(ctx context.Context, key string, window, expireBefore time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `INSERT INTO rate_limits (key, window_start, count) VALUES ($1, $2, 1)
		ON CONFLICT (key, window_start) DO UPDATE SET count = rate_limits.count + 1 RETURNING count`, key, window).Scan(&n)
	if err != nil {
		return 0, err
	}
	// Old windows are cleaned up opportunistically by the first request of
	// a new window.
	if n == 1 {
		_, err = s.pool.Exec(ctx, `DELETE FROM rate_limits WHERE window_start < $1`, expireBefore)
	}
	return n, err
}
