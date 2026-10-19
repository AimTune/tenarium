package certs

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// issuance lock: a best-effort, KV-based mutual exclusion so that only one
// replica runs the ACME flow for a given certificate at a time. It is
// best-effort because:
//
//   - a lock older than its TTL is considered abandoned (holder crashed) and
//     is broken with Delete + PutIfAbsent, which is not atomic: two replicas
//     breaking the same stale lock at the same moment may both win;
//   - release compares the owner with Get then Delete, which is not atomic
//     either (it can only delete a lock that expired and was re-taken in
//     between, i.e. after the TTL — set LockTTL well above issuance time);
//   - waiters give up after Config.LockWait and issue themselves.
//
// None of this affects correctness: the worst case is a duplicate issuance,
// which is wasteful (it counts against CA rate limits) but harmless — the last
// certificate written to the cache wins and both are valid.
type lockValue struct {
	Owner   string    `json:"owner"`
	Expires time.Time `json:"expires"`
}

func lockKey(prefix, name string) string { return prefix + "lock/" + name }

// tryLock attempts to take the lock once. It reports whether we hold it.
func (m *Manager) tryLock(ctx context.Context, key string) (bool, error) {
	val, _ := json.Marshal(lockValue{Owner: m.id, Expires: m.now().Add(m.cfg.LockTTL)})
	ok, err := m.kv.PutIfAbsent(ctx, key, val)
	if err != nil || ok {
		return ok, err
	}
	cur, err := m.kv.Get(ctx, key)
	if errors.Is(err, ErrNotFound) { // released meanwhile
		return m.kv.PutIfAbsent(ctx, key, val)
	}
	if err != nil {
		return false, err
	}
	var lv lockValue
	if json.Unmarshal(cur, &lv) == nil && m.now().Before(lv.Expires) {
		return lv.Owner == m.id, nil
	}
	// Stale or garbage: break it.
	if err := m.kv.Delete(ctx, key); err != nil {
		return false, err
	}
	return m.kv.PutIfAbsent(ctx, key, val)
}

// lockHeld reports whether a live (non-expired) lock exists under key.
func (m *Manager) lockHeld(ctx context.Context, key string) bool {
	cur, err := m.kv.Get(ctx, key)
	if err != nil {
		return false
	}
	var lv lockValue
	return json.Unmarshal(cur, &lv) == nil && m.now().Before(lv.Expires)
}

func (m *Manager) unlock(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cur, err := m.kv.Get(ctx, key)
	if err != nil {
		return
	}
	var lv lockValue
	if json.Unmarshal(cur, &lv) == nil && lv.Owner != m.id {
		return
	}
	_ = m.kv.Delete(ctx, key)
}
