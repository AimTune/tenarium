package certs

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
)

// ErrNotFound is returned by KV.Get when the key does not exist.
var ErrNotFound = errors.New("certs: key not found")

// KV is the shared key/value store certificates, the ACME account key,
// in-flight challenge tokens and issuance locks are kept in. A database-backed
// implementation lets every replica serve and renew the same certificates.
//
// Implementations must be safe for concurrent use. Delete of a missing key is
// not an error.
type KV interface {
	// Get returns the value stored under key, or ErrNotFound.
	Get(ctx context.Context, key string) ([]byte, error)
	// Put creates or replaces the value stored under key.
	Put(ctx context.Context, key string, data []byte) error
	// PutIfAbsent stores data under key only if the key does not exist yet,
	// atomically. It reports whether the value was written. It backs the
	// best-effort issuance lock (for SQL: INSERT ... ON CONFLICT DO NOTHING).
	PutIfAbsent(ctx context.Context, key string, data []byte) (bool, error)
	// Delete removes key. Deleting a missing key returns nil.
	Delete(ctx context.Context, key string) error
}

// MemKV is an in-memory KV for tests and single-process development setups.
// Its zero value is ready to use.
type MemKV struct {
	mu sync.Mutex
	m  map[string][]byte
}

// NewMemKV returns an empty in-memory KV.
func NewMemKV() *MemKV { return &MemKV{} }

func (k *MemKV) Get(_ context.Context, key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[key]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (k *MemKV) Put(_ context.Context, key string, data []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil {
		k.m = make(map[string][]byte)
	}
	k.m[key] = append([]byte(nil), data...)
	return nil
}

func (k *MemKV) PutIfAbsent(_ context.Context, key string, data []byte) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.m[key]; ok {
		return false, nil
	}
	if k.m == nil {
		k.m = make(map[string][]byte)
	}
	k.m[key] = append([]byte(nil), data...)
	return true, nil
}

func (k *MemKV) Delete(_ context.Context, key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, key)
	return nil
}

// Keys returns the stored keys starting with prefix, sorted. Handy in tests.
func (k *MemKV) Keys(prefix string) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for key := range k.m {
		if strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}
