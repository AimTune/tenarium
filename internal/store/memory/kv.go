package memory

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func (s *Store) KVGet(_ context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.kv[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	return slices.Clone(v), nil
}

func (s *Store) KVPut(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kv[key] = slices.Clone(value)
	return nil
}

func (s *Store) KVPutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.kv[key]; ok {
		return false, nil
	}
	s.kv[key] = slices.Clone(value)
	return true, nil
}

func (s *Store) KVDelete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.kv, key)
	return nil
}

func (s *Store) KVKeys(_ context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for k := range s.kv {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (s *Store) KVCompareAndSwap(_ context.Context, key string, old, next []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.kv[key]
	if !ok || !bytes.Equal(cur, old) {
		return false, nil
	}
	s.kv[key] = slices.Clone(next)
	return true, nil
}

type rateKey struct {
	key    string
	window time.Time
}

func (s *Store) IncrementRateCounter(_ context.Context, key string, window, expireBefore time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rates == nil {
		s.rates = map[rateKey]int{}
	}
	k := rateKey{key, window}
	s.rates[k]++
	if s.rates[k] == 1 {
		for old := range s.rates {
			if old.window.Before(expireBefore) {
				delete(s.rates, old)
			}
		}
	}
	return s.rates[k], nil
}
