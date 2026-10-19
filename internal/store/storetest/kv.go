package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func testKV(t *testing.T, s store.Store) {
	ctx := context.Background()
	if _, err := s.KVGet(ctx, "certs/a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing key: %v", err)
	}
	if ok, err := s.KVPutIfAbsent(ctx, "certs/a", []byte("1")); !ok || err != nil {
		t.Fatalf("put if absent: %v %v", ok, err)
	}
	if ok, _ := s.KVPutIfAbsent(ctx, "certs/a", []byte("2")); ok {
		t.Fatal("overwrote existing key")
	}
	if err := s.KVPut(ctx, "certs/a", []byte("3")); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.KVGet(ctx, "certs/a"); string(v) != "3" {
		t.Fatalf("value: %s", v)
	}
	if err := s.KVDelete(ctx, "certs/a"); err != nil {
		t.Fatal(err)
	}
	if err := s.KVDelete(ctx, "certs/a"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	if _, err := s.KVGet(ctx, "certs/a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func testKVCompareAndSwap(t *testing.T, s store.Store) {
	ctx := context.Background()
	for _, k := range []string{"cas/b", "cas/a", "other/x"} {
		if err := s.KVPut(ctx, k, []byte("v1")); err != nil {
			t.Fatal(err)
		}
	}
	if keys, err := s.KVKeys(ctx, "cas/"); err != nil || len(keys) != 2 || keys[0] != "cas/a" {
		t.Fatalf("keys: %v %v", keys, err)
	}
	if ok, err := s.KVCompareAndSwap(ctx, "cas/a", []byte("stale"), []byte("v2")); ok || err != nil {
		t.Fatalf("swap with stale value: %v %v", ok, err)
	}
	if ok, err := s.KVCompareAndSwap(ctx, "cas/a", []byte("v1"), []byte("v2")); !ok || err != nil {
		t.Fatalf("swap: %v %v", ok, err)
	}
	if v, _ := s.KVGet(ctx, "cas/a"); string(v) != "v2" {
		t.Fatalf("after swap: %q", v)
	}
	if ok, _ := s.KVCompareAndSwap(ctx, "cas/missing", nil, []byte("v")); ok {
		t.Fatal("swapped a missing key")
	}
}

func testRateCounters(t *testing.T, s store.Store) {
	ctx := context.Background()
	w1 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	w2 := w1.Add(time.Minute)
	for i := 1; i <= 3; i++ {
		if n, err := s.IncrementRateCounter(ctx, "ip:1", w1, w1.Add(-time.Minute)); err != nil || n != i {
			t.Fatalf("increment %d: %d %v", i, n, err)
		}
	}
	if n, _ := s.IncrementRateCounter(ctx, "ip:2", w1, w1.Add(-time.Minute)); n != 1 {
		t.Fatalf("other key: %d", n)
	}
	// A new window starts from one and may drop the old one.
	if n, _ := s.IncrementRateCounter(ctx, "ip:1", w2, w2); n != 1 {
		t.Fatalf("new window: %d", n)
	}
	if n, _ := s.IncrementRateCounter(ctx, "ip:1", w2, w2); n != 2 {
		t.Fatalf("new window again: %d", n)
	}
}
