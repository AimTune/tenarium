package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func testSessions(t *testing.T, s store.Store) {
	ctx := context.Background()
	u, other := user("sess@example.com"), user("other-sess@example.com")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateUser(ctx, u) })
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateUser(ctx, other) })
	now := time.Now().UTC().Truncate(time.Microsecond)
	later := now.Add(time.Minute)
	for _, rt := range []store.RefreshToken{
		{Hash: "s1", UserID: u.ID, TenantID: "t1", Family: "fam-1", ExpiresAt: now.Add(time.Hour), CreatedAt: now, UserAgent: "Firefox", IP: "192.0.2.1"},
		{Hash: "s2", UserID: u.ID, Family: "fam-2", ExpiresAt: now.Add(time.Hour), CreatedAt: now},
		{Hash: "s3", UserID: u.ID, Family: "fam-3", ExpiresAt: now.Add(-time.Second), CreatedAt: now.Add(-time.Hour)},
	} {
		if err := s.CreateRefreshToken(ctx, rt); err != nil {
			t.Fatal(err)
		}
	}
	// Rotation keeps the client details unless new ones are given.
	if _, err := s.RotateRefreshToken(ctx, "s1", store.RefreshToken{Hash: "s1b", ExpiresAt: now.Add(2 * time.Hour), CreatedAt: later}, later); err != nil {
		t.Fatal(err)
	}
	ss, err := s.ListSessions(ctx, u.ID, later)
	if err != nil || len(ss) != 2 {
		t.Fatalf("sessions: %+v %v", ss, err)
	}
	first := ss[0]
	if first.ID != "fam-1" || first.UserAgent != "Firefox" || first.IP != "192.0.2.1" || first.TenantID != "t1" ||
		!first.CreatedAt.Equal(now) || !first.LastUsedAt.Equal(later) || !first.ExpiresAt.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("session: %+v", first)
	}
	if err := s.RevokeSession(ctx, other.ID, "fam-1", later); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoked someone else's session: %v", err)
	}
	if err := s.RevokeSession(ctx, u.ID, "fam-1", later); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession(ctx, u.ID, "fam-1", later); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoke twice: %v", err)
	}
	if _, err := s.RotateRefreshToken(ctx, "s1b", store.RefreshToken{Hash: "s1c", ExpiresAt: now.Add(time.Hour), CreatedAt: later}, later); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoked session still refreshes: %v", err)
	}
	if ss, _ := s.ListSessions(ctx, u.ID, later); len(ss) != 1 || ss[0].ID != "fam-2" {
		t.Fatalf("after revoke: %+v", ss)
	}

	// Action tokens carry kind-specific data.
	if err := s.CreateActionToken(ctx, store.ActionToken{Hash: "ec", Kind: "email_change", UserID: u.ID, Data: "new@example.com",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if at, err := s.ConsumeActionToken(ctx, "ec", "email_change", now); err != nil || at.Data != "new@example.com" {
		t.Fatalf("action token data: %+v %v", at, err)
	}
}

func testReplaceSigningKeyPEM(t *testing.T, s store.Store) {
	ctx := context.Background()
	if err := s.AddSigningKey(ctx, store.SigningKey{ID: "rk", Algorithm: "ES256", PrivatePEM: []byte("a"), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceSigningKeyPEM(ctx, "rk", []byte("stale"), []byte("b")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale: %v", err)
	}
	if err := s.ReplaceSigningKeyPEM(ctx, "nope", []byte("a"), []byte("b")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := s.ReplaceSigningKeyPEM(ctx, "rk", []byte("a"), []byte("b")); err != nil {
		t.Fatal(err)
	}
	keys, _ := s.ListSigningKeys(ctx)
	for _, k := range keys {
		if k.ID == "rk" && string(k.PrivatePEM) != "b" {
			t.Fatalf("pem: %q", k.PrivatePEM)
		}
	}
	_ = s.DeleteSigningKey(ctx, "rk")
}
