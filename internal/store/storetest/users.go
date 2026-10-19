package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func user(email string) sdk.User {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return sdk.User{
		ID: newID(), Email: email, Name: "N", Status: sdk.UserInvited, Directory: "internal",
		Roles: []string{"admin"}, Attributes: map[string]string{"team": "a"}, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func testUsers(t *testing.T, s store.Store) {
	ctx := context.Background()
	u := user("Ada@Example.com")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateUser(ctx, u) })
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.CreateUser(ctx, user("ada@example.COM")) }); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("case-insensitive duplicate email: %v", err)
	}
	got, err := s.GetUserByEmail(ctx, "ADA@example.com")
	if err != nil || got.ID != u.ID || got.Roles[0] != "admin" || got.Attributes["team"] != "a" {
		t.Fatalf("by email: %+v %v", got, err)
	}

	u2 := got.Clone()
	u2.Status, u2.ExternalID, u2.Version = sdk.UserActive, "kc-1", 2
	mustTx(t, s, func(tx store.Tx) error { return tx.UpdateUser(ctx, u2, 1) })
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.UpdateUser(ctx, u2, 1) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if got, err := s.GetUserByExternalID(ctx, "internal", "kc-1"); err != nil || got.ID != u.ID {
		t.Fatalf("by external id: %v", err)
	}
	if _, err := s.GetUserByExternalID(ctx, "other", "kc-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("external id is per directory: %v", err)
	}

	for _, e := range []string{"bob@example.com", "carol@example.com"} {
		mustTx(t, s, func(tx store.Tx) error { return tx.CreateUser(ctx, user(e)) })
	}
	if l, _ := s.ListUsers(ctx, store.ListUsersQuery{Search: "CAROL"}); len(l) != 1 {
		t.Fatalf("search: %d", len(l))
	}
	if l, _ := s.ListUsers(ctx, store.ListUsersQuery{Status: sdk.UserActive}); len(l) != 1 {
		t.Fatalf("status filter: %d", len(l))
	}
	if l, _ := s.ListUsers(ctx, store.ListUsersQuery{Search: "%"}); len(l) != 0 {
		t.Fatalf("LIKE wildcards must be literal: %d", len(l))
	}

	// Memberships of a user, across tenants.
	tn := tenant("ut")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateTenant(ctx, tn) })
	now := time.Now().UTC().Truncate(time.Microsecond)
	m := sdk.Member{ID: newID(), TenantID: tn.ID, UserID: u.ID, Email: u.Email, Role: "owner", Status: sdk.MemberInvited, Version: 1, CreatedAt: now, UpdatedAt: now}
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateMember(ctx, m) })
	if ms, _ := s.ListMembershipsOfUser(ctx, u.ID); len(ms) != 1 || ms[0].TenantID != tn.ID {
		t.Fatalf("memberships: %+v", ms)
	}
	mustTx(t, s, func(tx store.Tx) error {
		ms, err := tx.ListMembersOfUser(ctx, u.ID)
		if err == nil && len(ms) != 1 {
			err = errors.New("tx memberships")
		}
		return err
	})

	mustTx(t, s, func(tx store.Tx) error { return tx.DeleteUser(ctx, u.ID) })
	if _, err := s.GetUser(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted user: %v", err)
	}
}

func testCredentials(t *testing.T, s store.Store) {
	ctx := context.Background()
	u := user("cred@example.com")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateUser(ctx, u) })
	mustTx(t, s, func(tx store.Tx) error { return tx.SetPasswordHash(ctx, u.ID, "hash1") })
	now := time.Now().UTC()
	for i := 1; i <= 3; i++ {
		locked, err := s.RecordLoginFailure(ctx, u.ID, 3, time.Minute, now)
		if err != nil || locked != (i == 3) {
			t.Fatalf("failure %d: locked=%v %v", i, locked, err)
		}
	}
	c, _ := s.GetCredentials(ctx, u.ID)
	if c.PasswordHash != "hash1" || c.LockedUntil == nil || c.FailedLogins != 0 {
		t.Fatalf("after lock: %+v", c)
	}
	if err := s.RecordLoginSuccess(ctx, u.ID, now); err != nil {
		t.Fatal(err)
	}
	c, _ = s.GetCredentials(ctx, u.ID)
	got, _ := s.GetUser(ctx, u.ID)
	if c.LockedUntil != nil || got.LastLoginAt == nil {
		t.Fatalf("after success: %+v %+v", c, got)
	}
	mustTx(t, s, func(tx store.Tx) error { return tx.SetPasswordHash(ctx, u.ID, "hash2") })
	if c, _ = s.GetCredentials(ctx, u.ID); c.PasswordHash != "hash2" {
		t.Fatalf("new hash: %+v", c)
	}
}

func testActionTokens(t *testing.T, s store.Store) {
	ctx := context.Background()
	u := user("act@example.com")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateUser(ctx, u) })
	now := time.Now().UTC().Truncate(time.Microsecond)
	tok := store.ActionToken{Hash: "h1", Kind: "invitation", UserID: u.ID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := s.CreateActionToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeActionToken(ctx, "h1", "password_reset", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("wrong kind: %v", err)
	}
	// Exactly one of many concurrent consumers wins.
	var wins sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for range 10 {
		wins.Go(func() {
			if got, err := s.ConsumeActionToken(ctx, "h1", "invitation", now); err == nil && got.UserID == u.ID {
				mu.Lock()
				won++
				mu.Unlock()
			}
		})
	}
	wins.Wait()
	if won != 1 {
		t.Fatalf("token consumed %d times", won)
	}
	expired := store.ActionToken{Hash: "h2", Kind: "invitation", UserID: u.ID, ExpiresAt: now.Add(-time.Second), CreatedAt: now}
	_ = s.CreateActionToken(ctx, expired)
	if _, err := s.ConsumeActionToken(ctx, "h2", "invitation", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired token: %v", err)
	}
}

func testRefreshTokens(t *testing.T, s store.Store) {
	ctx := context.Background()
	u := user("ref@example.com")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateUser(ctx, u) })
	now := time.Now().UTC().Truncate(time.Microsecond)
	rt := func(h string) store.RefreshToken {
		return store.RefreshToken{Hash: h, UserID: u.ID, TenantID: "t1", Family: "f1", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	}
	if err := s.CreateRefreshToken(ctx, rt("a")); err != nil {
		t.Fatal(err)
	}
	old, err := s.RotateRefreshToken(ctx, "a", store.RefreshToken{Hash: "b", ExpiresAt: now.Add(time.Hour), CreatedAt: now}, now)
	if err != nil || old.UserID != u.ID || old.TenantID != "t1" {
		t.Fatalf("rotate: %+v %v", old, err)
	}
	// Presenting "a" again is theft: the whole family (incl. "b") dies.
	if _, err := s.RotateRefreshToken(ctx, "a", store.RefreshToken{Hash: "c", ExpiresAt: now.Add(time.Hour), CreatedAt: now}, now); !errors.Is(err, store.ErrTokenReused) {
		t.Fatalf("reuse: %v", err)
	}
	if _, err := s.RotateRefreshToken(ctx, "b", store.RefreshToken{Hash: "d", ExpiresAt: now.Add(time.Hour), CreatedAt: now}, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("family member after reuse: %v", err)
	}

	f2 := rt("x")
	f2.Family = "f2"
	_ = s.CreateRefreshToken(ctx, f2)
	if err := s.RevokeUserRefreshTokens(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateRefreshToken(ctx, "x", store.RefreshToken{Hash: "y", ExpiresAt: now.Add(time.Hour), CreatedAt: now}, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoked user token: %v", err)
	}
	if _, err := s.RotateRefreshToken(ctx, "missing", store.RefreshToken{Hash: "z", ExpiresAt: now, CreatedAt: now}, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown token: %v", err)
	}
}

func testSigningKeys(t *testing.T, s store.Store) {
	ctx := context.Background()
	k := store.SigningKey{ID: "k1", Algorithm: "ES256", PrivatePEM: []byte("pem"), CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if err := s.AddSigningKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSigningKey(ctx, k); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate key: %v", err)
	}
	keys, err := s.ListSigningKeys(ctx)
	if err != nil || len(keys) != 1 || string(keys[0].PrivatePEM) != "pem" {
		t.Fatalf("keys: %+v %v", keys, err)
	}
	if err := s.DeleteSigningKey(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSigningKey(ctx, "k1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if keys, _ := s.ListSigningKeys(ctx); len(keys) != 0 {
		t.Fatalf("after delete: %+v", keys)
	}
}

func testAPIKeys(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	k := store.APIKey{ID: newID(), TenantID: "t1", Name: "ci", Prefix: "tnr_abcd", Hash: "h-1", Roles: []string{"admin"}, CreatedBy: "u", CreatedAt: now}
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateAPIKey(ctx, k) })
	dup := k
	dup.ID = newID()
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.CreateAPIKey(ctx, dup) }); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate hash: %v", err)
	}
	got, err := s.GetAPIKeyByHash(ctx, "h-1")
	if err != nil || got.ID != k.ID || got.Roles[0] != "admin" || got.TenantID != "t1" {
		t.Fatalf("by hash: %+v %v", got, err)
	}
	platform := store.APIKey{ID: newID(), Name: "ops", Prefix: "tnr_x", Hash: "h-2", CreatedAt: now}
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateAPIKey(ctx, platform) })
	if l, _ := s.ListAPIKeys(ctx, "t1"); len(l) != 1 {
		t.Fatalf("tenant keys: %d", len(l))
	}
	if l, _ := s.ListAPIKeys(ctx, ""); len(l) != 1 || l[0].ID != platform.ID {
		t.Fatalf("platform keys: %+v", l)
	}
	if err := s.TouchAPIKey(ctx, k.ID, now); err != nil {
		t.Fatal(err)
	}
	// Revoking requires the right tenant.
	if err := s.InTx(ctx, func(tx store.Tx) error { _, err := tx.RevokeAPIKey(ctx, "other", k.ID, now); return err }); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoke from another tenant: %v", err)
	}
	mustTx(t, s, func(tx store.Tx) error { _, err := tx.RevokeAPIKey(ctx, "t1", k.ID, now); return err })
	if got, _ := s.GetAPIKeyByHash(ctx, "h-1"); got.RevokedAt == nil || got.LastUsedAt == nil {
		t.Fatalf("after revoke: %+v", got)
	}
	if err := s.InTx(ctx, func(tx store.Tx) error { _, err := tx.RevokeAPIKey(ctx, "t1", k.ID, now); return err }); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("double revoke: %v", err)
	}
}

func testDomains(t *testing.T, s store.Store) {
	ctx := context.Background()
	tn := tenant("dom")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateTenant(ctx, tn) })
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := store.Domain{Hostname: "app.acme.example", TenantID: tn.ID, Token: "tok", CreatedAt: now}
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateDomain(ctx, d) })
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.CreateDomain(ctx, d) }); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate hostname: %v", err)
	}
	mustTx(t, s, func(tx store.Tx) error { return tx.MarkDomainVerified(ctx, d.Hostname, now) })
	got, err := s.GetDomain(ctx, d.Hostname)
	if err != nil || !got.Verified || got.VerifiedAt == nil || got.TenantID != tn.ID {
		t.Fatalf("get: %+v %v", got, err)
	}
	if l, _ := s.ListDomains(ctx, tn.ID); len(l) != 1 {
		t.Fatalf("list: %d", len(l))
	}
	mustTx(t, s, func(tx store.Tx) error { return tx.DeleteDomain(ctx, d.Hostname) })
	if _, err := s.GetDomain(ctx, d.Hostname); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
}
