package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func testMFA(t *testing.T, s store.Store) {
	ctx := context.Background()
	u := user("mfa@example.com")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateUser(ctx, u) })
	if _, err := s.GetMFA(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no mfa: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	m := store.MFA{UserID: u.ID, TOTPSecret: "SECRET", RecoveryHashes: []string{"h1", "h2"}, UpdatedAt: now}
	if err := s.PutMFA(ctx, m); err != nil {
		t.Fatal(err)
	}
	m.Enabled = true
	if err := s.PutMFA(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetMFA(ctx, u.ID)
	if err != nil || !got.Enabled || got.TOTPSecret != "SECRET" || len(got.RecoveryHashes) != 2 || !got.UpdatedAt.Equal(now) {
		t.Fatalf("get: %+v %v", got, err)
	}
	if err := s.PutMFA(ctx, store.MFA{UserID: newID(), TOTPSecret: "x", UpdatedAt: now}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mfa for unknown user: %v", err)
	}

	if ok, err := s.UseTOTPStep(ctx, u.ID, 100); !ok || err != nil {
		t.Fatalf("step: %v %v", ok, err)
	}
	if ok, _ := s.UseTOTPStep(ctx, u.ID, 100); ok {
		t.Fatal("step reused")
	}
	if ok, _ := s.UseTOTPStep(ctx, u.ID, 99); ok {
		t.Fatal("older step accepted")
	}
	if ok, _ := s.UseRecoveryCode(ctx, u.ID, "h1"); !ok {
		t.Fatal("recovery code refused")
	}
	if ok, _ := s.UseRecoveryCode(ctx, u.ID, "h1"); ok {
		t.Fatal("recovery code reused")
	}
	if ok, _ := s.UseRecoveryCode(ctx, u.ID, "nope"); ok {
		t.Fatal("unknown recovery code accepted")
	}
	got, _ = s.GetMFA(ctx, u.ID)
	if got.LastStep != 100 || len(got.RecoveryHashes) != 1 || got.RecoveryHashes[0] != "h2" {
		t.Fatalf("after use: %+v", got)
	}

	if err := s.DeleteMFA(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteMFA(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	// Deleting the user removes its MFA.
	_ = s.PutMFA(ctx, m)
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.DeleteUser(ctx, u.ID) }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMFA(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mfa survived user deletion: %v", err)
	}
}
