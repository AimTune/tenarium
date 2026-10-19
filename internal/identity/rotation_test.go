package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
)

func TestRotationAndRetirement(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	clock := time.Now()
	now := func() time.Time { return clock }
	a := NewIssuer(s, "https://t.test", "tenarium", 15*time.Minute)
	b := NewIssuer(s, "https://t.test", "tenarium", 15*time.Minute)
	a.now, b.now = now, now
	if err := a.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Init(ctx); err != nil {
		t.Fatal(err)
	}
	old, _, _ := a.Sign("u1", "", "", "", nil)

	// Not due yet.
	if err := a.Maintain(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if keys, _ := a.Keys(ctx); len(keys) != 1 {
		t.Fatalf("rotated early: %+v", keys)
	}
	clock = clock.Add(25 * time.Hour)
	if err := a.Maintain(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	keys, _ := a.Keys(ctx)
	if len(keys) != 2 || keys[0].Active || !keys[1].Active {
		t.Fatalf("after rotation: %+v", keys)
	}
	fresh, _, _ := a.Sign("u1", "", "", "", nil)

	// b has not reloaded but verifies the new key by reloading on demand.
	if _, err := b.Verify(fresh); err != nil {
		t.Fatalf("other replica rejects new key: %v", err)
	}
	if _, err := b.Verify(old); err == nil {
		t.Fatal("old token outlived its expiry") // clock moved 25h; expired anyway
	}

	// The old key stays until its last tokens expired, then goes.
	clock = clock.Add(10 * time.Minute)
	_ = a.Maintain(ctx, 24*time.Hour)
	if keys, _ := a.Keys(ctx); len(keys) != 2 {
		t.Fatalf("retired too early: %+v", keys)
	}
	clock = clock.Add(15 * time.Minute)
	_ = a.Maintain(ctx, 24*time.Hour)
	if keys, _ := a.Keys(ctx); len(keys) != 1 || !keys[0].Active {
		t.Fatalf("not retired: %+v", keys)
	}
	if tok, _, _ := a.Sign("u1", "", "", "", nil); tok == "" {
		t.Fatal("cannot sign")
	} else if _, err := a.Verify(tok); err != nil {
		t.Fatalf("active key lost: %v", err)
	}
}

func TestRetireManually(t *testing.T) {
	ctx := context.Background()
	iss := NewIssuer(memory.New(), "https://t.test", "tenarium", time.Hour)
	if err := iss.Init(ctx); err != nil {
		t.Fatal(err)
	}
	leaked, _, _ := iss.Sign("u1", "", "", "", nil)
	keys, _ := iss.Keys(ctx)
	if err := iss.Retire(ctx, keys[0].ID); !errors.Is(err, ErrActiveKey) {
		t.Fatalf("retired active key: %v", err)
	}
	if err := iss.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := iss.Retire(ctx, keys[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Verify(leaked); err == nil {
		t.Fatal("token of retired key still verifies")
	}
	if err := iss.Retire(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
}

func TestSignClaims(t *testing.T) {
	ctx := context.Background()
	iss := NewIssuer(memory.New(), "https://t.test", "tenarium", time.Hour)
	if err := iss.Init(ctx); err != nil {
		t.Fatal(err)
	}
	type state struct {
		Nonce string `json:"nonce"`
	}
	raw, err := iss.SignClaims("tenarium-sso-state", time.Minute, state{Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	var got state
	if err := iss.VerifyClaims(raw, "tenarium-sso-state", &got); err != nil || got.Nonce != "n1" {
		t.Fatalf("verify: %+v %v", got, err)
	}
	if err := iss.VerifyClaims(raw, "other", &got); err == nil {
		t.Fatal("wrong audience accepted")
	}
	if _, err := iss.Verify(raw); err == nil {
		t.Fatal("state token accepted as access token")
	}
	iss.now = func() time.Time { return time.Now().Add(time.Hour) }
	if err := iss.VerifyClaims(raw, "tenarium-sso-state", &got); err == nil {
		t.Fatal("expired state accepted")
	}
}
