package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func testWebAuthn(t *testing.T, s store.Store) {
	ctx := context.Background()
	u, v := user("pk1@example.com"), user("pk2@example.com")
	mustTx(t, s, func(tx store.Tx) error {
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		return tx.CreateUser(ctx, v)
	})
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := store.WebAuthnCredential{ID: "cred-1", UserID: u.ID, Name: "laptop", Data: []byte(`{"k":1}`), CreatedAt: now}
	if err := s.PutWebAuthnCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.LastUsedAt, c.Data = &now, []byte(`{"k":2}`)
	if err := s.PutWebAuthnCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetWebAuthnCredential(ctx, "cred-1")
	if err != nil || string(got.Data) != `{"k":2}` || got.LastUsedAt == nil || got.Name != "laptop" {
		t.Fatalf("get: %+v %v", got, err)
	}
	stolen := c
	stolen.UserID = v.ID
	if err := s.PutWebAuthnCredential(ctx, stolen); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("credential of another user overwritten: %v", err)
	}
	if l, _ := s.ListWebAuthnCredentials(ctx, u.ID); len(l) != 1 {
		t.Fatalf("list: %+v", l)
	}
	if err := s.DeleteWebAuthnCredential(ctx, v.ID, "cred-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted through another user: %v", err)
	}
	mustTx(t, s, func(tx store.Tx) error { return tx.DeleteUser(ctx, u.ID) })
	if _, err := s.GetWebAuthnCredential(ctx, "cred-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("credential survived its user: %v", err)
	}
}
