package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func testSSO(t *testing.T, s store.Store) {
	ctx := context.Background()
	a, b := tenant("sso-a"), tenant("sso-b")
	mustTx(t, s, func(tx store.Tx) error {
		if err := tx.CreateTenant(ctx, a); err != nil {
			return err
		}
		return tx.CreateTenant(ctx, b)
	})
	if _, err := s.GetSSOConnection(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("none: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := store.SSOConnection{TenantID: a.ID, Issuer: "https://idp.example", ClientID: "cid", ClientSecret: "sec",
		Domains: []string{"a.example", "b.example"}, Enforce: true, AutoProvision: true, DefaultRole: "member", Enabled: true,
		CreatedAt: now, UpdatedAt: now}
	if err := s.PutSSOConnection(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSSOConnection(ctx, a.ID)
	if err != nil || got.ClientSecret != "sec" || len(got.Domains) != 2 || !got.Enforce || got.DefaultRole != "member" {
		t.Fatalf("get: %+v %v", got, err)
	}
	if f, err := s.FindSSOConnection(ctx, "b.example"); err != nil || f.TenantID != a.ID {
		t.Fatalf("find: %+v %v", f, err)
	}
	if _, err := s.FindSSOConnection(ctx, "c.example"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("find unknown: %v", err)
	}
	other := c
	other.TenantID, other.Domains = b.ID, []string{"b.example"}
	if err := s.PutSSOConnection(ctx, other); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("domain claimed twice: %v", err)
	}
	c.Domains, c.Enforce = []string{"a.example"}, false
	if err := s.PutSSOConnection(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSSOConnection(ctx, other); err != nil {
		t.Fatalf("released domain: %v", err)
	}
	if got, _ := s.GetSSOConnection(ctx, a.ID); got.Enforce || len(got.Domains) != 1 {
		t.Fatalf("replace: %+v", got)
	}
	if err := s.DeleteSSOConnection(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindSSOConnection(ctx, "a.example"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("domain survived delete: %v", err)
	}
	if err := s.DeleteSSOConnection(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}
