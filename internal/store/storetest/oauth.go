package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func testOAuth(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := store.OAuthClient{ID: "app", Name: "App", SecretHash: "h", RedirectURIs: []string{"https://app.example/cb"},
		Scopes: []string{"openid", "email"}, CreatedAt: now, UpdatedAt: now}
	if err := s.PutOAuthClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.FirstParty, c.Name = true, "App 2"
	if err := s.PutOAuthClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetOAuthClient(ctx, "app")
	if err != nil || !got.FirstParty || got.Name != "App 2" || got.SecretHash != "h" || len(got.RedirectURIs) != 1 {
		t.Fatalf("client: %+v %v", got, err)
	}
	if l, _ := s.ListOAuthClients(ctx); len(l) != 1 {
		t.Fatalf("list: %+v", l)
	}

	u := user("oauth@example.com")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateUser(ctx, u) })
	if err := s.PutOAuthConsent(ctx, store.OAuthConsent{UserID: u.ID, ClientID: "app", Scopes: []string{"openid"}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOAuthConsent(ctx, store.OAuthConsent{UserID: u.ID, ClientID: "nope", CreatedAt: now}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("consent for unknown client: %v", err)
	}
	if got, err := s.GetOAuthConsent(ctx, u.ID, "app"); err != nil || len(got.Scopes) != 1 {
		t.Fatalf("consent: %+v %v", got, err)
	}
	if err := s.DeleteOAuthClient(ctx, "app"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetOAuthConsent(ctx, u.ID, "app"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("consent survived client deletion: %v", err)
	}
	if err := s.DeleteOAuthClient(ctx, "app"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}
