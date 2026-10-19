package storetest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func testGDPR(t *testing.T, s store.Store) {
	ctx := context.Background()
	a, b := tenant("purge-a"), tenant("purge-b")
	now := time.Now().UTC().Truncate(time.Microsecond)
	mustTx(t, s, func(tx store.Tx) error {
		for _, tn := range []sdk.Tenant{a, b} {
			if err := tx.CreateTenant(ctx, tn); err != nil {
				return err
			}
			m := sdk.Member{ID: newID(), TenantID: tn.ID, Email: "x@" + tn.Slug + ".example", Role: "admin",
				Status: sdk.MemberInvited, Version: 1, CreatedAt: now, UpdatedAt: now}
			if err := tx.CreateMember(ctx, m); err != nil {
				return err
			}
			if err := tx.CreateDomain(ctx, store.Domain{Hostname: tn.Slug + ".example", TenantID: tn.ID, Token: "t", CreatedAt: now}); err != nil {
				return err
			}
			if err := tx.PutTenantRole(ctx, store.TenantRole{TenantID: tn.ID, Name: "r", Actions: []string{"usage:read"}, CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
		}
		return nil
	})
	if _, err := s.IncrementUsage(ctx, store.UsageKey{TenantID: a.ID, Metric: "calls"}, 3, nil); err != nil {
		t.Fatal(err)
	}
	mustTx(t, s, func(tx store.Tx) error { return tx.PurgeTenantData(ctx, a.ID) })

	if ms, _ := s.ListMembers(ctx, a.ID); len(ms) != 0 {
		t.Fatalf("members survived purge: %+v", ms)
	}
	if u, _ := s.ListUsage(ctx, store.UsageQuery{TenantID: a.ID}); len(u) != 0 {
		t.Fatalf("usage survived purge: %+v", u)
	}
	if _, err := s.GetDomain(ctx, "purge-a.example"); err == nil {
		t.Fatal("domain survived purge")
	}
	if r, _ := s.ListTenantRoles(ctx, a.ID); len(r) != 0 {
		t.Fatal("role survived purge")
	}
	if _, err := s.GetTenant(ctx, a.ID); err != nil {
		t.Fatalf("tenant record must stay: %v", err)
	}
	if ms, _ := s.ListMembers(ctx, b.ID); len(ms) != 1 {
		t.Fatal("other tenant's data purged")
	}
	if _, err := s.GetDomain(ctx, "purge-b.example"); err != nil {
		t.Fatal("other tenant's domain purged")
	}

	// Redaction rewrites personal data inside event payloads.
	mustTx(t, s, func(tx store.Tx) error {
		e := Event("user.created")
		e.Data = json.RawMessage(`{"email":"ann@example.com","name":"Ann \"A\" Lee"}`)
		f := Event("other")
		f.Data = json.RawMessage(`{"x":1}`)
		_, err := tx.AppendEvents(ctx, e, f)
		return err
	})
	n, err := s.RedactEvents(ctx, "ann@example.com", "[erased]")
	if err != nil || n != 1 {
		t.Fatalf("redact: %d %v", n, err)
	}
	if n, _ := s.RedactEvents(ctx, `Ann "A" Lee`, "[erased]"); n != 1 {
		t.Fatalf("redact quoted name: %d", n)
	}
	evts, _ := s.ReadEvents(ctx, 0, 0)
	for _, e := range evts {
		if strings.Contains(string(e.Data), "ann@") || strings.Contains(string(e.Data), "Lee") {
			t.Fatalf("not redacted: %s", e.Data)
		}
		if len(e.Data) > 0 && !json.Valid(e.Data) {
			t.Fatalf("redaction broke JSON: %s", e.Data)
		}
	}
}
