package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func testRolesAndGroups(t *testing.T, s store.Store) {
	ctx := context.Background()
	tn := tenant("rbac")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateTenant(ctx, tn) })
	now := time.Now().UTC().Truncate(time.Microsecond)

	r := store.TenantRole{TenantID: tn.ID, Name: "billing", Actions: []string{"usage:read"}, CreatedAt: now, UpdatedAt: now}
	mustTx(t, s, func(tx store.Tx) error { return tx.PutTenantRole(ctx, r) })
	r.Actions, r.Description = []string{"usage:read", "plans:read"}, "finance"
	mustTx(t, s, func(tx store.Tx) error { return tx.PutTenantRole(ctx, r) })
	got, err := s.GetTenantRole(ctx, tn.ID, "billing")
	if err != nil || len(got.Actions) != 2 || got.Description != "finance" {
		t.Fatalf("role: %+v %v", got, err)
	}
	if l, _ := s.ListTenantRoles(ctx, tn.ID); len(l) != 1 {
		t.Fatalf("list roles: %+v", l)
	}

	g := store.Group{ID: newID(), TenantID: tn.ID, Name: "finance", Roles: []string{"billing"}, Members: []string{"m1"}, CreatedAt: now, UpdatedAt: now}
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateGroup(ctx, g) })
	dup := g
	dup.ID = newID()
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.CreateGroup(ctx, dup) }); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate group name: %v", err)
	}
	g.Members = append(g.Members, "m2")
	mustTx(t, s, func(tx store.Tx) error { return tx.UpdateGroup(ctx, g) })
	if got, _ := s.GetGroup(ctx, tn.ID, g.ID); len(got.Members) != 2 || got.Roles[0] != "billing" {
		t.Fatalf("group: %+v", got)
	}
	if _, err := s.GetGroup(ctx, newID(), g.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("group through other tenant: %v", err)
	}
	if l, _ := s.ListGroups(ctx, tn.ID); len(l) != 1 {
		t.Fatalf("list groups: %+v", l)
	}
	mustTx(t, s, func(tx store.Tx) error { return tx.DeleteGroup(ctx, tn.ID, g.ID) })
	mustTx(t, s, func(tx store.Tx) error { return tx.DeleteTenantRole(ctx, tn.ID, "billing") })
	if _, err := s.GetTenantRole(ctx, tn.ID, "billing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted role: %v", err)
	}
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.DeleteGroup(ctx, tn.ID, g.ID) }); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}
