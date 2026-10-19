// Package storetest is a conformance suite every store.Store must pass.
package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// Run executes the suite. newStore must return an empty store.
func Run(t *testing.T, newStore func(t *testing.T) store.Store) {
	tests := map[string]func(t *testing.T, s store.Store){
		"Tenants":           testTenants,
		"TxRollback":        testTxRollback,
		"ListTenants":       testListTenants,
		"Plans":             testPlans,
		"Members":           testMembers,
		"Usage":             testUsage,
		"EventsAndCursors":  testEventsAndCursors,
		"ConcurrentEvents":  testConcurrentEvents,
		"Leases":            testLeases,
		"DeadLetters":       testDeadLetters,
		"Idempotency":       testIdempotency,
		"Users":             testUsers,
		"Credentials":       testCredentials,
		"ActionTokens":      testActionTokens,
		"RefreshTokens":     testRefreshTokens,
		"SigningKeys":       testSigningKeys,
		"APIKeys":           testAPIKeys,
		"Domains":           testDomains,
		"Schedule":          testSchedule,
		"EventQueries":      testEventQueries,
		"MFA":               testMFA,
		"Webhooks":          testWebhooks,
		"SSO":               testSSO,
		"RolesAndGroups":    testRolesAndGroups,
		"WebAuthn":          testWebAuthn,
		"GDPR":              testGDPR,
		"OAuth":             testOAuth,
		"KV":                testKV,
		"PlanRevisions":     testPlanRevisions,
		"Rollouts":          testRollouts,
		"TenantPlacement":   testTenantPlacement,
		"EventTraceContext": testEventTraceContext,
		"Sessions":          testSessions,
		"TenantExtras":      testTenantExtras,
		"KVCompareAndSwap":  testKVCompareAndSwap,
		"RateCounters":      testRateCounters,
		"ReplaceSigningKey": testReplaceSigningKeyPEM,
	}
	for name, fn := range tests {
		t.Run(name, func(t *testing.T) { fn(t, newStore(t)) })
	}
}

func newID() string { return uuid.Must(uuid.NewV7()).String() }

// Event returns a minimal valid event of the given type.
func Event(typ string) sdk.Event {
	return sdk.Event{ID: newID(), Type: typ, Source: "test", Time: time.Now()}
}

func tenant(slug string) sdk.Tenant {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return sdk.Tenant{
		ID: newID(), Slug: slug, Name: slug, Status: sdk.StatusActive, Version: 1,
		Labels:    map[string]string{"env": "prod"},
		Settings:  map[string]any{"theme": map[string]any{"color": "blue"}},
		Features:  map[string]bool{"sso": true},
		Limits:    map[string]int64{"seats": 5},
		CreatedAt: now, UpdatedAt: now,
	}
}

func mustTx(t *testing.T, s store.Store, fn func(tx store.Tx) error) {
	t.Helper()
	if err := s.InTx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func testTenants(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := tenant("acme")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateTenant(ctx, a) })

	got, err := s.GetTenant(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Slug != "acme" || got.Labels["env"] != "prod" || !got.Features["sso"] || got.Limits["seats"] != 5 ||
		got.Settings["theme"].(map[string]any)["color"] != "blue" || !got.CreatedAt.Equal(a.CreatedAt) {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if _, err := s.GetTenantBySlug(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetTenant(ctx, newID()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := s.GetTenant(ctx, "not-a-uuid"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound for bad id, got %v", err)
	}

	dup := tenant("acme")
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.CreateTenant(ctx, dup) }); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("want ErrAlreadyExists, got %v", err)
	}

	upd := got.Clone()
	upd.Name, upd.Version = "Acme 2", 2
	mustTx(t, s, func(tx store.Tx) error { return tx.UpdateTenant(ctx, upd, 1) })
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.UpdateTenant(ctx, upd, 1) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	ghost := tenant("ghost")
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.UpdateTenant(ctx, ghost, 1) }); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	// Deleting frees the slug.
	del := upd.Clone()
	del.Status, del.Version = sdk.StatusDeleted, 3
	now := time.Now().UTC()
	del.DeletedAt = &now
	mustTx(t, s, func(tx store.Tx) error { return tx.UpdateTenant(ctx, del, 2) })
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateTenant(ctx, dup) })

	// Hierarchy.
	child := tenant("child")
	child.ParentID = dup.ID
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateTenant(ctx, child) })
	mustTx(t, s, func(tx store.Tx) error {
		n, err := tx.CountLiveChildren(ctx, dup.ID)
		if err == nil && n != 1 {
			err = fmt.Errorf("children = %d", n)
		}
		return err
	})
}

func testTxRollback(t *testing.T, s store.Store) {
	ctx := context.Background()
	boom := errors.New("boom")
	a := tenant("rollback")
	err := s.InTx(ctx, func(tx store.Tx) error {
		if err := tx.CreateTenant(ctx, a); err != nil {
			return err
		}
		if _, err := tx.AppendEvents(ctx, sdk.Event{ID: newID(), Type: "x", Source: "test", Time: time.Now()}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	if _, err := s.GetTenant(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("tenant persisted despite rollback")
	}
	if evts, _ := s.ReadEvents(ctx, 0, 0); len(evts) != 0 {
		t.Fatal("event persisted despite rollback")
	}
}

func testListTenants(t *testing.T, s store.Store) {
	ctx := context.Background()
	var ids []string
	for i := range 5 {
		tn := tenant(fmt.Sprintf("t%d", i))
		if i%2 == 0 {
			tn.Plan = "pro"
			tn.Labels = map[string]string{"tier": "gold", "env": "prod"}
		}
		ids = append(ids, tn.ID)
		mustTx(t, s, func(tx store.Tx) error { return tx.CreateTenant(ctx, tn) })
	}
	all, _ := s.ListTenants(ctx, store.ListTenantsQuery{})
	if len(all) != 5 || all[0].ID != ids[0] {
		t.Fatalf("list all: %d", len(all))
	}
	page, _ := s.ListTenants(ctx, store.ListTenantsQuery{After: ids[1], Limit: 2})
	if len(page) != 2 || page[0].ID != ids[2] {
		t.Fatalf("pagination: %+v", page)
	}
	pro, _ := s.ListTenants(ctx, store.ListTenantsQuery{Plan: "pro"})
	gold, _ := s.ListTenants(ctx, store.ListTenantsQuery{Labels: map[string]string{"tier": "gold"}})
	if len(pro) != 3 || len(gold) != 3 {
		t.Fatalf("filters: pro=%d gold=%d", len(pro), len(gold))
	}
	some, _ := s.ListTenants(ctx, store.ListTenantsQuery{IDs: []string{ids[3], "junk"}})
	if len(some) != 1 || some[0].ID != ids[3] {
		t.Fatalf("ids filter: %+v", some)
	}
}

func testPlans(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := sdk.Plan{ID: "pro", Name: "Pro", Features: map[string]bool{"sso": true}, Limits: map[string]int64{"seats": 10}, Version: 1, CreatedAt: now, UpdatedAt: now}
	mustTx(t, s, func(tx store.Tx) error { return tx.CreatePlan(ctx, p) })
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.CreatePlan(ctx, p) }); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("dup plan: %v", err)
	}
	got, err := s.GetPlan(ctx, "pro")
	if err != nil || got.Limits["seats"] != 10 || !got.Features["sso"] {
		t.Fatalf("get plan: %+v %v", got, err)
	}
	p.Name, p.Version = "Pro+", 2
	mustTx(t, s, func(tx store.Tx) error { return tx.UpdatePlan(ctx, p, 1) })
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.UpdatePlan(ctx, p, 1) }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("plan conflict: %v", err)
	}
	tn := tenant("onpro")
	tn.Plan = "pro"
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateTenant(ctx, tn) })
	mustTx(t, s, func(tx store.Tx) error {
		n, err := tx.CountTenantsOnPlan(ctx, "pro")
		if err == nil && n != 1 {
			err = fmt.Errorf("on plan = %d", n)
		}
		return err
	})
	plans, _ := s.ListPlans(ctx)
	if len(plans) != 1 {
		t.Fatalf("list plans: %d", len(plans))
	}
	mustTx(t, s, func(tx store.Tx) error { return tx.DeletePlan(ctx, "pro") })
	if _, err := s.GetPlan(ctx, "pro"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted plan: %v", err)
	}
}

func testMembers(t *testing.T, s store.Store) {
	ctx := context.Background()
	tn := tenant("members")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateTenant(ctx, tn) })
	now := time.Now().UTC().Truncate(time.Microsecond)
	m := sdk.Member{ID: newID(), TenantID: tn.ID, Email: "Alice@Example.com", Role: "admin", Status: sdk.MemberInvited, Version: 1, CreatedAt: now, UpdatedAt: now}
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateMember(ctx, m) })
	dup := m
	dup.ID, dup.Email = newID(), "alice@example.com"
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.CreateMember(ctx, dup) }); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("case-insensitive duplicate email: %v", err)
	}
	m.Status, m.UserID, m.Version = sdk.MemberActive, "user-1", 2
	mustTx(t, s, func(tx store.Tx) error { return tx.UpdateMember(ctx, m, 1) })
	got, err := s.GetMember(ctx, tn.ID, m.ID)
	if err != nil || got.UserID != "user-1" || got.Status != sdk.MemberActive {
		t.Fatalf("member: %+v %v", got, err)
	}
	list, _ := s.ListMembers(ctx, tn.ID)
	if len(list) != 1 {
		t.Fatalf("list members: %d", len(list))
	}
	mustTx(t, s, func(tx store.Tx) error { return tx.DeleteMember(ctx, tn.ID, m.ID) })
	if _, err := s.GetMember(ctx, tn.ID, m.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted member: %v", err)
	}
}

func testEventsAndCursors(t *testing.T, s store.Store) {
	ctx := context.Background()
	mustTx(t, s, func(tx store.Tx) error {
		evts, err := tx.AppendEvents(ctx,
			sdk.Event{ID: newID(), Type: "a", Source: "test", TenantID: "t1", Actor: "me", Time: time.Now(), Data: json.RawMessage(`{"x":1}`)},
			sdk.Event{ID: newID(), Type: "b", Source: "test", Time: time.Now()},
		)
		if err == nil && (evts[0].Seq <= 0 || evts[1].Seq <= evts[0].Seq) {
			err = fmt.Errorf("bad seqs %d %d", evts[0].Seq, evts[1].Seq)
		}
		return err
	})
	evts, err := s.ReadEvents(ctx, 0, 0)
	if err != nil || len(evts) != 2 || evts[0].Type != "a" || evts[0].Actor != "me" || evts[0].TenantID != "t1" {
		t.Fatalf("read: %+v %v", evts, err)
	}
	var data map[string]int
	if err := json.Unmarshal(evts[0].Data, &data); err != nil || data["x"] != 1 {
		t.Fatalf("data: %s", evts[0].Data)
	}
	if rest, _ := s.ReadEvents(ctx, evts[0].Seq, 10); len(rest) != 1 || rest[0].Type != "b" {
		t.Fatalf("read after: %+v", rest)
	}
	if last, _ := s.LastEventSeq(ctx); last != evts[1].Seq {
		t.Fatalf("last seq %d", last)
	}

	if _, found, _ := s.GetCursor(ctx, "sub"); found {
		t.Fatal("cursor should not exist")
	}
	_ = s.SetCursor(ctx, "sub", 5)
	_ = s.SetCursor(ctx, "sub", 7)
	_ = s.SetCursor(ctx, "sub", 3) // a stale writer must not move it back
	if seq, found, err := s.GetCursor(ctx, "sub"); !found || seq != 7 || err != nil {
		t.Fatalf("cursor: %d %v %v", seq, found, err)
	}
}

// testConcurrentEvents checks that readers never see seq gaps get filled
// later: once ReadEvents returns seq N, no event with seq < N may appear.
func testConcurrentEvents(t *testing.T, s store.Store) {
	ctx := context.Background()
	const writers, per = 8, 10
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			for range per {
				_ = s.InTx(ctx, func(tx store.Tx) error {
					_, err := tx.AppendEvents(ctx, sdk.Event{ID: newID(), Type: "c", Source: "test", Time: time.Now()})
					return err
				})
			}
		})
	}
	seen := map[int64]bool{}
	var cursor int64
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for finished := false; ; {
		select {
		case <-done:
			finished = true
		default:
		}
		evts, err := s.ReadEvents(ctx, cursor, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range evts {
			seen[e.Seq] = true
			cursor = e.Seq
		}
		if finished && len(evts) == 0 {
			break
		}
	}
	if len(seen) != writers*per {
		t.Fatalf("cursor-based reader saw %d of %d events", len(seen), writers*per)
	}
}

func testLeases(t *testing.T, s store.Store) {
	ctx := context.Background()
	ok, err := s.AcquireLease(ctx, "sub", "a", time.Minute, false)
	if !ok || err != nil {
		t.Fatalf("a acquire: %v %v", ok, err)
	}
	if ok, _ := s.AcquireLease(ctx, "sub", "b", time.Minute, false); ok {
		t.Fatal("b acquired a held lease")
	}
	if ok, _ := s.AcquireLease(ctx, "sub", "a", time.Minute, false); !ok {
		t.Fatal("a could not renew")
	}
	_ = s.ReleaseLease(ctx, "sub", "a")
	if ok, _ := s.AcquireLease(ctx, "sub", "b", 50*time.Millisecond, false); !ok {
		t.Fatal("b could not acquire released lease")
	}
	time.Sleep(100 * time.Millisecond)
	if ok, _ := s.AcquireLease(ctx, "sub", "a", time.Minute, false); !ok {
		t.Fatal("a could not take over expired lease")
	}

	// A preferred owner takes over from a non-preferred one, but not the
	// other way round, nor from another preferred owner.
	if ok, _ := s.AcquireLease(ctx, "sub", "eu-1", time.Minute, true); !ok {
		t.Fatal("preferred owner did not take over")
	}
	if ok, _ := s.AcquireLease(ctx, "sub", "a", time.Minute, false); ok {
		t.Fatal("non-preferred owner took over from a preferred one")
	}
	if ok, _ := s.AcquireLease(ctx, "sub", "eu-2", time.Minute, true); ok {
		t.Fatal("preferred owner took over from another preferred one")
	}
	if ok, _ := s.AcquireLease(ctx, "sub", "eu-1", time.Minute, true); !ok {
		t.Fatal("preferred owner could not renew")
	}
}

func testDeadLetters(t *testing.T, s store.Store) {
	ctx := context.Background()
	dl := store.DeadLetter{
		ID: newID(), Subscription: "kafka/publish", Error: "down", Attempts: 3,
		FailedAt: time.Now().UTC().Truncate(time.Microsecond),
		Event:    sdk.Event{Seq: 4, ID: newID(), Type: "tenant.created", Source: "test", Time: time.Now().UTC().Truncate(time.Microsecond), Data: json.RawMessage(`{"a":1}`)},
	}
	if err := s.AddDeadLetter(ctx, dl); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDeadLetter(ctx, dl.ID)
	if err != nil || got.Event.Type != "tenant.created" || got.Event.Seq != 4 || got.Attempts != 3 {
		t.Fatalf("get: %+v %v", got, err)
	}
	if l, _ := s.ListDeadLetters(ctx, "kafka/publish", 10); len(l) != 1 {
		t.Fatalf("list: %d", len(l))
	}
	if l, _ := s.ListDeadLetters(ctx, "other", 10); len(l) != 0 {
		t.Fatalf("list other: %d", len(l))
	}
	if err := s.DeleteDeadLetter(ctx, dl.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDeadLetter(ctx, dl.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func testIdempotency(t *testing.T, s store.Store) {
	ctx := context.Background()
	rec := store.IdempotencyRecord{Key: "k1", RequestHash: "h", StatusCode: 201, Body: []byte(`{"id":1}`), CreatedAt: time.Now().UTC()}
	if err := s.PutIdempotency(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := s.PutIdempotency(ctx, rec); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("dup key: %v", err)
	}
	got, err := s.GetIdempotency(ctx, "k1")
	if err != nil || got.StatusCode != 201 || string(got.Body) != `{"id":1}` {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := s.GetIdempotency(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}
