package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func testEventQueries(t *testing.T, s store.Store) {
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	mk := func(i int, typ, tenantID, actor string) sdk.Event {
		e := Event(typ)
		e.TenantID, e.Actor, e.Time = tenantID, actor, base.Add(time.Duration(i)*time.Minute)
		return e
	}
	all := []sdk.Event{
		mk(0, "tenant.created", "t1", "user:a"),
		mk(1, "tenant.updated", "t1", "user:b"),
		mk(2, "member.added", "t1", "user:a"),
		mk(3, "tenant.created", "t2", "user:a"),
		mk(4, "plan.updated", "", "user:b"),
		mk(5, "tenant_x.odd", "t2", "user:a"), // "_" must not act as a LIKE wildcard
	}
	mustTx(t, s, func(tx store.Tx) error { _, err := tx.AppendEvents(ctx, all...); return err })

	seqs := func(q store.EventQuery) []int64 {
		t.Helper()
		evts, err := s.QueryEvents(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		out := []int64{}
		for _, e := range evts {
			out = append(out, e.Seq)
		}
		return out
	}
	eq := func(name string, got []int64, want ...int64) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: got %v, want %v", name, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%s: got %v, want %v", name, got, want)
			}
		}
	}
	eq("all newest first", seqs(store.EventQuery{}), 6, 5, 4, 3, 2, 1)
	eq("limit", seqs(store.EventQuery{Limit: 2}), 6, 5)
	eq("before", seqs(store.EventQuery{Before: 5, Limit: 2}), 4, 3)
	eq("tenant", seqs(store.EventQuery{TenantIDs: []string{"t1"}}), 3, 2, 1)
	eq("tenants", seqs(store.EventQuery{TenantIDs: []string{"t1", "t2"}, Limit: 3}), 6, 4, 3)
	eq("actor", seqs(store.EventQuery{Actor: "user:b"}), 5, 2)
	eq("exact type", seqs(store.EventQuery{Types: []string{"tenant.created"}}), 4, 1)
	eq("prefix type", seqs(store.EventQuery{Types: []string{"tenant.*"}}), 4, 2, 1)
	eq("mixed types", seqs(store.EventQuery{Types: []string{"tenant.*", "plan.updated"}}), 5, 4, 2, 1)
	eq("time range", seqs(store.EventQuery{Since: base.Add(time.Minute), Until: base.Add(3 * time.Minute)}), 3, 2)
	eq("combined", seqs(store.EventQuery{TenantIDs: []string{"t1"}, Actor: "user:a", Types: []string{"tenant.*"}}), 1)

	// Pruning: only old events up to maxSeq go; numbering continues.
	n, err := s.PruneEvents(ctx, base.Add(150*time.Second), 2)
	if err != nil || n != 2 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if n, _ := s.PruneEvents(ctx, base.Add(time.Hour), 2); n != 0 {
		t.Fatalf("pruned past maxSeq: %d", n)
	}
	rest, _ := s.ReadEvents(ctx, 0, 0)
	if len(rest) != 4 || rest[0].Seq != 3 {
		t.Fatalf("after prune: %+v", rest)
	}
	if r, _ := s.ReadEvents(ctx, 4, 1); len(r) != 1 || r[0].Seq != 5 {
		t.Fatalf("read after prune: %+v", r)
	}
	if last, _ := s.LastEventSeq(ctx); last != 6 {
		t.Fatalf("last seq: %d", last)
	}
	appended := mustAppend(t, s, Event("x"))
	if appended.Seq != 7 {
		t.Fatalf("seq after prune: %d", appended.Seq)
	}
	eq("query after prune", seqs(store.EventQuery{Limit: 2}), 7, 6)
}

func mustAppend(t *testing.T, s store.Store, e sdk.Event) sdk.Event {
	t.Helper()
	var out []sdk.Event
	mustTx(t, s, func(tx store.Tx) error {
		var err error
		out, err = tx.AppendEvents(context.Background(), e)
		return err
	})
	return out[0]
}
