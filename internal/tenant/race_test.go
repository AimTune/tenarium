package tenant

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/internal/store/postgres/pgtest"
)

// stores runs fn against the memory store and, if configured, PostgreSQL,
// where READ COMMITTED makes check-then-write races real.
func stores(t *testing.T, fn func(t *testing.T, s store.Store)) {
	t.Run("memory", func(t *testing.T) { fn(t, memory.New()) })
	t.Run("postgres", func(t *testing.T) { fn(t, pgtest.Open(t)) })
}

func TestConcurrentDeleteParentAndCreateChild(t *testing.T) {
	stores(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		svc := NewService(s, Options{})
		for i := range 30 {
			parent, err := svc.Create(ctx, CreateInput{Slug: fmt.Sprintf("p%d", i), Name: "P"})
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			var childErr, delErr error
			wg.Go(func() {
				_, childErr = svc.Create(ctx, CreateInput{Slug: fmt.Sprintf("c%d", i), Name: "C", ParentID: parent.ID})
			})
			wg.Go(func() { _, delErr = svc.Delete(ctx, parent.ID) })
			wg.Wait()
			if childErr == nil && delErr == nil {
				t.Fatalf("round %d: parent deleted while a live child was created", i)
			}
		}
	})
}

func TestConcurrentMembersRespectLimit(t *testing.T) {
	stores(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		svc := NewService(s, Options{})
		tn, err := svc.Create(ctx, CreateInput{Slug: "m", Name: "M", Limits: map[string]int64{MetricMembers: 2}})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for i := range 20 {
			wg.Go(func() {
				_, _ = svc.AddMember(ctx, tn.ID, MemberInput{Email: fmt.Sprintf("u%d@example.com", i), Role: "member"})
			})
		}
		wg.Wait()
		ms, _ := svc.ListMembers(ctx, tn.ID)
		if len(ms) != 2 {
			t.Fatalf("%d members, limit is 2", len(ms))
		}
	})
}

func TestChildInheritsPlanAndUUIDSlugsRejected(t *testing.T) {
	ctx := context.Background()
	svc := NewService(memory.New(), Options{})
	org, _ := svc.Create(ctx, CreateInput{Slug: "org", Name: "Org", Plan: "pro"})
	ws, err := svc.Create(ctx, CreateInput{Slug: "ws", Name: "WS", ParentID: org.ID})
	if err != nil || ws.Plan != "pro" {
		t.Fatalf("child plan: %+v %v", ws, err)
	}
	var ve *ValidationError
	for _, slug := range []string{org.ID, "0123456789abcdef0123456789abcdef"} {
		if _, err := svc.Create(ctx, CreateInput{Slug: slug, Name: "x"}); !errors.As(err, &ve) {
			t.Errorf("slug %q accepted: %v", slug, err)
		}
	}
}
