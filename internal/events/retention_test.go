package events

import (
	"context"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func TestPruneKeepsUnprocessedEvents(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	appendEvents(t, s, "a", "b", "c", "d")
	d := NewDispatcher(s, discard, nil, Config{})
	noop := func(context.Context, sdk.Event) error { return nil }
	for _, name := range []string{"fast", "slow"} {
		if err := d.Add(Subscription{Name: name, Handler: noop}); err != nil {
			t.Fatal(err)
		}
	}
	future := time.Now().Add(time.Hour)
	if err := s.SetCursor(ctx, "fast", 3); err != nil {
		t.Fatal(err)
	}
	if n, err := d.Prune(ctx, future); err != nil || n != 0 {
		t.Fatalf("pruned before every subscription started: %d %v", n, err)
	}
	if err := s.SetCursor(ctx, "slow", 2); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.Prune(ctx, future); n != 2 {
		t.Fatalf("pruned %d, want 2 (slowest cursor)", n)
	}
	if n, _ := d.Prune(ctx, time.Time{}); n != 0 {
		t.Fatalf("pruned events newer than the cutoff: %d", n)
	}
	rest, _ := s.ReadEvents(ctx, 0, 0)
	if len(rest) != 2 || rest[0].Type != "c" {
		t.Fatalf("remaining: %+v", rest)
	}
}
