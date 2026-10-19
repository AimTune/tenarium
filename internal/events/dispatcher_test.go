package events

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/pkg/sdk"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func appendEvents(t *testing.T, s store.Store, types ...string) {
	t.Helper()
	err := s.InTx(context.Background(), func(tx store.Tx) error {
		for _, typ := range types {
			if _, err := tx.AppendEvents(context.Background(), sdk.Event{ID: typ, Type: typ}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func fastOpts(maxAttempts int) sdk.SubscribeOptions {
	return sdk.SubscribeOptions{MaxAttempts: maxAttempts, BaseBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}
}

func start(t *testing.T, d *Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = d.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type recorder struct {
	mu    sync.Mutex
	types []string
}

func (r *recorder) handle(_ context.Context, e sdk.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.types = append(r.types, e.Type)
	return nil
}

func (r *recorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.types...)
}

func TestDeliversMatchingEventsInOrder(t *testing.T) {
	s := memory.New()
	appendEvents(t, s, "tenant.created", "other.thing", "tenant.updated")

	d := NewDispatcher(s, discard, nil, Config{PollInterval: 10 * time.Millisecond})
	var rec recorder
	if err := d.Add(Subscription{Name: "rec", Filter: sdk.EventFilter{Types: []string{"tenant.*"}}, Handler: rec.handle, Options: fastOpts(3)}); err != nil {
		t.Fatal(err)
	}
	start(t, d)

	eventually(t, func() bool { return len(rec.got()) == 2 })
	if got := rec.got(); got[0] != "tenant.created" || got[1] != "tenant.updated" {
		t.Fatalf("unexpected order %v", got)
	}
	eventually(t, func() bool {
		seq, _, _ := s.GetCursor(context.Background(), "rec")
		return seq == 3
	})

	appendEvents(t, s, "tenant.deleted")
	d.Notify()
	eventually(t, func() bool { return len(rec.got()) == 3 })
}

func TestRetriesThenDeadLettersWithoutBlockingOthers(t *testing.T) {
	s := memory.New()
	appendEvents(t, s, "a", "b")

	d := NewDispatcher(s, discard, nil, Config{PollInterval: 10 * time.Millisecond})
	var calls atomic.Int32
	failing := func(_ context.Context, e sdk.Event) error {
		calls.Add(1)
		if e.Type == "a" {
			return errors.New("boom")
		}
		return nil
	}
	var healthy recorder
	_ = d.Add(Subscription{Name: "failing", Handler: failing, Options: fastOpts(3)})
	_ = d.Add(Subscription{Name: "healthy", Handler: healthy.handle, Options: fastOpts(3)})
	start(t, d)

	eventually(t, func() bool { return len(healthy.got()) == 2 })
	eventually(t, func() bool {
		dls, _ := s.ListDeadLetters(context.Background(), "failing", 0)
		return len(dls) == 1
	})
	dls, _ := s.ListDeadLetters(context.Background(), "failing", 0)
	if dls[0].Event.Type != "a" || dls[0].Attempts != 3 {
		t.Fatalf("unexpected dead letter %+v", dls[0])
	}
	// 3 attempts for "a", then "b" is still delivered.
	eventually(t, func() bool { return calls.Load() == 4 })
}

func TestStartAtEndSkipsHistory(t *testing.T) {
	s := memory.New()
	appendEvents(t, s, "old")

	d := NewDispatcher(s, discard, nil, Config{PollInterval: 10 * time.Millisecond})
	var rec recorder
	opts := fastOpts(1)
	opts.StartAtEnd = true
	_ = d.Add(Subscription{Name: "new", Handler: rec.handle, Options: opts})
	start(t, d)

	eventually(t, func() bool {
		_, found, _ := s.GetCursor(context.Background(), "new")
		return found
	})
	appendEvents(t, s, "fresh")
	d.Notify()
	eventually(t, func() bool { return len(rec.got()) == 1 })
	if rec.got()[0] != "fresh" {
		t.Fatalf("got %v", rec.got())
	}
}

func TestHandlerPanicIsRecovered(t *testing.T) {
	s := memory.New()
	appendEvents(t, s, "x")
	d := NewDispatcher(s, discard, nil, Config{PollInterval: 10 * time.Millisecond})
	_ = d.Add(Subscription{Name: "p", Handler: func(context.Context, sdk.Event) error { panic("oops") }, Options: fastOpts(2)})
	start(t, d)
	eventually(t, func() bool {
		dls, _ := s.ListDeadLetters(context.Background(), "p", 0)
		return len(dls) == 1
	})
}

func TestLeaseGivesExclusiveProcessingAndFailover(t *testing.T) {
	s := memory.New()
	var mu sync.Mutex
	byInstance := map[string]int{}
	count := func(id string) int {
		mu.Lock()
		defer mu.Unlock()
		return byInstance[id]
	}
	mk := func(id string) *Dispatcher {
		d := NewDispatcher(s, discard, nil, Config{PollInterval: 10 * time.Millisecond, InstanceID: id, LeaseTTL: 300 * time.Millisecond})
		_ = d.Add(Subscription{Name: "shared", Options: fastOpts(1), Handler: func(context.Context, sdk.Event) error {
			mu.Lock()
			byInstance[id]++
			mu.Unlock()
			return nil
		}})
		return d
	}

	// a starts first and takes the lease.
	a := mk("a")
	ctxA, stopA := context.WithCancel(context.Background())
	doneA := make(chan struct{})
	go func() { _ = a.Run(ctxA); close(doneA) }()
	defer func() { stopA(); <-doneA }()
	appendEvents(t, s, "e1")
	eventually(t, func() bool { return count("a") == 1 })

	// b joins but must not process while a holds the lease.
	b := mk("b")
	start(t, b)
	appendEvents(t, s, "e2", "e3")
	a.Notify()
	b.Notify()
	eventually(t, func() bool { return count("a") == 3 })
	time.Sleep(100 * time.Millisecond)
	if count("b") != 0 {
		t.Fatalf("b processed %d events while a held the lease", count("b"))
	}

	// a stops (releasing its lease); b takes over from the shared cursor.
	stopA()
	<-doneA
	appendEvents(t, s, "e4")
	b.Notify()
	eventually(t, func() bool { return count("b") == 1 })
	if count("a")+count("b") != 4 {
		t.Fatalf("events processed %v, want exactly 4", byInstance)
	}
}

func TestReplayDeadLetter(t *testing.T) {
	s := memory.New()
	appendEvents(t, s, "x")
	var fail atomic.Bool
	fail.Store(true)
	d := NewDispatcher(s, discard, nil, Config{PollInterval: 10 * time.Millisecond})
	_ = d.Add(Subscription{Name: "r", Options: fastOpts(1), Handler: func(context.Context, sdk.Event) error {
		if fail.Load() {
			return errors.New("down")
		}
		return nil
	}})
	start(t, d)
	var dls []store.DeadLetter
	eventually(t, func() bool {
		dls, _ = s.ListDeadLetters(context.Background(), "r", 0)
		return len(dls) == 1
	})
	if err := d.Replay(context.Background(), dls[0].ID); err == nil {
		t.Fatal("replay should fail while handler fails")
	}
	fail.Store(false)
	if err := d.Replay(context.Background(), dls[0].ID); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.ListDeadLetters(context.Background(), "r", 0); len(left) != 0 {
		t.Fatal("dead letter not removed after successful replay")
	}
}

func TestProducerLink(t *testing.T) {
	if l := producerLink(sdk.Event{}); l != nil {
		t.Fatalf("untraced: %v", l)
	}
	if l := producerLink(sdk.Event{TraceParent: "garbage"}); l != nil {
		t.Fatalf("invalid: %v", l)
	}
	l := producerLink(sdk.Event{TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"})
	if len(l) != 1 || l[0].SpanContext.TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("link: %v", l)
	}
}

func TestLeaseAffinityPrefersTheSubscriptionsRegion(t *testing.T) {
	s := memory.New()
	var mu sync.Mutex
	byInstance := map[string]int{}
	count := func(id string) int {
		mu.Lock()
		defer mu.Unlock()
		return byInstance[id]
	}
	mk := func(id, region string) *Dispatcher {
		d := NewDispatcher(s, discard, nil, Config{PollInterval: 10 * time.Millisecond, InstanceID: id, Region: region, LeaseTTL: 300 * time.Millisecond})
		_ = d.Add(Subscription{Name: "eu-provisioner", Regions: []string{"eu"}, Options: fastOpts(1), Handler: func(context.Context, sdk.Event) error {
			mu.Lock()
			byInstance[id]++
			mu.Unlock()
			return nil
		}})
		return d
	}

	// Only an instance elsewhere: it processes rather than nobody.
	us := mk("us-1", "us")
	start(t, us)
	appendEvents(t, s, "e1")
	eventually(t, func() bool { return count("us-1") == 1 })

	// An instance in the preferred region joins and takes over.
	eu := mk("eu-1", "eu")
	start(t, eu)
	eventually(t, func() bool {
		appendEvents(t, s, "probe")
		us.Notify()
		eu.Notify()
		time.Sleep(50 * time.Millisecond)
		return count("eu-1") > 0
	})
	before := count("us-1")
	appendEvents(t, s, "e2", "e3")
	eu.Notify()
	us.Notify()
	time.Sleep(500 * time.Millisecond)
	if count("us-1") != before {
		t.Fatalf("instance outside the region kept processing: %v", byInstance)
	}
}
