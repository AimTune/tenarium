package gateway_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/gateway"
	"github.com/prometheus/client_golang/prometheus"
)

func TestLocalLimiterBucket(t *testing.T) {
	clock := newFakeClock()
	l := gateway.NewLocalLimiter(gateway.WithClock(clock.Now))
	ctx := context.Background()
	lim := gateway.Limit{Rate: 2, Burst: 4} // a token every 500ms

	for i := range 4 {
		d, _ := l.Allow(ctx, "a", lim)
		if !d.Allowed || d.Remaining != int64(3-i) || d.Limit != 4 {
			t.Fatalf("request %d: %+v", i, d)
		}
	}
	d, _ := l.Allow(ctx, "a", lim)
	if d.Allowed || d.RetryAfter != 500*time.Millisecond || d.Reset != 2*time.Second || d.Remaining != 0 {
		t.Fatalf("over limit: %+v", d)
	}
	// Other keys are independent.
	if d, _ := l.Allow(ctx, "b", lim); !d.Allowed || d.Remaining != 3 {
		t.Fatalf("key b: %+v", d)
	}
	clock.Advance(250 * time.Millisecond)
	if d, _ := l.Allow(ctx, "a", lim); d.Allowed || d.RetryAfter != 250*time.Millisecond {
		t.Fatalf("half token: %+v", d)
	}
	clock.Advance(250 * time.Millisecond)
	if d, _ := l.Allow(ctx, "a", lim); !d.Allowed || d.Remaining != 0 {
		t.Fatalf("refilled token: %+v", d)
	}
	// Refill is capped at the burst.
	clock.Advance(time.Hour)
	for i := range 4 {
		if d, _ := l.Allow(ctx, "a", lim); !d.Allowed {
			t.Fatalf("after idle, request %d denied", i)
		}
	}
	if d, _ := l.Allow(ctx, "a", lim); d.Allowed {
		t.Fatal("burst exceeded after idle")
	}

	// Lowering the burst caps the stored tokens.
	clock.Advance(time.Hour)
	if d, _ := l.Allow(ctx, "a", gateway.Limit{Rate: 1, Burst: 1}); !d.Allowed || d.Remaining != 0 {
		t.Fatalf("lowered limit: %+v", d)
	}
	if d, _ := l.Allow(ctx, "a", gateway.Limit{Rate: 1, Burst: 1}); d.Allowed || d.RetryAfter != time.Second {
		t.Fatalf("lowered limit, second: %+v", d)
	}

	// A zero limit denies.
	if d, _ := l.Allow(ctx, "z", gateway.Limit{}); d.Allowed {
		t.Fatal("zero limit allowed")
	}
}

func TestLocalLimiterFractionalRate(t *testing.T) {
	clock := newFakeClock()
	l := gateway.NewLocalLimiter(gateway.WithClock(clock.Now))
	lim := gateway.Limit{Rate: 1.0 / 60, Burst: 1} // one per minute
	if d, _ := l.Allow(context.Background(), "k", lim); !d.Allowed {
		t.Fatal("first denied")
	}
	d, _ := l.Allow(context.Background(), "k", lim)
	if d.Allowed || d.RetryAfter != time.Minute {
		t.Fatalf("%+v", d)
	}
	clock.Advance(59 * time.Second)
	if d, _ := l.Allow(context.Background(), "k", lim); d.Allowed || d.RetryAfter > time.Second+time.Millisecond {
		t.Fatalf("%+v", d)
	}
	clock.Advance(time.Second)
	if d, _ := l.Allow(context.Background(), "k", lim); !d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestLocalLimiterSweep(t *testing.T) {
	clock := newFakeClock()
	l := gateway.NewLocalLimiter(gateway.WithClock(clock.Now))
	lim := gateway.Limit{Rate: 10, Burst: 10}
	for i := range 200_000 {
		_, _ = l.Allow(context.Background(), fmt.Sprint("k", i), lim)
	}
	before := l.Len()
	clock.Advance(2 * time.Second) // every bucket is full again
	for i := range 200_000 {
		_, _ = l.Allow(context.Background(), fmt.Sprint("n", i), lim)
	}
	if after := l.Len(); after >= before+200_000 {
		t.Fatalf("no sweep: %d -> %d", before, after)
	}
}

func TestLocalLimiterConcurrent(t *testing.T) {
	clock := newFakeClock()
	l := gateway.NewLocalLimiter(gateway.WithClock(clock.Now))
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if d, _ := l.Allow(context.Background(), "k", gateway.Limit{Rate: 1, Burst: 100}); d.Allowed {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if allowed != 100 {
		t.Fatalf("allowed %d, want 100", allowed)
	}
}

func counterValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	metrics:
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if want, ok := labels[lp.GetName()]; ok && want != lp.GetValue() {
					continue metrics
				}
			}
			return m.GetCounter().GetValue()
		}
	}
	return 0
}

func histogramCount(t *testing.T, reg *prometheus.Registry, name string) uint64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var n uint64
	for _, mf := range mfs {
		if mf.GetName() == name {
			for _, m := range mf.GetMetric() {
				n += m.GetHistogram().GetSampleCount()
			}
		}
	}
	return n
}
