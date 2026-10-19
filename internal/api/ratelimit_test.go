package api

import (
	"context"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store/memory"
)

func TestSharedRateLimitAcrossReplicas(t *testing.T) {
	st := memory.New()
	a, b := newRateLimiter(3, time.Minute), newRateLimiter(3, time.Minute)
	a.shared, b.shared = st.IncrementRateCounter, st.IncrementRateCounter
	now := time.Now()
	allowed := 0
	for i := range 6 {
		l := a
		if i%2 == 1 {
			l = b
		}
		if l.allow(context.Background(), "192.0.2.1", now) {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("two replicas allowed %d requests, want 3 in total", allowed)
	}
	if !a.allow(context.Background(), "192.0.2.1", now.Add(time.Minute)) {
		t.Fatal("next window refused")
	}
}
