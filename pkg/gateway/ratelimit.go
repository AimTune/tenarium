package gateway

import (
	"context"
	"hash/maphash"
	"math"
	"sync"
	"time"
)

// Limit is a token bucket: Burst tokens, refilled at Rate tokens per
// second. Every request takes one token.
type Limit struct {
	Rate  float64
	Burst int64
}

// Decision is a limiter's answer.
type Decision struct {
	Allowed bool
	// Limit is the bucket size.
	Limit int64
	// Remaining is the number of tokens left after this request.
	Remaining int64
	// RetryAfter is, for denials, the time until a token is available.
	RetryAfter time.Duration
	// Reset is the time until the bucket is full again.
	Reset time.Duration
}

// Limiter takes one token from key's bucket.
type Limiter interface {
	Allow(ctx context.Context, key string, l Limit) (Decision, error)
}

// LocalLimiter is an in-memory token bucket limiter. Each replica limits on
// its own: with N replicas behind a round-robin balancer a tenant gets up
// to N times its rate. Use RedisLimiter for a shared limit.
type LocalLimiter struct {
	now    func() time.Time
	seed   maphash.Seed
	shards [64]localShard
}

type localShard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	sweepAt int
}

type bucket struct {
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
}

// minSweep is the bucket count per shard that triggers the first sweep.
const minSweep = 1024

// LocalOption configures a LocalLimiter.
type LocalOption func(*LocalLimiter)

// WithClock sets the limiter's clock (default time.Now); for tests.
func WithClock(now func() time.Time) LocalOption { return func(l *LocalLimiter) { l.now = now } }

// NewLocalLimiter returns an in-memory limiter.
func NewLocalLimiter(opts ...LocalOption) *LocalLimiter {
	l := &LocalLimiter{now: time.Now, seed: maphash.MakeSeed()}
	for i := range l.shards {
		l.shards[i].buckets = map[string]*bucket{}
		l.shards[i].sweepAt = minSweep
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

// Allow takes a token from key's bucket. A bucket starts full; a changed
// limit applies from the next call (tokens are capped at the new burst).
func (l *LocalLimiter) Allow(_ context.Context, key string, lim Limit) (Decision, error) {
	if lim.Rate <= 0 || lim.Burst <= 0 {
		return Decision{Limit: max(lim.Burst, 0)}, nil
	}
	now := l.now()
	burst := float64(lim.Burst)
	s := &l.shards[maphash.String(l.seed, key)%uint64(len(l.shards))]
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[key]
	if b == nil {
		if len(s.buckets) >= s.sweepAt {
			s.sweep(now)
		}
		b = &bucket{tokens: burst, last: now}
		s.buckets[key] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * lim.Rate
		b.last = now
	}
	b.rate, b.burst = lim.Rate, burst
	b.tokens = min(b.tokens, burst)
	d := Decision{Limit: lim.Burst}
	if b.tokens >= 1 {
		b.tokens--
		d.Allowed = true
	} else {
		d.RetryAfter = seconds((1 - b.tokens) / lim.Rate)
	}
	d.Remaining = int64(math.Floor(b.tokens))
	d.Reset = seconds((burst - b.tokens) / lim.Rate)
	return d, nil
}

// sweep drops buckets that have refilled completely: they are
// indistinguishable from new ones.
func (s *localShard) sweep(now time.Time) {
	for k, b := range s.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*b.rate >= b.burst {
			delete(s.buckets, k)
		}
	}
	s.sweepAt = max(minSweep, 2*len(s.buckets))
}

// Len returns the number of tracked buckets.
func (l *LocalLimiter) Len() int {
	n := 0
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		n += len(s.buckets)
		s.mu.Unlock()
	}
	return n
}

func seconds(s float64) time.Duration {
	return time.Duration(math.Ceil(s * float64(time.Second)))
}
