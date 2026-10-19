package memory

import (
	"context"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func (s *Store) QueryEvents(_ context.Context, q store.EventQuery) ([]sdk.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []sdk.Event
	for i := len(s.events) - 1; i >= 0 && (q.Limit <= 0 || len(out) < q.Limit); i-- {
		if q.Match(s.events[i]) {
			out = append(out, s.events[i])
		}
	}
	return out, nil
}

func (s *Store) PruneEvents(_ context.Context, before time.Time, maxSeq int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Only a prefix can go, to keep Seq usable as an index; events are
	// appended in time order, so the prefix holds the oldest.
	n := 0
	for n < len(s.events) && s.events[n].Seq <= maxSeq && s.events[n].Time.Before(before) {
		n++
	}
	s.events = append([]sdk.Event(nil), s.events[n:]...)
	s.pruned += int64(n)
	return int64(n), nil
}
