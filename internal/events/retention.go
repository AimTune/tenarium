package events

import (
	"context"
	"log/slog"
	"time"
)

// Prune deletes events older than before that every registered
// subscription has processed. A subscription that has not started yet
// holds back everything, so no event is lost to it.
func (d *Dispatcher) Prune(ctx context.Context, before time.Time) (int64, error) {
	maxSeq, err := d.store.LastEventSeq(ctx)
	if err != nil {
		return 0, err
	}
	for _, name := range d.Subscriptions() {
		seq, found, err := d.store.GetCursor(ctx, name)
		if err != nil {
			return 0, err
		}
		if !found {
			return 0, nil
		}
		maxSeq = min(maxSeq, seq)
	}
	if maxSeq <= 0 {
		return 0, nil
	}
	return d.store.PruneEvents(ctx, before, maxSeq)
}

// RunRetention prunes events older than retention every interval until ctx
// ends.
func (d *Dispatcher) RunRetention(ctx context.Context, retention, interval time.Duration, log *slog.Logger) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		n, err := d.Prune(ctx, time.Now().Add(-retention))
		switch {
		case err != nil && ctx.Err() == nil:
			log.Error("event retention failed", "err", err)
		case n > 0:
			log.Info("pruned events", "count", n, "retention", retention)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
