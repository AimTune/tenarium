package events

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// ErrInvalidRange means since is missing or not before until.
var ErrInvalidRange = errors.New("since is required and must be before until")

// MaxReplayEvents bounds one ReplayRange call.
const MaxReplayEvents = 10000

// RangeQuery selects the events ReplayRange redelivers; the subscription's
// own filter applies on top.
type RangeQuery struct {
	Since, Until time.Time
	Types        []string
	TenantIDs    []string
}

// ReplayResult counts the outcome of a ReplayRange.
type ReplayResult struct {
	Matched      int  `json:"matched"`
	Delivered    int  `json:"delivered"`
	DeadLettered int  `json:"dead_lettered"`
	Truncated    bool `json:"truncated,omitempty"`
}

// ReplayRange redelivers the stored events of a time range to one
// subscription, oldest first, without moving its cursor: for example after
// fixing a consumer that acknowledged events it mishandled. Each event is
// tried once; failures become dead letters. Handlers must be idempotent,
// since the events were normally delivered before. Events already pruned by
// retention can only be replayed from an archive.
func (d *Dispatcher) ReplayRange(ctx context.Context, subscription string, q RangeQuery) (ReplayResult, error) {
	var res ReplayResult
	if q.Since.IsZero() || (!q.Until.IsZero() && !q.Until.After(q.Since)) {
		return res, ErrInvalidRange
	}
	d.mu.Lock()
	w := d.worker(subscription)
	d.mu.Unlock()
	if w == nil {
		return res, fmt.Errorf("%w %q", ErrUnknownSubscription, subscription)
	}
	// QueryEvents pages newest first; collect, then deliver in order.
	var all []sdk.Event
	before := int64(0)
	for {
		page, err := d.store.QueryEvents(ctx, store.EventQuery{TenantIDs: q.TenantIDs, Types: q.Types,
			Since: q.Since, Until: q.Until, Before: before, Limit: 500})
		if err != nil {
			return res, err
		}
		for _, e := range page {
			if w.sub.Filter.Match(e) {
				all = append(all, e)
			}
		}
		if len(all) > MaxReplayEvents {
			// Keep the oldest; the caller continues from the last one.
			all, res.Truncated = all[len(all)-MaxReplayEvents:], true
		}
		if len(page) < 500 {
			break
		}
		before = page[len(page)-1].Seq
	}
	slices.Reverse(all)
	res.Matched = len(all)
	for _, e := range all {
		if err := w.call(ctx, e); err != nil {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			if err := d.store.AddDeadLetter(context.WithoutCancel(ctx), store.DeadLetter{
				ID: uuid.Must(uuid.NewV7()).String(), Subscription: subscription, Event: e,
				Error: "replay: " + err.Error(), Attempts: 1, FailedAt: time.Now().UTC(),
			}); err != nil {
				return res, err
			}
			res.DeadLettered++
			continue
		}
		res.Delivered++
	}
	return res, nil
}
