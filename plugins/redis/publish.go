package redis

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/redis/go-redis/v9"
)

// publish writes e to the configured stream or channel. Errors are returned
// so the dispatcher retries.
func (p *Plugin) publish(ctx context.Context, e sdk.Event) error {
	c := p.cfg.Publish
	body, err := json.Marshal(e.CloudEvent())
	if err != nil {
		return err
	}
	if c.Mode == ModePubSub {
		return p.client.Publish(ctx, p.publishKey(c.Channel, e), body).Err()
	}
	return p.client.XAdd(ctx, &redis.XAddArgs{
		Stream: p.publishKey(c.Stream, e),
		MaxLen: c.MaxLen,
		Approx: true,
		Values: []any{
			"type", e.Type,
			"id", e.ID,
			"tenant", e.TenantID,
			"seq", strconv.FormatInt(e.Seq, 10),
			"event", body,
		},
	}).Err()
}

// publishKey returns the prefixed stream or channel for e.
func (p *Plugin) publishKey(name string, e sdk.Event) string {
	if p.cfg.Publish.PerTenant && e.TenantID != "" {
		return p.key(name, ":", e.TenantID)
	}
	return p.key(name)
}
