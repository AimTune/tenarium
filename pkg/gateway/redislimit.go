package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultRedisLimitPrefix prefixes the Redis rate limit keys.
const DefaultRedisLimitPrefix = "tenarium:gw:rl:"

// RedisLimiter is a shared limiter for multi-replica deployments. It runs
// GCRA (the generic cell rate algorithm, equivalent to a token bucket) in a
// Lua script: one key per tenant holding the theoretical arrival time, one
// round trip per check, Redis server time as the clock so replica clock
// skew does not matter. Keys expire once the bucket would be full.
type RedisLimiter struct {
	client redis.Scripter
	prefix string
}

// NewRedisLimiter returns a limiter storing state in client under prefix
// (default DefaultRedisLimitPrefix). Cluster clients work: each script
// touches a single key.
func NewRedisLimiter(client redis.Scripter, prefix string) *RedisLimiter {
	if prefix == "" {
		prefix = DefaultRedisLimitPrefix
	}
	return &RedisLimiter{client: client, prefix: prefix}
}

// gcraScript. KEYS: bucket key. ARGV: emission interval (µs per token),
// burst. Returns {allowed, remaining, retry_after_us, reset_us}.
var gcraScript = redis.NewScript(`
if redis.replicate_commands then redis.replicate_commands() end
local emission = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local tat = tonumber(redis.call('GET', KEYS[1]))
if not tat or tat < now then tat = now end
local tolerance = emission * burst
local new_tat = tat + emission
local allow_at = new_tat - tolerance
if allow_at > now then
  return {0, 0, math.ceil(allow_at - now), math.ceil(tat - now)}
end
redis.call('SET', KEYS[1], string.format('%.0f', new_tat), 'PX', math.ceil((new_tat - now) / 1000) + 1)
local remaining = math.floor((tolerance - (new_tat - now)) / emission)
return {1, remaining, 0, math.ceil(new_tat - now)}
`)

// Allow takes a token from key's bucket.
func (l *RedisLimiter) Allow(ctx context.Context, key string, lim Limit) (Decision, error) {
	if lim.Rate <= 0 || lim.Burst <= 0 {
		return Decision{Limit: max(lim.Burst, 0)}, nil
	}
	emission := 1e6 / lim.Rate
	vals, err := gcraScript.Run(ctx, l.client, []string{l.prefix + key}, emission, lim.Burst).Int64Slice()
	if err != nil {
		return Decision{}, fmt.Errorf("gateway: redis limiter: %w", err)
	}
	if len(vals) != 4 {
		return Decision{}, fmt.Errorf("gateway: redis limiter: unexpected reply %v", vals)
	}
	return Decision{
		Allowed:    vals[0] == 1,
		Limit:      lim.Burst,
		Remaining:  vals[1],
		RetryAfter: time.Duration(vals[2]) * time.Microsecond,
		Reset:      time.Duration(vals[3]) * time.Microsecond,
	}, nil
}
