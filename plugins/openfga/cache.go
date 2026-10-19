package openfga

import (
	"sync"
	"time"
)

// decisionCache is a small TTL cache of check results. Only definite
// answers from the server are cached, never errors.
type decisionCache struct {
	mu  sync.Mutex
	ttl time.Duration
	max int
	now func() time.Time
	m   map[string]cacheEntry
}

type cacheEntry struct {
	allowed bool
	expires time.Time
}

func newDecisionCache(ttl time.Duration, max int) *decisionCache {
	return &decisionCache{ttl: ttl, max: max, now: time.Now, m: map[string]cacheEntry{}}
}

func (c *decisionCache) get(key string) (allowed, ok bool) {
	if c == nil || c.ttl <= 0 {
		return false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return false, false
	}
	if !c.now().Before(e.expires) {
		delete(c.m, key)
		return false, false
	}
	return e.allowed, true
}

func (c *decisionCache) put(key string, allowed bool) {
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.m) >= c.max {
		for k, e := range c.m {
			if !now.Before(e.expires) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= c.max {
			clear(c.m)
		}
	}
	c.m[key] = cacheEntry{allowed: allowed, expires: now.Add(c.ttl)}
}

// purge drops every entry, e.g. after tuples were written.
func (c *decisionCache) purge() {
	if c == nil {
		return
	}
	c.mu.Lock()
	clear(c.m)
	c.mu.Unlock()
}
