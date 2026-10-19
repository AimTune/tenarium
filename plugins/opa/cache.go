package opa

import (
	"sync"
	"time"
)

// decisionCache is a small TTL cache of policy results. Only definite
// answers from the server are cached, never errors.
type decisionCache struct {
	mu  sync.Mutex
	ttl time.Duration
	max int
	now func() time.Time
	m   map[string]cacheEntry
}

type cacheEntry struct {
	result  Result
	expires time.Time
}

func newDecisionCache(ttl time.Duration, max int) *decisionCache {
	return &decisionCache{ttl: ttl, max: max, now: time.Now, m: map[string]cacheEntry{}}
}

func (c *decisionCache) get(key string) (Result, bool) {
	if c == nil || c.ttl <= 0 {
		return Result{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return Result{}, false
	}
	if !c.now().Before(e.expires) {
		delete(c.m, key)
		return Result{}, false
	}
	return e.result, true
}

func (c *decisionCache) put(key string, r Result) {
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
	c.m[key] = cacheEntry{result: r, expires: now.Add(c.ttl)}
}
