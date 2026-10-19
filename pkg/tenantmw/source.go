package tenantmw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Source loads a tenant's state by ID or slug. It returns ErrNotFound (or
// an error matching it) for unknown tenants.
type Source interface {
	Tenant(ctx context.Context, idOrSlug string) (*Tenant, error)
}

// SourceFunc adapts a function to Source.
type SourceFunc func(ctx context.Context, idOrSlug string) (*Tenant, error)

func (f SourceFunc) Tenant(ctx context.Context, idOrSlug string) (*Tenant, error) {
	return f(ctx, idOrSlug)
}

// APISource loads tenants from the Tenarium REST API (GET tenant plus
// entitlements). Wrap it in CachingSource: it makes two calls per load.
func APISource(baseURL, apiKey string, opts ...ClientOption) Source {
	return NewClient(baseURL, apiKey, opts...)
}

// DefaultRedisPrefix is the redis plugin's default key_prefix.
const DefaultRedisPrefix = "tenarium:"

// RedisSource reads tenants from the cache maintained by Tenarium's redis
// plugin: "<prefix>tenant:<id>" holds the tenant JSON and
// "<prefix>tenant-slug:<slug>" its ID. prefix defaults to "tenarium:".
// Tenants missing from the cache are reported as ErrNotFound, so enable
// the plugin's cache and resync it before relying on this source.
func RedisSource(client redis.Cmdable, prefix string) Source {
	if prefix == "" {
		prefix = DefaultRedisPrefix
	}
	return &redisSource{client: client, prefix: prefix}
}

type redisSource struct {
	client redis.Cmdable
	prefix string
}

func (s *redisSource) Tenant(ctx context.Context, idOrSlug string) (*Tenant, error) {
	raw, err := s.client.Get(ctx, s.prefix+"tenant:"+idOrSlug).Bytes()
	if errors.Is(err, redis.Nil) {
		var id string
		if id, err = s.client.Get(ctx, s.prefix+"tenant-slug:"+idOrSlug).Result(); err == nil {
			raw, err = s.client.Get(ctx, s.prefix+"tenant:"+id).Bytes()
		}
	}
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("tenantmw: redis: %w", err)
	}
	var t Tenant
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("tenantmw: decode cached tenant: %w", err)
	}
	return &t, nil
}

// CachedSource is an in-memory TTL cache in front of a Source.
type CachedSource struct {
	src   Source
	cache *ttlCache[*Tenant]
}

// CachingSource caches src's answers for ttl. Unknown tenants are cached
// too (negative caching, for NegativeTTL which defaults to ttl), other
// errors are not. Concurrent misses for the same key share one load.
func CachingSource(src Source, ttl time.Duration) *CachedSource {
	return &CachedSource{src: src, cache: newTTLCache[*Tenant](ttl)}
}

// SetNegativeTTL changes how long unknown tenants are remembered; 0
// disables negative caching. Call it before use.
func (c *CachedSource) SetNegativeTTL(d time.Duration) *CachedSource {
	c.cache.negTTL = d
	return c
}

// SetMaxEntries bounds the cache size (default 10000). Call it before use.
func (c *CachedSource) SetMaxEntries(n int) *CachedSource {
	c.cache.max = n
	return c
}

func (c *CachedSource) Tenant(ctx context.Context, idOrSlug string) (*Tenant, error) {
	return c.cache.get(ctx, idOrSlug, func(ctx context.Context) (*Tenant, error) {
		return c.src.Tenant(ctx, idOrSlug)
	})
}

// Invalidate drops a cached entry, e.g. on a tenant.* event.
func (c *CachedSource) Invalidate(idOrSlug string) { c.cache.del(idOrSlug) }

// Purge drops all cached entries.
func (c *CachedSource) Purge() { c.cache.purge() }

// CachingDomains caches a DomainResolver's answers (including unknown
// hosts) for ttl.
func CachingDomains(d DomainResolver, ttl time.Duration) DomainResolver {
	return &cachedDomains{d: d, cache: newTTLCache[Domain](ttl)}
}

type cachedDomains struct {
	d     DomainResolver
	cache *ttlCache[Domain]
}

func (c *cachedDomains) ResolveDomain(ctx context.Context, host string) (Domain, error) {
	return c.cache.get(ctx, host, func(ctx context.Context) (Domain, error) {
		return c.d.ResolveDomain(ctx, host)
	})
}

// ttlCache is a small TTL cache with negative caching of ErrNotFound and
// deduplication of concurrent loads.
type ttlCache[V any] struct {
	ttl, negTTL time.Duration
	max         int
	now         func() time.Time

	mu       sync.Mutex
	items    map[string]cacheEntry[V]
	inflight map[string]*cacheCall[V]
}

type cacheEntry[V any] struct {
	v   V
	err error
	exp time.Time
}

type cacheCall[V any] struct {
	done chan struct{}
	v    V
	err  error
}

func newTTLCache[V any](ttl time.Duration) *ttlCache[V] {
	return &ttlCache[V]{
		ttl: ttl, negTTL: ttl, max: 10000, now: time.Now,
		items: map[string]cacheEntry[V]{}, inflight: map[string]*cacheCall[V]{},
	}
}

func (c *ttlCache[V]) get(ctx context.Context, key string, load func(context.Context) (V, error)) (V, error) {
	c.mu.Lock()
	if e, ok := c.items[key]; ok && c.now().Before(e.exp) {
		c.mu.Unlock()
		return e.v, e.err
	}
	call, ok := c.inflight[key]
	if !ok {
		call = &cacheCall[V]{done: make(chan struct{})}
		c.inflight[key] = call
		// The load outlives a canceled caller so waiters still get a result.
		go c.run(context.WithoutCancel(ctx), key, call, load)
	}
	c.mu.Unlock()
	select {
	case <-call.done:
		return call.v, call.err
	case <-ctx.Done():
		var zero V
		return zero, ctx.Err()
	}
}

func (c *ttlCache[V]) run(ctx context.Context, key string, call *cacheCall[V], load func(context.Context) (V, error)) {
	defer close(call.done)
	defer func() {
		if p := recover(); p != nil {
			call.err = fmt.Errorf("tenantmw: source panicked: %v", p)
			c.mu.Lock()
			delete(c.inflight, key)
			c.mu.Unlock()
		}
	}()
	call.v, call.err = load(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.inflight, key)
	ttl := c.ttl
	switch {
	case call.err == nil:
	case errors.Is(call.err, ErrNotFound):
		ttl = c.negTTL
	default:
		return
	}
	if ttl <= 0 {
		return
	}
	if len(c.items) >= c.max {
		c.evict()
	}
	c.items[key] = cacheEntry[V]{v: call.v, err: call.err, exp: c.now().Add(ttl)}
}

// evict drops expired entries, then arbitrary ones down to 90% of max.
func (c *ttlCache[V]) evict() {
	now := c.now()
	for k, e := range c.items {
		if !now.Before(e.exp) {
			delete(c.items, k)
		}
	}
	for k := range c.items {
		if len(c.items) < c.max*9/10 {
			break
		}
		delete(c.items, k)
	}
}

func (c *ttlCache[V]) del(key string) {
	c.mu.Lock()
	delete(c.items, key)
	c.mu.Unlock()
}

func (c *ttlCache[V]) purge() {
	c.mu.Lock()
	clear(c.items)
	c.mu.Unlock()
}
