package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/redis/go-redis/v9"
)

// CachedTenant is the JSON stored under "<prefix>tenant:<id>".
type CachedTenant struct {
	ID        string            `json:"id"`
	Slug      string            `json:"slug"`
	Name      string            `json:"name"`
	Status    sdk.TenantStatus  `json:"status"`
	Plan      string            `json:"plan,omitempty"`
	ParentID  string            `json:"parent_id,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Features  map[string]bool   `json:"features"`
	Limits    map[string]int64  `json:"limits"`
	Version   int64             `json:"version"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// HasFeature reports whether feature is enabled.
func (c CachedTenant) HasFeature(feature string) bool { return c.Features[feature] }

// Limit returns the limit for metric and whether one is set. Absent limits
// mean unlimited.
func (c CachedTenant) Limit(metric string) (int64, bool) {
	v, ok := c.Limits[metric]
	return v, ok
}

// ErrNotCached is returned by ReadTenant when the tenant is not in the cache.
var ErrNotCached = errors.New("tenant not cached")

// ReadTenant reads a tenant cached by the plugin. prefix is the plugin's
// key_prefix ("tenarium:" by default); idOrSlug is a tenant ID or slug.
func ReadTenant(ctx context.Context, client *redis.Client, prefix, idOrSlug string) (CachedTenant, error) {
	raw, err := client.Get(ctx, tenantKey(prefix, idOrSlug)).Bytes()
	if errors.Is(err, redis.Nil) {
		var id string
		if id, err = client.Get(ctx, slugKey(prefix, idOrSlug)).Result(); err == nil {
			raw, err = client.Get(ctx, tenantKey(prefix, id)).Bytes()
		}
	}
	if errors.Is(err, redis.Nil) {
		return CachedTenant{}, ErrNotCached
	} else if err != nil {
		return CachedTenant{}, err
	}
	var t CachedTenant
	if err := json.Unmarshal(raw, &t); err != nil {
		return CachedTenant{}, fmt.Errorf("decode cached tenant: %w", err)
	}
	return t, nil
}

func tenantKey(prefix, id string) string { return prefix + "tenant:" + id }
func slugKey(prefix, slug string) string { return prefix + "tenant-slug:" + slug }

// writeScript stores a tenant unless the cached version is newer, and drops
// the slug key of a previous slug that still points at the tenant.
//
// KEYS: tenant key, slug key. ARGV: json, version, ttl ms, slug key prefix,
// tenant ID.
var writeScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
if cur then
  local ok, old = pcall(cjson.decode, cur)
  if ok and type(old) == 'table' then
    if tonumber(old.version) and tonumber(old.version) > tonumber(ARGV[2]) then
      return 0
    end
    if type(old.slug) == 'string' and old.slug ~= '' and ARGV[4] .. old.slug ~= KEYS[2] then
      local k = ARGV[4] .. old.slug
      if redis.call('GET', k) == ARGV[5] then redis.call('DEL', k) end
    end
  end
end
local ttl = tonumber(ARGV[3])
if ttl > 0 then
  redis.call('SET', KEYS[1], ARGV[1], 'PX', ttl)
  redis.call('SET', KEYS[2], ARGV[5], 'PX', ttl)
else
  redis.call('SET', KEYS[1], ARGV[1])
  redis.call('SET', KEYS[2], ARGV[5])
end
return 1
`)

// deleteScript removes a tenant unless the cached version is newer.
//
// KEYS: tenant key, slug key. ARGV: version, slug key prefix, tenant ID.
var deleteScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
if cur then
  local ok, old = pcall(cjson.decode, cur)
  if ok and type(old) == 'table' then
    if tonumber(old.version) and tonumber(old.version) > tonumber(ARGV[1]) then
      return 0
    end
    if type(old.slug) == 'string' and old.slug ~= '' then
      local k = ARGV[2] .. old.slug
      if redis.call('GET', k) == ARGV[3] then redis.call('DEL', k) end
    end
  end
  redis.call('DEL', KEYS[1])
end
if redis.call('GET', KEYS[2]) == ARGV[3] then redis.call('DEL', KEYS[2]) end
return 1
`)

// cacheEvent keeps the cache in sync with tenant and plan events.
func (p *Plugin) cacheEvent(ctx context.Context, e sdk.Event) error {
	if strings.HasPrefix(e.Type, "rollout.") {
		// A rollout can change any tenant's features.
		_, err := p.recache(ctx, func(sdk.Tenant) bool { return true })
		return err
	}
	if strings.HasPrefix(e.Type, "plan.") {
		if e.Type != sdk.EventPlanUpdated && e.Type != sdk.EventPlanDeleted {
			return nil
		}
		var d sdk.PlanEventData
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return fmt.Errorf("decode plan event: %w", err)
		}
		_, err := p.recache(ctx, func(t sdk.Tenant) bool { return t.Plan == d.Plan.ID || slices.Contains(t.AddOns, d.Plan.ID) })
		return err
	}
	var d sdk.TenantEventData
	if err := json.Unmarshal(e.Data, &d); err != nil {
		// Member and usage events also match tenant.*; they carry no tenant.
		return nil
	}
	if d.Tenant.ID == "" {
		return nil
	}
	if e.Type == sdk.EventTenantDeleted || d.Tenant.Status == sdk.StatusDeleted {
		return p.uncache(ctx, d.Tenant)
	}
	err := p.cache(ctx, d.Tenant)
	if errors.Is(err, sdk.ErrNotFound) {
		// The tenant is gone; a later tenant.deleted removes it.
		return nil
	}
	return err
}

// cache recomputes t's entitlements and stores it unless a newer version is
// cached.
func (p *Plugin) cache(ctx context.Context, t sdk.Tenant) error {
	ent, err := p.host.Entitlements(ctx, t.ID)
	if err != nil {
		return fmt.Errorf("entitlements of %s: %w", t.ID, err)
	}
	body, err := json.Marshal(CachedTenant{
		ID: t.ID, Slug: t.Slug, Name: t.Name, Status: t.Status, Plan: t.Plan, ParentID: t.ParentID,
		Labels: t.Labels, Features: ent.Features, Limits: ent.Limits,
		Version: t.Version, UpdatedAt: t.UpdatedAt,
	})
	if err != nil {
		return err
	}
	prefix := p.cfg.KeyPrefix
	keys := []string{tenantKey(prefix, t.ID), slugKey(prefix, t.Slug)}
	return writeScript.Run(ctx, p.client, keys,
		body, t.Version, p.ttl.Milliseconds(), slugKey(prefix, ""), t.ID).Err()
}

func (p *Plugin) uncache(ctx context.Context, t sdk.Tenant) error {
	prefix := p.cfg.KeyPrefix
	keys := []string{tenantKey(prefix, t.ID), slugKey(prefix, t.Slug)}
	return deleteScript.Run(ctx, p.client, keys, t.Version, slugKey(prefix, ""), t.ID).Err()
}

// recache pages through all live tenants and caches those matching keep.
func (p *Plugin) recache(ctx context.Context, keep func(sdk.Tenant) bool) (int, error) {
	const pageSize = 200
	n, after := 0, ""
	for {
		page, err := p.host.ListTenants(ctx, after, pageSize)
		if err != nil {
			return n, err
		}
		for _, t := range page {
			if !keep(t) {
				continue
			}
			err := p.cache(ctx, t)
			if errors.Is(err, sdk.ErrNotFound) {
				continue
			} else if err != nil {
				return n, err
			}
			n++
		}
		if len(page) < pageSize {
			return n, nil
		}
		after = page[len(page)-1].ID
	}
}

func (p *Plugin) serveTenant(w http.ResponseWriter, r *http.Request) {
	t, err := p.host.GetTenant(r.Context(), r.PathValue("tenant"))
	if errors.Is(err, sdk.ErrNotFound) {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Answer "not found" rather than "forbidden" so callers cannot probe
	// other tenants' slugs.
	res := sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
	if err := p.host.Authorize(r.Context(), sdk.ActionTenantsRead, res); err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}
	raw, err := p.client.Get(r.Context(), tenantKey(p.cfg.KeyPrefix, t.ID)).Bytes()
	if errors.Is(err, redis.Nil) {
		http.Error(w, "tenant not cached", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// serveResync rebuilds the whole cache. Only platform-wide callers may use
// it.
func (p *Plugin) serveResync(w http.ResponseWriter, r *http.Request) {
	pr, ok := sdk.PrincipalFrom(r.Context())
	if !ok || pr.TenantID != "" ||
		p.host.Authorize(r.Context(), sdk.ActionTenantsRead, sdk.Resource{Type: "tenant"}) != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	n, err := p.recache(r.Context(), func(sdk.Tenant) bool { return true })
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"tenants":` + strconv.Itoa(n) + "}\n"))
}
