import { ApiError, QuotaExceededError, type Tenant } from "./types.ts";

/** Loads tenant state by ID or slug; resolves null for unknown tenants. */
export interface Source {
  get(idOrSlug: string): Promise<Tenant | null>;
}

/** A custom hostname mapped to a tenant. */
export interface Domain {
  tenant_id: string;
  slug: string;
  hostname: string;
}

/** Maps custom hostnames to tenants; resolves null for unknown hosts. */
export interface DomainResolver {
  resolveDomain(host: string): Promise<Domain | null>;
}

export interface Usage {
  metric: string;
  value: number;
  /** Absent means unlimited. */
  limit?: number;
}

export interface ClientOptions {
  fetch?: typeof fetch;
  /** Per-request timeout in ms (default 10s). */
  timeoutMs?: number;
}

/** Minimal Tenarium REST client authenticating with an API key. */
export class Client implements Source, DomainResolver {
  readonly baseUrl: string;
  #apiKey: string;
  #fetch: typeof fetch;
  #timeoutMs: number;

  constructor(baseUrl: string, apiKey: string, opts: ClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.#apiKey = apiKey;
    this.#fetch = opts.fetch ?? globalThis.fetch;
    this.#timeoutMs = opts.timeoutMs ?? 10_000;
  }

  async #call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (this.#apiKey) headers.authorization = `Bearer ${this.#apiKey}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    const res = await this.#fetch(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(this.#timeoutMs),
    });
    const text = await res.text();
    if (!res.ok) {
      let code = "", message = res.statusText;
      try {
        const env = JSON.parse(text) as { error?: { code?: string; message?: string } };
        code = env.error?.code ?? "";
        message = env.error?.message ?? message;
      } catch {
        /* not JSON */
      }
      if (res.status === 429) throw new QuotaExceededError(code || "quota_exceeded", message);
      throw new ApiError(res.status, code, message);
    }
    return (text ? JSON.parse(text) : undefined) as T;
  }

  async #orNull<T>(p: Promise<T>): Promise<T | null> {
    try {
      return await p;
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) return null;
      throw err;
    }
  }

  /** The tenant with its effective entitlements, or null if unknown. */
  async get(idOrSlug: string): Promise<Tenant | null> {
    const t = await this.#orNull(this.#call<Tenant>("GET", `/v1/tenants/${encodeURIComponent(idOrSlug)}`));
    if (!t) return null;
    const e = await this.entitlements(t.id);
    return { ...t, features: e.features ?? {}, limits: e.limits ?? {}, plan: e.plan || t.plan };
  }

  entitlements(id: string): Promise<{ tenant_id: string; plan?: string; features: Record<string, boolean>; limits: Record<string, number> }> {
    return this.#call("GET", `/v1/tenants/${encodeURIComponent(id)}/entitlements`);
  }

  /** GET /v1/domains/resolve?host=...; null for unknown hosts. */
  resolveDomain(host: string): Promise<Domain | null> {
    return this.#orNull(this.#call<Domain>("GET", `/v1/domains/resolve?host=${encodeURIComponent(host)}`));
  }

  /** Atomically adds delta; throws QuotaExceededError on 429. */
  recordUsage(tenantId: string, metric: string, delta = 1): Promise<Usage> {
    return this.#call("POST", `/v1/tenants/${encodeURIComponent(tenantId)}/usage/${encodeURIComponent(metric)}`, { delta });
  }
}

/** Tenant state from the Tenarium API (GET tenant + entitlements). */
export function apiSource(baseUrl: string, apiKey: string, opts?: ClientOptions): Source {
  return new Client(baseUrl, apiKey, opts);
}

/** The subset of a Redis client the Redis source needs (ioredis and node-redis both fit). */
export interface RedisLike {
  get(key: string): Promise<string | null>;
}

/**
 * Tenant state from the cache kept by Tenarium's redis plugin:
 * "<prefix>tenant:<id>" (JSON) and "<prefix>tenant-slug:<slug>" (ID).
 */
export function redisSource(client: RedisLike, prefix = "tenarium:"): Source {
  return {
    async get(ref) {
      let raw = await client.get(`${prefix}tenant:${ref}`);
      if (raw == null) {
        const id = await client.get(`${prefix}tenant-slug:${ref}`);
        if (id != null) raw = await client.get(`${prefix}tenant:${id}`);
      }
      if (raw == null) return null;
      const t = JSON.parse(raw) as Tenant;
      return { ...t, features: t.features ?? {}, limits: t.limits ?? {} };
    },
  };
}

/** In-memory TTL cache with negative caching and deduplicated concurrent loads. */
export class TtlCache<V> {
  #ttlMs: number;
  #negativeTtlMs: number;
  #max: number;
  #items = new Map<string, { value: V | null; expires: number }>();
  #inflight = new Map<string, Promise<V | null>>();

  constructor(ttlMs: number, opts: { negativeTtlMs?: number; maxEntries?: number } = {}) {
    this.#ttlMs = ttlMs;
    this.#negativeTtlMs = opts.negativeTtlMs ?? ttlMs;
    this.#max = opts.maxEntries ?? 10_000;
  }

  get(key: string, load: () => Promise<V | null>): Promise<V | null> {
    const hit = this.#items.get(key);
    if (hit && hit.expires > Date.now()) return Promise.resolve(hit.value);
    let p = this.#inflight.get(key);
    if (!p) {
      p = load().then(
        (value) => {
          this.#inflight.delete(key);
          const ttl = value == null ? this.#negativeTtlMs : this.#ttlMs;
          if (ttl > 0) {
            if (this.#items.size >= this.#max) this.#evict();
            this.#items.set(key, { value, expires: Date.now() + ttl });
          }
          return value;
        },
        (err) => {
          this.#inflight.delete(key); // errors are not cached
          throw err;
        },
      );
      this.#inflight.set(key, p);
    }
    return p;
  }

  delete(key: string): void {
    this.#items.delete(key);
  }

  clear(): void {
    this.#items.clear();
  }

  #evict(): void {
    const now = Date.now();
    for (const [k, e] of this.#items) if (e.expires <= now) this.#items.delete(k);
    // Maps iterate in insertion order: drop the oldest entries.
    for (const k of this.#items.keys()) {
      if (this.#items.size < this.#max * 0.9) break;
      this.#items.delete(k);
    }
  }
}

/** A Source with an in-memory TTL cache. */
export interface CachedSource extends Source {
  invalidate(idOrSlug: string): void;
  clear(): void;
}

/** Caches src for ttlMs; unknown tenants are cached for negativeTtlMs (default ttlMs, 0 disables). */
export function cachingSource(src: Source, ttlMs: number, opts?: { negativeTtlMs?: number; maxEntries?: number }): CachedSource {
  const cache = new TtlCache<Tenant>(ttlMs, opts);
  return {
    get: (ref) => cache.get(ref, () => src.get(ref)),
    invalidate: (ref) => cache.delete(ref),
    clear: () => cache.clear(),
  };
}

/** Caches a DomainResolver (including unknown hosts) for ttlMs. */
export function cachingDomains(d: DomainResolver, ttlMs: number): DomainResolver {
  const cache = new TtlCache<Domain>(ttlMs);
  return { resolveDomain: (host) => cache.get(host, () => d.resolveDomain(host)) };
}

/** Records metered usage through the API. */
export class UsageRecorder {
  #client: Client;
  constructor(client: Client) {
    this.#client = client;
  }
  /** Throws QuotaExceededError when the tenant's limit would be exceeded. */
  record(tenantId: string, metric: string, delta = 1): Promise<Usage> {
    return this.#client.recordUsage(tenantId, metric, delta);
  }
}
