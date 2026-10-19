"""Tenant state sources: the Tenarium API, the redis plugin's cache and a TTL cache."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Generic, Optional, Protocol, TypeVar

from ._types import ApiError, QuotaExceeded, Tenant

T = TypeVar("T")


class Source(Protocol):
    def get(self, id_or_slug: str) -> Optional[Tenant]:
        """The tenant by ID or slug, or None when it is unknown."""


class ApiClient:
    """Minimal Tenarium REST client authenticating with an API key (urllib)."""

    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", "Bearer " + self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            code, message = "", e.reason or ""
            try:
                err = json.loads(e.read() or b"{}").get("error") or {}
                code, message = err.get("code", ""), err.get("message", message)
            except ValueError:
                pass
            if e.code == 429:
                raise QuotaExceeded(429, code or "quota_exceeded", message) from None
            raise ApiError(e.code, code, str(message)) from None
        return json.loads(raw) if raw else None

    def _or_none(self, fn: Callable[[], T]) -> Optional[T]:
        try:
            return fn()
        except ApiError as e:
            if e.status == 404:
                return None
            raise

    def tenant(self, id_or_slug: str) -> Optional[Dict[str, Any]]:
        return self._or_none(lambda: self._call("GET", "/v1/tenants/" + _q(id_or_slug)))

    def entitlements(self, tenant_id: str) -> Dict[str, Any]:
        return self._call("GET", "/v1/tenants/%s/entitlements" % _q(tenant_id))

    def get(self, id_or_slug: str) -> Optional[Tenant]:
        """The tenant with effective entitlements (implements Source)."""
        t = self.tenant(id_or_slug)
        if t is None:
            return None
        ent = self.entitlements(t["id"])
        t = dict(t, features=ent.get("features") or {}, limits=ent.get("limits") or {})
        if ent.get("plan"):
            t["plan"] = ent["plan"]
        return Tenant.from_dict(t)

    def resolve_domain(self, host: str) -> Optional[Dict[str, Any]]:
        """GET /v1/domains/resolve?host=...: {tenant_id, slug, hostname} or None."""
        return self._or_none(
            lambda: self._call("GET", "/v1/domains/resolve?host=" + urllib.parse.quote(host, safe=""))
        )

    def record_usage(self, tenant_id: str, metric: str, delta: int = 1) -> Dict[str, Any]:
        """Atomically adds delta; raises QuotaExceeded on 429."""
        path = "/v1/tenants/%s/usage/%s" % (_q(tenant_id), _q(metric))
        return self._call("POST", path, {"delta": delta})


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def api_source(base_url: str, api_key: str, timeout: float = 10.0) -> ApiClient:
    """Tenant state from the Tenarium API (GET tenant + entitlements)."""
    return ApiClient(base_url, api_key, timeout)


class RedisSource:
    """Tenant state from the cache kept by Tenarium's redis plugin.

    ``client`` is anything with ``get(key)`` returning str, bytes or None
    (e.g. ``redis.Redis``). Keys: ``<prefix>tenant:<id>`` holds the JSON,
    ``<prefix>tenant-slug:<slug>`` the ID.
    """

    def __init__(self, client: Any, prefix: str = "tenarium:"):
        self.client = client
        self.prefix = prefix

    def _get(self, key: str) -> Optional[str]:
        v = self.client.get(key)
        return v.decode() if isinstance(v, bytes) else v

    def get(self, id_or_slug: str) -> Optional[Tenant]:
        raw = self._get(self.prefix + "tenant:" + id_or_slug)
        if raw is None:
            tid = self._get(self.prefix + "tenant-slug:" + id_or_slug)
            if tid is not None:
                raw = self._get(self.prefix + "tenant:" + tid)
        return None if raw is None else Tenant.from_dict(json.loads(raw))


def redis_source(client: Any, prefix: str = "tenarium:") -> RedisSource:
    return RedisSource(client, prefix)


class _Call:
    def __init__(self) -> None:
        self.done = threading.Event()
        self.value: Any = None
        self.error: Optional[BaseException] = None


class TTLCache(Generic[T]):
    """Thread-safe TTL cache. None results are cached for ``negative_ttl``;
    exceptions are not cached; concurrent misses share one load."""

    def __init__(self, ttl: float, negative_ttl: Optional[float] = None, max_entries: int = 10000):
        self.ttl = ttl
        self.negative_ttl = ttl if negative_ttl is None else negative_ttl
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._items: Dict[str, Any] = {}  # key -> (value, expires)
        self._inflight: Dict[str, _Call] = {}

    def get(self, key: str, load: Callable[[], Optional[T]]) -> Optional[T]:
        with self._lock:
            hit = self._items.get(key)
            if hit is not None and hit[1] > time.monotonic():
                return hit[0]
            call = self._inflight.get(key)
            leader = call is None
            if leader:
                call = self._inflight[key] = _Call()
        if not leader:
            call.done.wait()
            if call.error is not None:
                raise call.error
            return call.value
        try:
            call.value = load()
        except BaseException as e:
            call.error = e
            raise
        else:
            ttl = self.negative_ttl if call.value is None else self.ttl
            if ttl > 0:
                with self._lock:
                    if len(self._items) >= self.max_entries:
                        self._evict()
                    self._items[key] = (call.value, time.monotonic() + ttl)
            return call.value
        finally:
            with self._lock:
                self._inflight.pop(key, None)
            call.done.set()

    def _evict(self) -> None:
        now = time.monotonic()
        for k in [k for k, (_, exp) in self._items.items() if exp <= now]:
            del self._items[k]
        for k in list(self._items):  # insertion order: oldest first
            if len(self._items) < self.max_entries * 0.9:
                break
            del self._items[k]

    def delete(self, key: str) -> None:
        with self._lock:
            self._items.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


class CachingSource:
    """In-memory TTL cache in front of a Source (negative caching included)."""

    def __init__(self, source: Any, ttl: float, negative_ttl: Optional[float] = None, max_entries: int = 10000):
        self.source = source
        self._cache: TTLCache[Tenant] = TTLCache(ttl, negative_ttl, max_entries)

    def get(self, id_or_slug: str) -> Optional[Tenant]:
        return self._cache.get(id_or_slug, lambda: self.source.get(id_or_slug))

    def invalidate(self, id_or_slug: str) -> None:
        self._cache.delete(id_or_slug)

    def clear(self) -> None:
        self._cache.clear()


class CachingDomains:
    """Caches ``resolve_domain`` answers (including unknown hosts)."""

    def __init__(self, resolver: Any, ttl: float):
        self.resolver = resolver
        self._cache: TTLCache[Dict[str, Any]] = TTLCache(ttl)

    def resolve_domain(self, host: str) -> Optional[Dict[str, Any]]:
        return self._cache.get(host, lambda: self.resolver.resolve_domain(host))


class UsageRecorder:
    """Records metered usage through the API."""

    def __init__(self, client: ApiClient):
        self.client = client

    def record(self, tenant_id: str, metric: str, delta: int = 1) -> Dict[str, Any]:
        """Raises QuotaExceeded when the tenant's limit would be exceeded."""
        return self.client.record_usage(tenant_id, metric, delta)
