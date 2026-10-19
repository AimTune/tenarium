"""Tenant resolution core plus WSGI and ASGI middleware."""
from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Sequence

from ._types import ACTIVE, DELETED, Tenant, TenantError
from .resolver import Request, Resolver

_current: contextvars.ContextVar[Optional["TenantContext"]] = contextvars.ContextVar(
    "tenarium_tenant", default=None
)

ENVIRON_KEY = "tenarium.tenant"
CLAIMS_KEY = "tenarium.claims"


@dataclass
class TenantContext:
    tenant: Optional[Tenant]
    claims: Optional[Dict[str, Any]] = None  # verified token claims, if any


def current_tenant() -> Optional[Tenant]:
    """The tenant of the request being handled (set by both middlewares)."""
    ctx = _current.get()
    return ctx.tenant if ctx else None


def current_claims() -> Optional[Dict[str, Any]]:
    ctx = _current.get()
    return ctx.claims if ctx else None


def _load(source: Any, ref: str) -> Optional[Tenant]:
    try:
        return source.get(ref)
    except TenantError:
        raise
    except Exception as e:
        raise TenantError("tenant_unavailable", str(e)) from e


def resolve_tenant(
    req: Request,
    resolver: Resolver,
    source: Any,
    allowed_statuses: Sequence[str] = (ACTIVE,),
    optional: bool = False,
) -> TenantContext:
    """Framework-agnostic core: resolves and loads the tenant, enforces the
    allowed statuses and the token mismatch rule. Raises TenantError."""
    res = resolver.resolve(req)
    if res is None:
        if optional:
            return TenantContext(None)
        raise TenantError("tenant_required", "no tenant in request")
    tenant = _load(source, res.primary.ref)
    if tenant is None or tenant.status == DELETED:
        raise TenantError("tenant_not_found", "tenant not found")

    if res.token and res.addressed:
        token_id = res.token.ref
        if res.primary is res.addressed:
            same = tenant.id == token_id
        else:
            ref = res.addressed.ref
            if ref in (token_id, tenant.slug):
                same = True
            else:
                other = _load(source, ref)
                same = other is not None and other.id == token_id
        if not same:
            raise TenantError("tenant_mismatch", "token tenant does not match request tenant")

    if tenant.status not in allowed_statuses:
        raise TenantError("tenant_inactive", "tenant is %s" % tenant.status)
    return TenantContext(tenant, res.token.claims if res.token else None)


def _error_response(err: TenantError):
    body = json.dumps(err.body()).encode()
    status = "%d %s" % (err.status, {401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
                                     429: "Too Many Requests", 503: "Service Unavailable"}.get(err.status, "Error"))
    headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    return status, headers, body


class TenantMiddleware:
    """WSGI middleware. Stores the tenant in ``environ["tenarium.tenant"]``
    (claims in ``environ["tenarium.claims"]``) and in a context variable
    read by ``current_tenant()``. A TenantError raised by the app before it
    starts the response (e.g. from ``require_feature``) is answered too."""

    def __init__(self, app: Callable, resolver: Resolver, source: Any,
                 allowed_statuses: Sequence[str] = (ACTIVE,), optional: bool = False):
        self.app = app
        self.resolver = resolver
        self.source = source
        self.allowed_statuses = tuple(allowed_statuses)
        self.optional = optional

    def __call__(self, environ: Dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        try:
            ctx = resolve_tenant(Request.from_wsgi(environ), self.resolver, self.source,
                                 self.allowed_statuses, self.optional)
        except TenantError as e:
            return self._reject(e, start_response)
        environ[ENVIRON_KEY] = ctx.tenant
        environ[CLAIMS_KEY] = ctx.claims
        token = _current.set(ctx)
        try:
            return self.app(environ, start_response)
        except TenantError as e:
            return self._reject(e, start_response)
        finally:
            _current.reset(token)

    @staticmethod
    def _reject(e: TenantError, start_response: Callable) -> Iterable[bytes]:
        status, headers, body = _error_response(e)
        start_response(status, headers)
        return [body]


class TenantASGIMiddleware:
    """ASGI middleware for HTTP (and websocket) scopes. Stores the tenant in
    ``scope["tenarium.tenant"]`` and ``scope["state"]["tenant"]`` (Starlette's
    ``request.state.tenant``) and in ``current_tenant()``. Sources are called
    in a worker thread, so blocking clients are fine."""

    def __init__(self, app: Callable, resolver: Resolver, source: Any,
                 allowed_statuses: Sequence[str] = (ACTIVE,), optional: bool = False):
        self.app = app
        self.resolver = resolver
        self.source = source
        self.allowed_statuses = tuple(allowed_statuses)
        self.optional = optional

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        req = Request.from_asgi(scope)
        try:
            ctx = await asyncio.get_running_loop().run_in_executor(
                None, functools.partial(resolve_tenant, req, self.resolver, self.source,
                                        self.allowed_statuses, self.optional))
        except TenantError as e:
            await self._reject(e, scope, send)
            return
        scope[ENVIRON_KEY] = ctx.tenant
        scope[CLAIMS_KEY] = ctx.claims
        scope.setdefault("state", {})["tenant"] = ctx.tenant
        started = False

        async def tracking_send(message: Dict[str, Any]) -> None:
            nonlocal started
            if message["type"] in ("http.response.start", "websocket.accept"):
                started = True
            await send(message)

        token = _current.set(ctx)
        try:
            await self.app(scope, receive, tracking_send)
        except TenantError as e:
            if started:
                raise
            await self._reject(e, scope, send)
        finally:
            _current.reset(token)

    @staticmethod
    async def _reject(e: TenantError, scope: Dict[str, Any], send: Callable) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 4000 + e.status})
            return
        _, headers, body = _error_response(e)
        await send({"type": "http.response.start", "status": e.status,
                    "headers": [(k.lower().encode(), v.encode()) for k, v in headers]})
        await send({"type": "http.response.body", "body": body})


def require_feature(feature: str) -> Callable:
    """Decorator raising TenantError (403 feature_disabled, or 404 without a
    tenant) unless the current tenant has ``feature``. Works on sync and
    async callables; the middlewares turn the error into a response."""

    def check() -> None:
        tenant = current_tenant()
        if tenant is None:
            raise TenantError("tenant_required", "no tenant in request")
        if not tenant.has_feature(feature):
            raise TenantError("feature_disabled", "feature %s not enabled for tenant" % feature)

    def decorate(fn: Callable) -> Callable:
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                check()
                return await fn(*args, **kwargs)
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            check()
            return fn(*args, **kwargs)
        return wrapper

    return decorate
