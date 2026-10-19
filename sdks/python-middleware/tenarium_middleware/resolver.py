"""Finding the tenant reference of a request."""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional

from ._types import ForeignToken, InvalidToken, TenantError
from .tokens import TokenVerifier


@dataclass
class Request:
    """The parts of an HTTP request the resolver reads."""

    host: str = ""
    path: str = "/"
    headers: Mapping[str, str] = field(default_factory=dict)  # lowercase names

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    @classmethod
    def from_wsgi(cls, environ: Mapping[str, Any]) -> "Request":
        headers = {k[5:].replace("_", "-").lower(): v for k, v in environ.items() if k.startswith("HTTP_")}
        for k in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            if environ.get(k):
                headers[k.replace("_", "-").lower()] = environ[k]
        host = headers.get("host") or environ.get("SERVER_NAME", "")
        return cls(host=_normalize_host(host), path=environ.get("PATH_INFO") or "/", headers=headers)

    @classmethod
    def from_asgi(cls, scope: Mapping[str, Any]) -> "Request":
        headers: Dict[str, str] = {}
        for k, v in scope.get("headers") or []:
            headers.setdefault(k.decode("latin-1").lower(), v.decode("latin-1"))
        host = headers.get("host")
        if not host and scope.get("server"):
            host = scope["server"][0]
        return cls(host=_normalize_host(host or ""), path=scope.get("path") or "/", headers=headers)


def _normalize_host(host: str) -> str:
    host = host.strip().lower()
    if host.startswith("["):
        host = host[: host.find("]") + 1]
    else:
        host = re.sub(r":\d+$", "", host)
    return host.rstrip(".")


@dataclass
class Match:
    source: str
    ref: str  # tenant ID or slug
    claims: Optional[Dict[str, Any]] = None


class Extractor:
    """Finds a tenant reference in a request. Subclass and implement extract."""

    name = "custom"
    token = False  # True for extractors whose matches come from access tokens

    def extract(self, req: Request) -> Optional[Match]:
        raise NotImplementedError


class _Fn(Extractor):
    def __init__(self, name: str, fn: Callable[[Request], Optional[Match]], token: bool = False):
        self.name, self._fn, self.token = name, fn, token

    def extract(self, req: Request) -> Optional[Match]:
        return self._fn(req)


def from_subdomain(base_domain: str) -> Extractor:
    """"acme.<base_domain>" resolves to slug "acme" (single label only)."""
    suffix = "." + base_domain.lower().strip(".")

    def extract(req: Request) -> Optional[Match]:
        if not req.host.endswith(suffix):
            return None
        label = req.host[: -len(suffix)]
        return Match("subdomain", label) if label and "." not in label else None

    return _Fn("subdomain", extract)


def from_header(name: str) -> Extractor:
    """Tenant ID or slug from a header such as "X-Tenant-ID"."""

    def extract(req: Request) -> Optional[Match]:
        v = (req.header(name) or "").strip()
        return Match("header", v) if v else None

    return _Fn("header", extract)


def from_path_prefix(prefix: str = "/t/") -> Extractor:
    """Paths like "/t/{slug}/..." (prefix must start and end with "/")."""

    def extract(req: Request) -> Optional[Match]:
        if not req.path.startswith(prefix):
            return None
        ref = urllib.parse.unquote(req.path[len(prefix):].split("/", 1)[0])
        return Match("path", ref) if ref else None

    return _Fn("path", extract)


def from_token(verifier: TokenVerifier) -> Extractor:
    """The tid claim of a Tenarium access token ("Authorization: Bearer ...").

    Non-JWT bearers and tokens of other issuers are ignored; invalid
    Tenarium tokens are rejected with 401. Tokens without tid do not match.
    """

    def extract(req: Request) -> Optional[Match]:
        m = re.match(r"(?i)^bearer\s+(\S+)\s*$", req.header("authorization") or "")
        if not m:
            return None
        try:
            claims = verifier.verify(m.group(1))
        except ForeignToken:
            return None
        except InvalidToken as e:
            raise TenantError("unauthorized", "invalid access token: %s" % e) from e
        tid = claims.get("tid")
        return Match("token", tid, claims) if tid else None

    return _Fn("token", extract, token=True)


def from_custom_domain(domains: Any) -> Extractor:
    """Custom hostnames via ``domains.resolve_domain(host)`` (an ApiClient,
    ideally wrapped in CachingDomains)."""

    def extract(req: Request) -> Optional[Match]:
        if not req.host:
            return None
        d = domains.resolve_domain(req.host)
        return Match("domain", d["tenant_id"]) if d and d.get("tenant_id") else None

    return _Fn("domain", extract)


@dataclass
class Resolution:
    primary: Match
    token: Optional[Match] = None
    addressed: Optional[Match] = None  # first non-token match


class Resolver:
    """Tries extractors in order; the first match wins.

    With a token extractor, resolution continues until both the token's
    tenant and the addressed tenant (host, header or path) are known, so the
    middleware can refuse a token used against another tenant.
    """

    def __init__(self, *extractors: Extractor):
        self.extractors: List[Extractor] = list(extractors)

    def resolve(self, req: Request) -> Optional[Resolution]:
        tokens_left = sum(1 for e in self.extractors if e.token)
        primary = token = addressed = None
        for e in self.extractors:
            if e.token:
                tokens_left -= 1
            if addressed and (token or (tokens_left == 0 and not e.token)):
                break
            if (token if e.token else addressed) is not None:
                continue
            try:
                m = e.extract(req)
            except TenantError:
                raise
            except Exception as ex:
                raise TenantError("tenant_unavailable", str(ex)) from ex
            if not m or not m.ref:
                continue
            primary = primary or m
            if e.token:
                token = m
            else:
                addressed = m
        return Resolution(primary, token, addressed) if primary else None
