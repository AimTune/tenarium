"""The Tenarium API client: transport, retries, credentials and pagination."""

from __future__ import annotations

import datetime
import http.client
import json
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Tuple, Union

from ._generated import Operations
from .auth import StaticToken, TokenProvider, TokenSource
from .errors import parse_error

__all__ = ["Client", "ResultDict", "response_of", "etag_of", "DEFAULT_USER_AGENT"]

DEFAULT_USER_AGENT = "tenarium-python-client/0.1"

_IDEMPOTENT = frozenset(["GET", "HEAD", "PUT", "DELETE", "OPTIONS"])
_JSON_TYPE = re.compile(r"[/+]json\b", re.IGNORECASE)
_MAX_RESPONSE_BYTES = 32 << 20


class ResultDict(dict):  # type: ignore[type-arg]
    """A decoded JSON object that remembers the response it came from.

    It is a plain ``dict`` with the extra attributes ``status``, ``headers``,
    ``etag`` (pass it as ``if_match``) and ``request_id``.
    """

    status: int = 0
    headers: Mapping[str, str] = {}
    etag: Optional[str] = None
    request_id: Optional[str] = None


def response_of(result: Any) -> Optional[ResultDict]:
    """Return ``result`` if it carries response metadata, else None."""
    return result if isinstance(result, ResultDict) else None


def etag_of(result: Any) -> Optional[str]:
    """Return the ``ETag`` of the response a result was decoded from."""
    return result.etag if isinstance(result, ResultDict) else None


class Client(Operations):
    """Client for the Tenarium REST API.

    It has one method per operation of the OpenAPI spec, named after the
    snake_case operationId, plus ``iter_*`` generators for paginated lists::

        c = Client("https://tenarium.example.com", api_key=KEY, max_retries=3)
        t = c.create_tenant({"slug": "acme", "name": "Acme"})
        for t in c.iter_tenants(status="active"):
            print(t["slug"])

    Arguments:
        base_url: Server URL, e.g. ``http://localhost:8080`` (a path prefix is kept).
        api_key: A static API key (``tnr_...``), sent as a bearer token.
        token: A fixed bearer token, e.g. from an external identity provider.
        token_source: Any object with ``token()`` (and optionally
            ``reauth(rejected)``), such as a :class:`TokenSource`.
        max_retries: Retry failed requests up to this many additional times
            (default 0). Only requests that are safe to repeat are retried:
            GET, HEAD, PUT, DELETE, OPTIONS, and POSTs that carry an
            Idempotency-Key. Network errors, 502/503/504 and 429 with
            Retry-After are retried. With retries enabled, create calls get
            an Idempotency-Key automatically.
        retry_backoff: First backoff delay in seconds; it doubles per
            attempt, with jitter (default 0.2).
        max_retry_delay: Upper bound of the computed backoff (default 30).
        timeout: Socket timeout per attempt in seconds (default 30).
        headers: Headers sent with every request.
        user_agent: The User-Agent header.
        opener: A ``urllib.request.OpenerDirector`` (proxies, TLS settings).

    A client is thread-safe; :class:`TokenSource` serializes refreshes.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: Optional[str] = None,
        token: Optional[str] = None,
        token_source: Optional[TokenProvider] = None,
        max_retries: int = 0,
        retry_backoff: float = 0.2,
        max_retry_delay: float = 30.0,
        timeout: Optional[float] = 30.0,
        headers: Optional[Mapping[str, str]] = None,
        user_agent: str = DEFAULT_USER_AGENT,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("tenarium: invalid base URL %r: want http(s)://host[:port]" % base_url)
        self.base_url = base_url.rstrip("/")
        self._config: Dict[str, Any] = dict(
            api_key=api_key,
            token=token,
            token_source=token_source,
            max_retries=max_retries,
            retry_backoff=retry_backoff,
            max_retry_delay=max_retry_delay,
            timeout=timeout,
            headers=dict(headers or {}),
            user_agent=user_agent,
            opener=opener,
        )
        cred = api_key or token
        self._tokens: Optional[TokenProvider] = token_source or (StaticToken(cred) if cred else None)
        self._max_retries = max(0, max_retries)
        self._retry_backoff = retry_backoff
        self._max_retry_delay = max_retry_delay
        self._timeout = timeout
        self._headers = dict(headers or {})
        self._user_agent = user_agent
        self._opener = opener or urllib.request.build_opener()
        self._sleep: Callable[[float], None] = time.sleep

    def with_options(self, **overrides: Any) -> "Client":
        """Return a client with some options replaced.

        For example other credentials after a login:
        ``client.with_options(token_source=ts)``. Setting one kind of
        credentials drops the others.
        """
        config = dict(self._config)
        if {"api_key", "token", "token_source"} & set(overrides):
            config.update(api_key=None, token=None, token_source=None)
        config.update(overrides)
        return Client(self.base_url, **config)

    def token_source(self, pair: Mapping[str, Any], **kwargs: Any) -> TokenSource:
        """Return a :class:`TokenSource` that refreshes ``pair`` through this client."""
        return TokenSource(self, pair, **kwargs)

    def call(
        self,
        method: str,
        path: str,
        *,
        path_params: Optional[Mapping[str, Any]] = None,
        query: Optional[Mapping[str, Any]] = None,
        body: Any = None,
        content_type: Optional[str] = None,
        public: bool = False,
        if_match: Union[str, int, None] = None,
        idempotency_key: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        """Call any endpoint, e.g. one without an operationId such as ``/readyz``."""
        return self._request(
            method.upper(),
            path,
            path_params=path_params,
            query=query,
            body=body,
            content_type=content_type,
            public=public,
            if_match=if_match,
            idempotency_key=idempotency_key,
            headers=headers,
        )

    # --- transport ---------------------------------------------------------------------

    def _request(  # type: ignore[override]
        self,
        method: str,
        path: str,
        *,
        path_params: Optional[Mapping[str, Any]] = None,
        query: Optional[Mapping[str, Any]] = None,
        body: Any = None,
        content_type: Optional[str] = None,
        public: bool = False,
        auto_idempotency_key: bool = False,
        if_match: Union[str, int, None] = None,
        idempotency_key: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        url = self.base_url + _expand_path(path, path_params or {}) + _encode_query(query)
        hdrs: Dict[str, str] = {"Accept": "application/json", "User-Agent": self._user_agent}
        data: Optional[bytes] = None
        if body is not None:
            ct = content_type or "application/json"
            hdrs["Content-Type"] = ct
            data = _encode_body(body, ct)
        if idempotency_key is None and auto_idempotency_key and self._max_retries > 0:
            idempotency_key = uuid.uuid4().hex
        if idempotency_key is not None:
            hdrs["Idempotency-Key"] = idempotency_key
        if if_match is not None:
            hdrs["If-Match"] = _format_if_match(if_match)
        hdrs.update(self._headers)
        hdrs.update(headers or {})

        retryable = method in _IDEMPOTENT or (method == "POST" and idempotency_key is not None)
        tokens = None if public else self._tokens
        reauthed = False
        attempt = 0
        while True:
            token = None
            if tokens is not None:
                token = tokens.token()
                if token:
                    hdrs["Authorization"] = "Bearer " + token
            try:
                status, resp_headers, raw = self._send(method, url, data, hdrs)
            except (OSError, http.client.HTTPException):
                if retryable and attempt < self._max_retries:
                    self._sleep(self._backoff(attempt, None))
                    attempt += 1
                    continue
                raise
            if status == 401 and not reauthed and token and hasattr(tokens, "reauth"):
                reauthed = True
                try:
                    tokens.reauth(token)  # type: ignore[union-attr]
                    continue  # a credential refresh is not a retry
                except Exception:  # noqa: BLE001 - report the 401 instead
                    pass
            if status >= 400:
                err = parse_error(status, resp_headers, raw)
                if retryable and attempt < self._max_retries and _retryable_status(status, err.retry_after):
                    self._sleep(self._backoff(attempt, err.retry_after))
                    attempt += 1
                    continue
                raise err
            return _decode(status, resp_headers, raw)

    def _send(
        self, method: str, url: str, data: Optional[bytes], headers: Mapping[str, str]
    ) -> Tuple[int, Mapping[str, str], bytes]:
        req = urllib.request.Request(url, data=data, headers=dict(headers), method=method)
        try:
            with self._opener.open(req, timeout=self._timeout) as resp:
                return resp.status, resp.headers, resp.read(_MAX_RESPONSE_BYTES)
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(_MAX_RESPONSE_BYTES)
            finally:
                e.close()
            return e.code, e.headers, raw

    def _backoff(self, attempt: int, retry_after: Optional[float]) -> float:
        if retry_after:
            return retry_after
        d = self._retry_backoff * (2 ** min(attempt, 16))
        if d <= 0 or d > self._max_retry_delay:
            d = self._max_retry_delay
        return d / 2 + random.random() * (d / 2)  # noqa: S311 - jitter needs no cryptographic randomness

    def _paginate(self, fetch: Callable[[Optional[str]], Any]) -> Iterator[Any]:
        cursor: Optional[str] = None
        while True:
            page = fetch(cursor)
            for item in page.get("items") or []:
                yield item
            nxt = page.get("next")
            if not nxt or nxt == cursor:
                return
            cursor = nxt


# --- helpers ---------------------------------------------------------------------------


def _retryable_status(status: int, retry_after: Optional[float]) -> bool:
    if status in (502, 503, 504):
        return True
    return status == 429 and bool(retry_after)


def _decode(status: int, headers: Mapping[str, str], raw: bytes) -> Any:
    if status == 204 or not raw:
        return None
    ct = headers.get("Content-Type") or ""
    text = raw.decode("utf-8", "replace")
    if not _JSON_TYPE.search(ct):
        return text
    value = json.loads(text)
    if isinstance(value, dict):
        result = ResultDict(value)
        result.status = status
        result.headers = headers
        result.etag = headers.get("ETag") or None
        result.request_id = headers.get("X-Request-ID") or None
        return result
    return value


def _expand_path(template: str, params: Mapping[str, Any]) -> str:
    def sub(m: "re.Match[str]") -> str:
        name = m.group(1)
        v = params.get(name)
        if v is None or v == "":
            raise ValueError("tenarium: empty path parameter %s" % name)
        return urllib.parse.quote(str(v), safe="")

    return re.sub(r"\{([^}]+)\}", sub, template)


def _query_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (datetime.datetime, datetime.date)):
        return v.isoformat()
    return str(v)


def _query_pairs(query: Optional[Mapping[str, Any]]) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for k, v in (query or {}).items():
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            pairs.extend((k, _query_value(x)) for x in v if x is not None)
        else:
            pairs.append((k, _query_value(v)))
    return pairs


def _encode_query(query: Optional[Mapping[str, Any]]) -> str:
    pairs = _query_pairs(query)
    return "?" + urllib.parse.urlencode(pairs) if pairs else ""


def _encode_body(body: Any, content_type: str) -> bytes:
    if _JSON_TYPE.search(content_type):
        return json.dumps(body, separators=(",", ":")).encode("utf-8")
    if content_type.lower().startswith("application/x-www-form-urlencoded") and isinstance(body, Mapping):
        return urllib.parse.urlencode(_query_pairs(body)).encode("ascii")
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    raise TypeError("tenarium: cannot encode a %s body as %s" % (type(body).__name__, content_type))


def _format_if_match(v: Union[str, int]) -> str:
    if isinstance(v, int) and not isinstance(v, bool):
        return '"%d"' % v
    s = str(v)
    if s == "*" or re.match(r'^(W/)?".*"$', s):
        return s
    return '"%s"' % s

