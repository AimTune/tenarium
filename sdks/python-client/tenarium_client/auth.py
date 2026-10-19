"""Token providers: static credentials and a refreshing Tenarium session."""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, Mapping, Optional, Protocol


class TokenProvider(Protocol):
    """Supplies the bearer token for each request.

    A provider may also define ``reauth(rejected) -> str``: the client calls
    it at most once per request after a 401 and retries with the new token.
    """

    def token(self) -> str: ...


class StaticToken:
    """A fixed bearer token or API key."""

    def __init__(self, value: str) -> None:
        self._value = value

    def token(self) -> str:
        return self._value


class NoRefreshToken(Exception):
    """A refresh is needed but the pair has no refresh token."""


class TokenSource:
    """Holds a Tenarium token pair and refreshes the access token.

    The access token is refreshed with the ``refresh_token`` grant shortly
    before it expires, and once when the server rejects it with 401. It is
    thread-safe; refreshes are serialized so a rotated refresh token is
    never reused (reusing one makes the server revoke the session)::

        pair = client.token({"grant_type": "password", "email": e, "password": p})
        authed = client.with_options(token_source=TokenSource(client, pair))

    ``on_refresh`` receives every new pair, including ``expires_at`` (epoch
    seconds); store it and pass it back to restore the session later.
    """

    def __init__(
        self,
        client: Any,
        pair: Mapping[str, Any],
        *,
        skew: float = 30.0,
        on_refresh: Optional[Callable[[Dict[str, Any]], None]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._client = client
        self._skew = skew
        self._on_refresh = on_refresh
        self._clock = clock
        self._lock = threading.Lock()
        self._pair = self._stamp(pair)

    @property
    def pair(self) -> Dict[str, Any]:
        """The current token pair."""
        with self._lock:
            return dict(self._pair)

    def token(self) -> str:
        """Return a valid access token, refreshing it first if it expires soon."""
        with self._lock:
            if self._pair.get("access_token") and not self._expiring():
                return self._pair["access_token"]
            return self._refresh_locked()

    def reauth(self, rejected: str) -> str:
        """Refresh after the server rejected ``rejected``, unless that already happened."""
        with self._lock:
            current = self._pair.get("access_token")
            if current and current != rejected:
                return current
            return self._refresh_locked()

    def refresh(self) -> str:
        """Force a refresh now."""
        with self._lock:
            return self._refresh_locked()

    def _expiring(self) -> bool:
        exp = self._pair.get("expires_at")
        if not exp:
            return False
        skew = self._skew
        expires_in = self._pair.get("expires_in") or 0
        if expires_in > 0:
            skew = min(skew, expires_in / 2.0)
        return self._clock() + skew >= exp

    def _stamp(self, pair: Mapping[str, Any]) -> Dict[str, Any]:
        p = dict(pair)
        if p.get("expires_at") is None and (p.get("expires_in") or 0) > 0:
            p["expires_at"] = self._clock() + p["expires_in"]
        return p

    def _refresh_locked(self) -> str:
        refresh_token = self._pair.get("refresh_token")
        if not refresh_token:
            raise NoRefreshToken("tenarium: access token expired and no refresh token is available")
        new = dict(self._client.token({"grant_type": "refresh_token", "refresh_token": refresh_token}))
        new.pop("expires_at", None)
        self._pair = self._stamp(new)
        if self._on_refresh is not None:
            self._on_refresh(dict(self._pair))
        return self._pair["access_token"]
