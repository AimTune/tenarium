"""Errors raised by the Tenarium client."""

from __future__ import annotations

import email.utils
import json
import time
from typing import Any, Mapping, Optional


class TenariumError(Exception):
    """A non-2xx API response.

    The server reports errors as ``{"error": {"code", "message", "field"}}``;
    SCIM endpoints use SCIM error bodies, whose ``scimType`` and ``detail``
    become ``code`` and ``message``.
    """

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        field: Optional[str] = None,
        request_id: Optional[str] = None,
        retry_after: Optional[float] = None,
        body: Any = None,
    ) -> None:
        super().__init__(message)
        #: HTTP status code.
        self.status = status
        #: Machine-readable code, e.g. ``not_found``, ``version_conflict``, ``quota_exceeded``.
        self.code = code
        self.message = message
        #: The offending input field or, for quota errors, the metric.
        self.field = field
        #: The server's ``X-Request-ID``, useful when reporting issues.
        self.request_id = request_id
        #: The server's ``Retry-After`` hint in seconds.
        self.retry_after = retry_after
        #: The decoded response body.
        self.body = body

    def __str__(self) -> str:
        s = "tenarium: %d" % self.status
        if self.code:
            s += " " + self.code
        if self.message:
            s += ": " + self.message
        if self.field:
            s += " (field %s)" % self.field
        if self.request_id:
            s += " [request %s]" % self.request_id
        return s

    def __repr__(self) -> str:
        return "TenariumError(status=%d, code=%r, message=%r, field=%r, request_id=%r)" % (
            self.status, self.code, self.message, self.field, self.request_id,
        )


def is_not_found(err: BaseException) -> bool:
    """A 404 response."""
    return isinstance(err, TenariumError) and err.status == 404


def is_conflict(err: BaseException) -> bool:
    """A 409 response (already exists, invalid transition)."""
    return isinstance(err, TenariumError) and err.status == 409


def is_version_conflict(err: BaseException) -> bool:
    """A 412 response: the resource changed since the version sent as ``if_match``."""
    return isinstance(err, TenariumError) and err.status == 412


def is_quota_exceeded(err: BaseException) -> bool:
    """A refused usage increment; ``field`` is the metric."""
    return isinstance(err, TenariumError) and err.code == "quota_exceeded"


def is_forbidden(err: BaseException) -> bool:
    """A 403 response."""
    return isinstance(err, TenariumError) and err.status == 403


def is_unauthorized(err: BaseException) -> bool:
    """A 401 response (missing, invalid or expired credentials)."""
    return isinstance(err, TenariumError) and err.status == 401


def is_validation(err: BaseException) -> bool:
    """A 400 ``validation_failed`` response."""
    return isinstance(err, TenariumError) and err.code == "validation_failed"


def parse_retry_after(value: Optional[str], now: Optional[float] = None) -> Optional[float]:
    """Parse ``Retry-After`` (seconds or an HTTP date) into seconds."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        t = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if t is None:
        return None
    return max(t.timestamp() - (time.time() if now is None else now), 0.0)


def parse_error(status: int, headers: Mapping[str, str], raw: bytes) -> TenariumError:
    """Build the error for a non-2xx response."""
    request_id = headers.get("X-Request-ID") or None
    retry_after = parse_retry_after(headers.get("Retry-After"))
    text = raw.decode("utf-8", "replace")
    body: Any = None
    try:
        body = json.loads(text) if text else None
    except ValueError:
        body = None
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict) and isinstance(e.get("code"), str):
            message = e.get("message")
            field = e.get("field")
            return TenariumError(
                status,
                e["code"],
                message if isinstance(message, str) else "",
                field if isinstance(field, str) and field else None,
                request_id,
                retry_after,
                body,
            )
        if isinstance(body.get("detail"), str):
            scim_type = body.get("scimType")
            return TenariumError(
                status,
                scim_type if isinstance(scim_type, str) else "",
                body["detail"],
                None,
                request_id,
                retry_after,
                body,
            )
    message = text.strip()
    if len(message) > 200:
        message = message[:200] + "..."
    return TenariumError(status, "", message or "HTTP %d" % status, None, request_id, retry_after, body)
