from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

ACTIVE = "active"
DELETED = "deleted"


@dataclass(frozen=True)
class Tenant:
    """Tenant state with effective entitlements (plan plus tenant overrides)."""

    id: str
    slug: str
    status: str
    name: str = ""
    plan: str = ""
    parent_id: str = ""
    labels: Mapping[str, str] = field(default_factory=dict)
    features: Mapping[str, bool] = field(default_factory=dict)
    limits: Mapping[str, int] = field(default_factory=dict)
    version: int = 0

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Tenant":
        return cls(
            id=d["id"],
            slug=d.get("slug", ""),
            status=d.get("status", ""),
            name=d.get("name") or "",
            plan=d.get("plan") or "",
            parent_id=d.get("parent_id") or "",
            labels=dict(d.get("labels") or {}),
            features=dict(d.get("features") or {}),
            limits=dict(d.get("limits") or {}),
            version=int(d.get("version") or 0),
        )

    def has_feature(self, feature: str) -> bool:
        return self.features.get(feature) is True

    def limit(self, metric: str) -> Optional[int]:
        """The limit for metric, or None when the metric is unlimited."""
        return self.limits.get(metric)


_STATUS = {
    "tenant_required": 404,
    "tenant_not_found": 404,
    "tenant_inactive": 403,
    "tenant_mismatch": 403,
    "unauthorized": 401,
    "feature_disabled": 403,
    "quota_exceeded": 429,
    "tenant_unavailable": 503,
}


class TenantError(Exception):
    """A rejection carrying the HTTP status the middleware answers with."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = _STATUS.get(code, 500)

    def body(self) -> Dict[str, Any]:
        """Tenarium-style JSON error body; upstream details are not exposed."""
        msg = "tenant state unavailable" if self.status == 503 else self.message
        return {"error": {"code": self.code, "message": msg}}


class ApiError(Exception):
    """A non-2xx answer of the Tenarium API."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__("tenarium api: %d %s: %s" % (status, code, message))
        self.status = status
        self.code = code
        self.message = message


class QuotaExceeded(ApiError):
    """Recording usage would exceed the tenant's limit (HTTP 429)."""


class ForeignToken(Exception):
    """A bearer that is not a JWT or was issued by someone else."""


class InvalidToken(Exception):
    """A Tenarium token that failed verification."""
