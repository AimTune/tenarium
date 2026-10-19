"""Typed client for the Tenarium REST API.

``Client`` has one method per operation of the OpenAPI spec (generated into
``_generated.py`` by ``tools/clientgen``); the request and response types
are ``TypedDict`` classes exported from this package.
"""

from ._generated import *  # noqa: F401,F403
from ._generated import __all__ as _generated_all
from .auth import NoRefreshToken, StaticToken, TokenProvider, TokenSource
from .client import DEFAULT_USER_AGENT, Client, ResultDict, etag_of, response_of
from .errors import (
    TenariumError,
    is_conflict,
    is_forbidden,
    is_not_found,
    is_quota_exceeded,
    is_unauthorized,
    is_validation,
    is_version_conflict,
)

__version__ = "0.1.0"

__all__ = [
    "Client",
    "DEFAULT_USER_AGENT",
    "NoRefreshToken",
    "ResultDict",
    "StaticToken",
    "TenariumError",
    "TokenProvider",
    "TokenSource",
    "etag_of",
    "is_conflict",
    "is_forbidden",
    "is_not_found",
    "is_quota_exceeded",
    "is_unauthorized",
    "is_validation",
    "is_version_conflict",
    "response_of",
] + list(_generated_all)
