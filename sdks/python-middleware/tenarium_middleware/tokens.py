"""Claim checks for Tenarium access tokens.

Tenarium signs access tokens with ES256. The Python standard library cannot
verify ECDSA signatures, so signature verification is delegated to a callback
you supply, for example with PyJWT::

    import jwt  # PyJWT[crypto]
    jwks = jwt.PyJWKClient("https://tenarium.example.com/.well-known/jwks.json")

    def decode(token):
        key = jwks.get_signing_key_from_jwt(token).key
        return jwt.decode(token, key, algorithms=["ES256"], audience="tenarium",
                          issuer="https://tenarium.example.com")

    verifier = TokenVerifier("https://tenarium.example.com", decode)

or with jwcrypto (``JWT(jwt=token, key=jwkset).claims``). Whatever the callback
checks, TokenVerifier checks iss, aud, exp and nbf again on the claims it
returns.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any, Callable, Dict, Mapping, Optional

from ._types import ForeignToken, InvalidToken

Claims = Dict[str, Any]


def unverified_claims(token: str) -> Optional[Claims]:
    """Decodes a JWT payload without verification; None if it is not a JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        claims = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    return claims if isinstance(claims, dict) else None


def check_claims(
    claims: Mapping[str, Any],
    issuer: str,
    audience: str = "tenarium",
    leeway: float = 30,
    now: Optional[float] = None,
) -> None:
    """Checks iss, aud, exp and nbf of decoded claims; raises InvalidToken."""
    now = time.time() if now is None else now
    if claims.get("iss") != issuer:
        raise InvalidToken("issuer mismatch")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if audience not in auds:
        raise InvalidToken("audience mismatch")
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        raise InvalidToken("no expiry")
    if now - leeway >= exp:
        raise InvalidToken("token expired")
    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and now + leeway < nbf:
        raise InvalidToken("token not yet valid")


class TokenVerifier:
    """Verifies Tenarium access tokens.

    ``decode(token) -> claims`` must verify the ES256 signature against
    Tenarium's JWKS and return the claims (raising on a bad signature).
    Tokens that are not JWTs or whose unverified ``iss`` is not ``issuer``
    raise ForeignToken without calling ``decode``.
    """

    def __init__(
        self,
        issuer: str,
        decode: Callable[[str], Mapping[str, Any]],
        audience: str = "tenarium",
        leeway: float = 30,
    ):
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self._decode = decode

    def verify(self, token: str) -> Claims:
        peek = unverified_claims(token)
        if peek is None or peek.get("iss") != self.issuer:
            raise ForeignToken()
        try:
            claims = dict(self._decode(token))
        except InvalidToken:
            raise
        except Exception as e:  # the library's own error types
            raise InvalidToken(str(e)) from e
        check_claims(claims, self.issuer, self.audience, self.leeway)
        return claims
