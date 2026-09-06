"""Getting the raw tokens out of django-pyoidc.

This is the one place that touches pyoidc internals, and the riskiest integration point in
the library, so it is isolated here and covered by an integration test.

Why it is needed: ``hook_get_user`` receives only
``{"info_token_claims", "access_token_jwt", "access_token_claims", "id_token_claims"}``
(built in django_pyoidc/views.py).  The raw ID token is decoded to claims and dropped -- the
``id_token_jwt`` line is commented out upstream -- and the refresh token is never passed at
all.  Both survive on the pyoidc ``Consumer``: ``AccessTokenResponse.verify()`` stores the
raw ID token as ``id_token_jwt`` (oic/oic/message.py) and ``Token.__init__`` copies every
response property onto the token object held in the consumer's grant database.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RawTokens:
    """The tokens as issued, before anything decodes them."""

    access_token: str | None = None
    id_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    scope: str = ""
    _fields: tuple[str, ...] = field(default=("access_token", "id_token", "refresh_token"), repr=False)

    def __repr__(self) -> str:  # never render the tokens themselves
        present = [name for name in self._fields if getattr(self, name)]
        return f"<RawTokens present={present}>"

    __str__ = __repr__

    @property
    def is_empty(self) -> bool:
        return not (self.access_token or self.id_token or self.refresh_token)


def _iter_grant_tokens(consumer: Any) -> list[Any]:
    """Every token object the consumer currently holds, newest grants last."""
    tokens: list[Any] = []
    grants = getattr(consumer, "grant", None) or {}
    try:
        values = list(grants.values())
    except AttributeError:  # pragma: no cover - defensive
        return tokens
    for grant in values:
        tokens.extend(getattr(grant, "tokens", []) or [])
    return tokens


def _expiry_from(token: Any) -> datetime | None:
    expiration = getattr(token, "token_expiration_time", 0)
    if not expiration:
        return None
    return datetime.fromtimestamp(int(expiration), tz=UTC)


def extract_raw_tokens(client: Any, tokens: dict[str, Any] | None = None) -> RawTokens:
    """Collect the raw tokens for the login currently held by ``client``.

    Never raises: token storage is a convenience, and failing to capture a refresh token
    must not break the login itself.
    """
    result = RawTokens()

    if tokens:
        # The access token is the one thing django-pyoidc does hand over.
        result.access_token = tokens.get("access_token_jwt")

    consumer = getattr(client, "consumer", None)
    if consumer is None:
        return result

    try:
        grant_tokens = _iter_grant_tokens(consumer)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Could not read the pyoidc grant database: %s", exc)
        return result

    for token in grant_tokens:
        access = getattr(token, "access_token", None)
        # Prefer the token object matching the access token we were given.
        if result.access_token and access and access != result.access_token:
            continue
        result.access_token = result.access_token or access
        result.refresh_token = getattr(token, "refresh_token", None) or result.refresh_token
        result.id_token = getattr(token, "id_token_jwt", None) or result.id_token
        result.access_token_expires_at = _expiry_from(token) or result.access_token_expires_at
        scope = getattr(token, "scope", None)
        if scope:
            result.scope = " ".join(scope) if isinstance(scope, (list, tuple)) else str(scope)
        if result.refresh_token and result.id_token:
            break

    if result.refresh_token is None:
        logger.info(
            "No refresh token captured at login. Background token refresh will be unavailable "
            "for this session; check that the client is confidential and the flow returns one."
        )
    return result
