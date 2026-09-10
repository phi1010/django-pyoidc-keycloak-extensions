"""Deriving a local username from a Keycloak account.

Keycloak usernames are unique within a realm, but a local row can still hold a name that
Keycloak has since freed and reassigned to someone else, so collisions are real and have to
be resolved rather than assumed away.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)

MAX_LENGTH = 150

#: How many ``-2``, ``-3``, ... candidates to try before falling back to a unique suffix.
MAX_SUFFIX = 99

#: Django's default username validator allows letters, digits and @ . + - _
_INVALID = re.compile(r"[^\w.@+-]", re.UNICODE)


def _candidate_from(representation: dict[str, Any]) -> str:
    """Prefer preferred_username, then email's local part, then the Keycloak id."""
    for key in ("preferred_username", "username"):
        value = representation.get(key)
        if value:
            return str(value)
    email = representation.get("email")
    if email:
        return str(email).split("@", 1)[0]
    for key in ("id", "sub"):
        value = representation.get(key)
        if value:
            return str(value)
    msg = "Cannot derive a username: the representation has no username, email or id."
    raise ValueError(msg)


def sanitize(raw: str) -> str:
    cleaned = _INVALID.sub("", raw).strip(".")
    return cleaned or "user"


def derive_username(representation: dict[str, Any], *, exclude_pk: Any = None) -> str:
    """Return a free username for this Keycloak account.

    ``exclude_pk`` is the row being updated, so a user keeps their own name instead of
    colliding with themselves.
    """
    user_model = get_user_model()
    base = sanitize(_candidate_from(representation))[:MAX_LENGTH]

    queryset = user_model.objects.all()
    if exclude_pk is not None:
        queryset = queryset.exclude(pk=exclude_pk)

    if not queryset.filter(username=base).exists():
        # The name itself is personal data, so only its length is logged.
        logger.debug("Derived a free username of %d character(s) for Keycloak %s", len(base), representation.get("id"))
        return base

    # Reserve room for the suffix rather than truncating it away.
    for suffix in range(2, MAX_SUFFIX + 1):
        tail = f"-{suffix}"
        candidate = f"{base[: MAX_LENGTH - len(tail)]}{tail}"
        if not queryset.filter(username=candidate).exists():
            logger.debug(
                "The derived username for Keycloak %s was taken; settled on suffix -%d",
                representation.get("id"),
                suffix,
            )
            return candidate

    # Bounded fallback, so a large collision set cannot turn this into a long scan.
    # The Keycloak id is unique by construction, which also breaks ties between two
    # concurrent logins racing for the same name.
    logger.info(
        "Exhausted %d numeric username suffixes for Keycloak %s; falling back to a unique suffix",
        MAX_SUFFIX - 1,
        representation.get("id"),
    )
    unique = uuid.uuid4().hex[:12] if not representation.get("id") else str(representation["id"])[:12]
    tail = f"-{unique}"
    return f"{base[: MAX_LENGTH - len(tail)]}{tail}"
