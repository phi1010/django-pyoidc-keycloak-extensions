"""Deriving a local username from a Keycloak account.

Keycloak usernames are unique within a realm, but a local row can still hold a name that
Keycloak has since freed and reassigned to someone else, so collisions are real and have to
be resolved rather than assumed away.
"""

from __future__ import annotations

import re
from typing import Any

from django.contrib.auth import get_user_model

MAX_LENGTH = 150

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
        return base

    # Reserve room for the suffix rather than truncating it away.
    suffix = 2
    while True:
        tail = f"-{suffix}"
        candidate = f"{base[: MAX_LENGTH - len(tail)]}{tail}"
        if not queryset.filter(username=candidate).exists():
            return candidate
        suffix += 1
