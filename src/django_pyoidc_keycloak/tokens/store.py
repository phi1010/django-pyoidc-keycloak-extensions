"""Persisting and purging the token set.

Storage is a two-phase handoff, forced by django-pyoidc's hook ordering: ``hook_get_user``
runs *before* the ``OIDCSession`` row exists, and ``hook_user_login`` runs after it but
receives no tokens.  So the first hook stashes the raw tokens on the user instance and the
second one writes them.
"""

from __future__ import annotations

import logging
from typing import Any

from django.utils import timezone

from django_pyoidc_keycloak.models.tokens import OIDCTokenSet
from django_pyoidc_keycloak.tokens.extract import RawTokens

logger = logging.getLogger(__name__)

#: Transient attribute carrying tokens between the two hooks. Never persisted as-is.
PENDING_ATTR = "_keycloak_pending_tokens"


def stash_tokens(user: Any, raw: RawTokens) -> None:
    """Phase one: remember the tokens until the session row exists."""
    setattr(user, PENDING_ATTR, raw)


def pop_tokens(user: Any) -> RawTokens | None:
    raw = getattr(user, PENDING_ATTR, None)
    if raw is not None:
        delattr(user, PENDING_ATTR)
    return raw


def find_session(request: Any, user: Any = None):
    """Locate the OIDCSession django-pyoidc has just created for this login."""
    from django_pyoidc.models import OIDCSession

    session_key = getattr(getattr(request, "session", None), "session_key", None)
    queryset = OIDCSession.objects.all()
    if session_key:
        queryset = queryset.filter(cache_session_key=session_key)
    return queryset.order_by("-created_at").first()


def store_tokens(*, session: Any, user: Any, raw: RawTokens, is_offline: bool = False) -> OIDCTokenSet | None:
    """Phase two: write the tokens into their encrypted columns."""
    if raw is None or raw.is_empty:
        return None

    token_set, _created = OIDCTokenSet.objects.update_or_create(
        session=session,
        defaults={
            "user": user,
            "access_token": raw.access_token,
            "id_token": raw.id_token,
            "refresh_token": raw.refresh_token,
            "access_token_expires_at": raw.access_token_expires_at,
            "refresh_token_expires_at": raw.refresh_token_expires_at,
            "scope": raw.scope[:500],
            "is_offline": is_offline or "offline_access" in (raw.scope or ""),
        },
    )
    return token_set


def purge_for_session(session: Any) -> int:
    """Drop the tokens for one session, at logout or backchannel logout."""
    deleted, _ = OIDCTokenSet.objects.filter(session=session).delete()
    return deleted


def purge_for_user(user: Any) -> int:
    deleted, _ = OIDCTokenSet.objects.filter(user=user).delete()
    return deleted


def purge_orphans() -> int:
    """Remove token sets whose refresh token has expired.

    Sets whose session row is gone are already removed by the cascade; this catches the ones
    that simply aged out.
    """
    stale = OIDCTokenSet.objects.filter(
        refresh_token_expires_at__isnull=False,
        refresh_token_expires_at__lte=timezone.now(),
    )
    count = stale.count()
    stale.delete()
    return count


def get_token_set(user: Any, *, offline_only: bool = False) -> OIDCTokenSet | None:
    """The most recently updated usable token set for this user."""
    queryset = OIDCTokenSet.objects.filter(user=user)
    if offline_only:
        queryset = queryset.filter(is_offline=True)
    return queryset.order_by("-updated_at").first()
