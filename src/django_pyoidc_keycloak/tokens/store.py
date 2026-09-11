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
    logger.debug("Stashing tokens for user %s until hook_user_login can attach them", user.pk)
    setattr(user, PENDING_ATTR, raw)


def pop_tokens(user: Any) -> RawTokens | None:
    raw = getattr(user, PENDING_ATTR, None)
    if raw is not None:
        delattr(user, PENDING_ATTR)
    else:
        logger.debug("No tokens were stashed for user %s at login", user.pk)
    return raw


def find_session(request: Any, user: Any = None):
    """Locate the OIDCSession django-pyoidc has just created for this login.

    Fails closed.  An earlier version fell back to "the most recent session row" when the
    request carried no session key, which could attach one user's tokens to another user's
    session -- and, because OIDCTokenSet is one-to-one on the session, silently overwrite
    theirs.  Returning None instead costs nothing: the caller simply stores no tokens.
    """
    # Imported here rather than at module scope: this is another app's model, and this module
    # is reachable from admin.py and the hooks during app loading.
    from django_pyoidc.models import OIDCSession

    session_key = getattr(getattr(request, "session", None), "session_key", None)
    if not session_key:
        # Failing closed: see the docstring. Without a key there is no safe candidate.
        logger.debug("This request carries no session key, so no OIDCSession can be matched")
        return None

    queryset = OIDCSession.objects.filter(cache_session_key=session_key)

    keycloak_id = getattr(user, "keycloak_id", None) if user is not None else None
    if keycloak_id is not None:
        # django-pyoidc stores the Keycloak "sub" here, which is our keycloak_id.
        queryset = queryset.filter(sub=str(keycloak_id))

    session = queryset.order_by("-created_at").first()
    if session is None:
        logger.debug("No OIDCSession matches this session key for Keycloak %s", keycloak_id)
    else:
        logger.debug("Matched OIDCSession %s for Keycloak %s", session.pk, keycloak_id)
    return session


def store_tokens(*, session: Any, user: Any, raw: RawTokens, is_offline: bool | None = None) -> OIDCTokenSet | None:
    """Phase two: write the tokens into their encrypted columns."""
    if raw is None or raw.is_empty:
        logger.debug("Nothing to store for user %s: the extracted token set is empty", getattr(user, "pk", None))
        return None

    if session is None:
        logger.debug("Not storing tokens for user %s: no session row to attach them to", getattr(user, "pk", None))
        return None

    # Which kinds arrived, never their values.
    logger.debug(
        "Storing tokens for user %s on session %s (access: %s, refresh: %s, id: %s, scope: %r)",
        getattr(user, "pk", None),
        getattr(session, "pk", None),
        bool(raw.access_token),
        bool(raw.refresh_token),
        bool(raw.id_token),
        raw.scope,
    )

    token_set, created = OIDCTokenSet.objects.update_or_create(
        session=session,
        defaults={
            "user": user,
            "access_token": raw.access_token,
            "id_token": raw.id_token,
            "refresh_token": raw.refresh_token,
            "access_token_expires_at": raw.access_token_expires_at,
            "refresh_token_expires_at": raw.refresh_token_expires_at,
            "scope": raw.scope[:500],
            # Derived from the granted scope. Requesting offline_access does not mean
            # Keycloak issued an offline token, and mislabelling one changes how its expiry
            # is interpreted. Scope tokens are space-delimited, so match exactly rather
            # than by substring: "notoffline_access" is not "offline_access".
            "is_offline": "offline_access" in (raw.scope or "").split() if is_offline is None else is_offline,
        },
    )
    logger.debug(
        "%s token set %s; offline=%s, access token expires %s",
        "Created" if created else "Replaced",
        token_set.pk,
        token_set.is_offline,
        token_set.access_token_expires_at.isoformat() if token_set.access_token_expires_at else "unknown",
    )
    return token_set


def purge_for_session(session: Any) -> int:
    """Drop the tokens for one session, at logout or backchannel logout."""
    deleted, _ = OIDCTokenSet.objects.filter(session=session).delete()
    logger.debug("Purged %d token set(s) for session %s", deleted, getattr(session, "pk", None))
    return deleted


def purge_for_user(user: Any) -> int:
    deleted, _ = OIDCTokenSet.objects.filter(user=user).delete()
    logger.debug("Purged %d token set(s) for user %s", deleted, getattr(user, "pk", None))
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
    if count:
        logger.info("Purging %d token set(s) whose refresh token has expired", count)
    else:
        logger.debug("No stored token sets have aged out")
    stale.delete()
    return count


def get_token_set(user: Any, *, offline_only: bool = False) -> OIDCTokenSet | None:
    """The most recently updated usable token set for this user."""
    queryset = OIDCTokenSet.objects.filter(user=user)
    if offline_only:
        queryset = queryset.filter(is_offline=True)
    token_set = queryset.order_by("-updated_at").first()
    logger.debug(
        "Looked up a token set for user %s (offline_only=%s): %s",
        getattr(user, "pk", None),
        offline_only,
        token_set.pk if token_set is not None else "none stored",
    )
    return token_set
