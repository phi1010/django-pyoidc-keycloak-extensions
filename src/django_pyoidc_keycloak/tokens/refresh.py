"""Lazy, on-demand token refresh.

Deliberately *not* a scheduled background job.  Refreshing a live session's token on a timer
resets Keycloak's SSO Session Idle clock -- defeating idle timeout -- is still capped by SSO
Session Max, and races the user's own browser refresh, which trips refresh-token reuse
detection when rotation is enabled.  Tokens are refreshed here only when something actually
needs one.

Concurrency uses a distributed Redis lock rather than ``select_for_update``: a row lock would
hold a database transaction open across the HTTP round-trip to Keycloak, which is exactly what
you do not want under ASGI.  The lock is django-redis's ``cache.client.lock()``, which is
redis-py's ``Lock`` underneath: acquisition is a single ``SET NX PX``, and release is a Lua
script that only deletes the key when it still carries the acquirer's own random token --
so a worker whose lock has expired cannot release the lock of whoever acquired it next.

Finding 3 of SECURITY_REVIEW.md: the previous implementation released with
``cache.get() == nonce`` followed by ``cache.delete()``, a non-atomic pair that raced with
lock expiry and could delete another worker's lock.  redis-py's token-checked release closes
that window.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from asgiref.sync import sync_to_async
from django.core.cache import cache

from django_pyoidc_keycloak.admin_api.exceptions import TokensUnavailable
from django_pyoidc_keycloak.admin_api.provider import get_connection
from django_pyoidc_keycloak.conf import app_settings
from django_pyoidc_keycloak.scrub import scrub_text

logger = logging.getLogger(__name__)

LOCK_TIMEOUT = 30
LOCK_POLL_INTERVAL = 0.1
LOCK_WAIT_TOTAL = 10.0


def _lock_key(token_set: Any) -> str:
    return f"keycloak:refresh:{token_set.pk}"


def _get_lock(key: str):
    """The django-redis lock for ``key``, from whichever cache is configured.

    ``cache.client`` is django-redis's client; its ``lock()`` returns redis-py's ``Lock``
    bound to a Redis connection.  The token redis-py stores *is* the nonce: a random
    UUID generated per acquisition, never a credential.
    """

    # django-stubs does not know django-redis attaches its own client to the cache.
    client = cache.client  # type: ignore[attr-defined] # noqa: TC001
    return client.lock(
        key,
        timeout=LOCK_TIMEOUT,
        sleep=LOCK_POLL_INTERVAL,
        # Never block in acquire(): the waiting path below polls the database instead,
        # which is what lets a caller pick up the other worker's result without holding
        # a connection open.
        blocking=False,
    )


def _expiry(seconds: Any) -> datetime | None:
    if not seconds:
        return None
    return datetime.now(tz=UTC) + timedelta(seconds=int(seconds))


def _perform_refresh(token_set: Any) -> Any:
    """Exchange the refresh token for a new set and store it."""
    connection = get_connection()
    logger.debug("Refreshing token set %s against %s", token_set.pk, connection.token_endpoint)
    with httpx.Client(timeout=app_settings.REQUEST_TIMEOUT) as client:
        response = client.post(
            connection.token_endpoint,
            data={
                "grant_type": "refresh_token",
                "refresh_token": token_set.refresh_token,
                "client_id": connection.client_id,
                "client_secret": connection.client_secret,
            },
        )

    if response.status_code >= 400:
        payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        # Only the status and the OAuth error code -- never the body, which carries tokens.
        error = payload.get("error", "")
        logger.debug("Refresh of token set %s was refused: %d %s", token_set.pk, response.status_code, error or "-")
        if error in {"invalid_grant", "invalid_token"}:
            # The session is over at Keycloak: the token is useless, so drop it rather than
            # leaving a row that will fail forever.
            logger.info("Keycloak rejected the refresh token for set %s; dropping it", token_set.pk)
            token_set.delete()
            msg = "The refresh token was rejected by Keycloak; the user must log in again."
            raise TokensUnavailable(msg)
        msg = f"Token refresh failed ({response.status_code}): {scrub_text(response.text)}"
        raise TokensUnavailable(msg)

    payload = response.json()
    access_token = payload.get("access_token")
    if not access_token:
        # Never persist a null token: get_valid_access_token is typed to return a str, and a
        # caller would carry the None into an Authorization header.
        msg = "Keycloak returned no access_token for the refresh grant."
        raise TokensUnavailable(msg)

    token_set.access_token = access_token
    token_set.access_token_expires_at = _expiry(payload.get("expires_in"))
    if payload.get("refresh_token"):
        # Keycloak rotates the refresh token when "Revoke Refresh Token" is enabled.
        logger.debug("Keycloak rotated the refresh token for set %s", token_set.pk)
        token_set.refresh_token = payload["refresh_token"]
        token_set.refresh_token_expires_at = _expiry(payload.get("refresh_expires_in"))
    if payload.get("id_token"):
        token_set.id_token = payload["id_token"]
    if payload.get("scope"):
        token_set.scope = str(payload["scope"])[:500]
    token_set.save()
    logger.debug(
        "Token set %s refreshed; the new access token expires %s",
        token_set.pk,
        token_set.access_token_expires_at.isoformat() if token_set.access_token_expires_at else "unknown",
    )
    return token_set


def _release(lock: Any) -> None:
    """Release the lock, tolerating expiry.

    redis-py raises ``LockNotOwnedError`` when the lock is no longer ours -- the timeout
    elapsed and another worker acquired it.  That is a warning, not an error: the refresh
    still happened; the next worker simply runs its own.
    """
    from redis.exceptions import LockError

    try:
        lock.release()
    except LockError:
        logger.warning(
            "The refresh lock for this token set expired before the refresh finished; "
            "another worker may have refreshed concurrently."
        )


def get_valid_access_token(token_set: Any, *, leeway: int | None = None) -> str:
    """Return a usable access token, refreshing first if it is about to expire."""
    if token_set is None:
        msg = "No token set is available for this user."
        raise TokensUnavailable(msg)

    leeway = int(app_settings.TOKEN_REFRESH_LEEWAY if leeway is None else leeway)

    if not token_set.expires_within(leeway) and token_set.access_token:
        logger.debug("Token set %s is still valid within %ds leeway; no refresh needed", token_set.pk, leeway)
        return token_set.access_token

    if not token_set.refresh_token:
        msg = "The access token has expired and no refresh token was stored for this session."
        raise TokensUnavailable(msg)

    lock = _get_lock(_lock_key(token_set))
    if lock.acquire():
        logger.debug("Took the refresh lock for token set %s", token_set.pk)
        try:
            token_set.refresh_from_db()
            # Someone may have refreshed between our check and acquiring the lock.
            if not token_set.expires_within(leeway) and token_set.access_token:
                logger.debug("Token set %s was refreshed while we waited for the lock", token_set.pk)
                return token_set.access_token
            _perform_refresh(token_set)
            return token_set.access_token
        finally:
            # Token-checked by a Lua script: a slow worker cannot release the next one's lock.
            _release(lock)

    return _await_other_refresh(token_set, leeway=leeway)


def _await_other_refresh(token_set: Any, *, leeway: int) -> str:
    """Another worker holds the lock; wait briefly for it to write the new token."""
    logger.debug("Another worker is refreshing token set %s; waiting up to %.1fs", token_set.pk, LOCK_WAIT_TOTAL)
    deadline = time.monotonic() + LOCK_WAIT_TOTAL
    while time.monotonic() < deadline:
        time.sleep(LOCK_POLL_INTERVAL)
        token_set.refresh_from_db()
        if token_set.access_token and not token_set.expires_within(leeway):
            logger.debug("The other worker refreshed token set %s", token_set.pk)
            return token_set.access_token
    msg = "Timed out waiting for another worker to refresh the access token."
    raise TokensUnavailable(msg)


async def aget_valid_access_token(token_set: Any, *, leeway: int | None = None) -> str:
    """Async twin of :func:`get_valid_access_token`.

    The refresh itself is blocking work (a database write plus an HTTP call), so it runs in a
    thread; the waiting path uses ``asyncio.sleep`` so the event loop stays free.
    """
    if token_set is None:
        msg = "No token set is available for this user."
        raise TokensUnavailable(msg)

    leeway = int(app_settings.TOKEN_REFRESH_LEEWAY if leeway is None else leeway)

    if not token_set.expires_within(leeway) and token_set.access_token:
        logger.debug("Token set %s is still valid within %ds leeway; no refresh needed", token_set.pk, leeway)
        return token_set.access_token
    if not token_set.refresh_token:
        msg = "The access token has expired and no refresh token was stored for this session."
        raise TokensUnavailable(msg)

    lock = _get_lock(_lock_key(token_set))
    if await sync_to_async(lock.acquire)():
        logger.debug("Took the refresh lock for token set %s", token_set.pk)
        try:
            await sync_to_async(token_set.refresh_from_db)()
            if not token_set.expires_within(leeway) and token_set.access_token:
                logger.debug("Token set %s was refreshed while we waited for the lock", token_set.pk)
                return token_set.access_token
            await sync_to_async(_perform_refresh)(token_set)
            return token_set.access_token
        finally:
            await sync_to_async(_release)(lock)

    logger.debug("Another worker is refreshing token set %s; waiting up to %.1fs", token_set.pk, LOCK_WAIT_TOTAL)
    deadline = time.monotonic() + LOCK_WAIT_TOTAL
    while time.monotonic() < deadline:
        await asyncio.sleep(LOCK_POLL_INTERVAL)
        await sync_to_async(token_set.refresh_from_db)()
        if token_set.access_token and not token_set.expires_within(leeway):
            logger.debug("The other worker refreshed token set %s", token_set.pk)
            return token_set.access_token
    msg = "Timed out waiting for another worker to refresh the access token."
    raise TokensUnavailable(msg)


def get_access_token_for_user(user: Any, *, offline_only: bool = False, leeway: int | None = None) -> str:
    """Convenience wrapper: find the user's token set and return a valid access token."""
    from django_pyoidc_keycloak.tokens.store import get_token_set

    token_set = get_token_set(user, offline_only=offline_only)
    if token_set is None:
        logger.debug("No stored token set for user %s (offline_only=%s)", getattr(user, "pk", None), offline_only)
        msg = f"No stored tokens for user {getattr(user, 'pk', None)}."
        raise TokensUnavailable(msg)
    return get_valid_access_token(token_set, leeway=leeway)
