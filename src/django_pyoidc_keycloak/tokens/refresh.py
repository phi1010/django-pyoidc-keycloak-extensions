"""Lazy, on-demand token refresh.

Deliberately *not* a scheduled background job.  Refreshing a live session's token on a timer
resets Keycloak's SSO Session Idle clock -- defeating idle timeout -- is still capped by SSO
Session Max, and races the user's own browser refresh, which trips refresh-token reuse
detection when rotation is enabled.  Tokens are refreshed here only when something actually
needs one.

Concurrency uses a cache mutex rather than ``select_for_update``: a row lock would hold a
database transaction open across the HTTP round-trip to Keycloak, which is exactly what you
do not want under ASGI.  The cached value is a random lock nonce -- never a token.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
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


def _expiry(seconds: Any) -> datetime | None:
    if not seconds:
        return None
    return datetime.now(tz=UTC) + timedelta(seconds=int(seconds))


def _perform_refresh(token_set: Any) -> Any:
    """Exchange the refresh token for a new set and store it."""
    connection = get_connection()
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
        error = payload.get("error", "")
        if error in {"invalid_grant", "invalid_token"}:
            # The session is over at Keycloak: the token is useless, so drop it rather than
            # leaving a row that will fail forever.
            token_set.delete()
            msg = "The refresh token was rejected by Keycloak; the user must log in again."
            raise TokensUnavailable(msg)
        msg = f"Token refresh failed ({response.status_code}): {scrub_text(response.text)}"
        raise TokensUnavailable(msg)

    payload = response.json()
    token_set.access_token = payload.get("access_token")
    token_set.access_token_expires_at = _expiry(payload.get("expires_in"))
    if payload.get("refresh_token"):
        # Keycloak rotates the refresh token when "Revoke Refresh Token" is enabled.
        token_set.refresh_token = payload["refresh_token"]
        token_set.refresh_token_expires_at = _expiry(payload.get("refresh_expires_in"))
    if payload.get("id_token"):
        token_set.id_token = payload["id_token"]
    if payload.get("scope"):
        token_set.scope = str(payload["scope"])[:500]
    token_set.save()
    return token_set


def get_valid_access_token(token_set: Any, *, leeway: int | None = None) -> str:
    """Return a usable access token, refreshing first if it is about to expire."""
    if token_set is None:
        msg = "No token set is available for this user."
        raise TokensUnavailable(msg)

    leeway = int(app_settings.TOKEN_REFRESH_LEEWAY if leeway is None else leeway)

    if not token_set.expires_within(leeway) and token_set.access_token:
        return token_set.access_token

    if not token_set.refresh_token:
        msg = "The access token has expired and no refresh token was stored for this session."
        raise TokensUnavailable(msg)

    key = _lock_key(token_set)
    nonce = secrets.token_hex(16)

    if cache.add(key, nonce, LOCK_TIMEOUT):
        try:
            token_set.refresh_from_db()
            # Someone may have refreshed between our check and acquiring the lock.
            if not token_set.expires_within(leeway) and token_set.access_token:
                return token_set.access_token
            _perform_refresh(token_set)
            return token_set.access_token
        finally:
            # Only release our own lock, never someone else's.
            if cache.get(key) == nonce:
                cache.delete(key)

    return _await_other_refresh(token_set, leeway=leeway)


def _await_other_refresh(token_set: Any, *, leeway: int) -> str:
    """Another worker holds the lock; wait briefly for it to write the new token."""
    deadline = time.monotonic() + LOCK_WAIT_TOTAL
    while time.monotonic() < deadline:
        time.sleep(LOCK_POLL_INTERVAL)
        token_set.refresh_from_db()
        if token_set.access_token and not token_set.expires_within(leeway):
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
        return token_set.access_token
    if not token_set.refresh_token:
        msg = "The access token has expired and no refresh token was stored for this session."
        raise TokensUnavailable(msg)

    key = _lock_key(token_set)
    nonce = secrets.token_hex(16)

    if await cache.aadd(key, nonce, LOCK_TIMEOUT):
        try:
            await sync_to_async(token_set.refresh_from_db)()
            if not token_set.expires_within(leeway) and token_set.access_token:
                return token_set.access_token
            await sync_to_async(_perform_refresh)(token_set)
            return token_set.access_token
        finally:
            if await cache.aget(key) == nonce:
                await cache.adelete(key)

    deadline = time.monotonic() + LOCK_WAIT_TOTAL
    while time.monotonic() < deadline:
        await asyncio.sleep(LOCK_POLL_INTERVAL)
        await sync_to_async(token_set.refresh_from_db)()
        if token_set.access_token and not token_set.expires_within(leeway):
            return token_set.access_token
    msg = "Timed out waiting for another worker to refresh the access token."
    raise TokensUnavailable(msg)


def get_access_token_for_user(user: Any, *, offline_only: bool = False, leeway: int | None = None) -> str:
    """Convenience wrapper: find the user's token set and return a valid access token."""
    from django_pyoidc_keycloak.tokens.store import get_token_set

    token_set = get_token_set(user, offline_only=offline_only)
    if token_set is None:
        msg = f"No stored tokens for {user}."
        raise TokensUnavailable(msg)
    return get_valid_access_token(token_set, leeway=leeway)
