"""django-pyoidc hooks.

Configure them per provider in ``DJANGO_PYOIDC``::

    "hook_get_user": "django_pyoidc_keycloak.hooks.get_user",
    "hook_user_login": "django_pyoidc_keycloak.hooks.user_login",
    "hook_user_logout": "django_pyoidc_keycloak.hooks.user_logout",
    "hook_session_logout": "django_pyoidc_keycloak.hooks.session_logout",
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation
from django.utils import timezone

from django_pyoidc_keycloak.conf import app_settings
from django_pyoidc_keycloak.signals import user_created
from django_pyoidc_keycloak.tokens.extract import extract_raw_tokens
from django_pyoidc_keycloak.tokens.store import find_session, pop_tokens, purge_for_session, stash_tokens, store_tokens

logger = logging.getLogger(__name__)

CLAIM_SOURCES = ("id_token_claims", "access_token_claims", "info_token_claims")


def _claim(tokens: dict[str, Any], name: str) -> Any:
    """Read a claim from whichever of django-pyoidc's token dicts carries it."""
    for source in CLAIM_SOURCES:
        claims = tokens.get(source) or {}
        if isinstance(claims, dict) and claims.get(name) is not None:
            return claims[name]
    return None


def _resolve_backend_path() -> str:
    configured = app_settings.AUTH_BACKEND
    if configured:
        return str(configured)
    backends = list(getattr(settings, "AUTHENTICATION_BACKENDS", []))
    if len(backends) == 1:
        return backends[0]
    msg = (
        "Cannot decide which authentication backend to record on the user. "
        "Set KEYCLOAK['AUTH_BACKEND'] to the dotted path of your authorization backend."
    )
    raise SuspiciousOperation(msg)


def _representation_from_claims(tokens: dict[str, Any], sub: str) -> dict[str, Any]:
    """Build a Keycloak-shaped representation out of the claims we already have.

    Lets a login refresh the user without an Admin API round trip.
    """
    representation: dict[str, Any] = {"id": sub}
    for claim, key in (
        ("preferred_username", "preferred_username"),
        ("email", "email"),
        ("given_name", "firstName"),
        ("family_name", "lastName"),
    ):
        value = _claim(tokens, claim)
        if value is not None:
            representation[key] = value
    verified = _claim(tokens, "email_verified")
    if verified is not None:
        representation["emailVerified"] = bool(verified)
    return representation


def get_user(client: Any, tokens: dict[str, Any]) -> Any:
    """Resolve the local user for this login, keyed on the Keycloak ``sub``.

    Replaces django-pyoidc's ``get_user_by_email``: email addresses change and get reused,
    the ``sub`` does not.
    """
    from django_pyoidc_keycloak.sync.users import apply_representation

    sub = _claim(tokens, "sub")
    if not sub:
        msg = "The OIDC tokens carry no 'sub' claim, so the user cannot be identified."
        raise SuspiciousOperation(msg)

    user_model = get_user_model()
    keycloak_id = uuid.UUID(str(sub))

    try:
        user = user_model.objects.get(keycloak_id=keycloak_id)
        created = False
    except user_model.DoesNotExist:
        user = user_model(keycloak_id=keycloak_id)
        user.set_unusable_password()
        created = True

    if app_settings.SYNC_ON_LOGIN or created:
        representation = _representation_from_claims(tokens, str(sub))
        apply_representation(user, representation)
        user.last_synced_at = timezone.now()
    user.save()

    if created:
        user_created.send(sender=user_model, user=user, representation={"id": str(sub)})

    if app_settings.SYNC_GROUPS:
        _sync_groups_from_login(user, tokens, client)

    # Keep the raw tokens until hook_user_login can attach them to the session row.
    if app_settings.STORE_TOKENS:
        stash_tokens(user, extract_raw_tokens(client, tokens))

    # auth.login() refuses to guess when several backends are configured.
    user.backend = _resolve_backend_path()
    return user


def _sync_groups_from_login(user: Any, tokens: dict[str, Any], client: Any) -> None:
    """Prefer a ``groups`` claim; fall back to the Admin API only if there is none."""
    from django_pyoidc_keycloak.sync.groups import apply_group_paths, sync_user_groups

    claim = _claim(tokens, "groups")
    try:
        if claim:
            paths = [str(entry) if str(entry).startswith("/") else f"/{entry}" for entry in claim]
            logger.debug("Applying group membership from the 'groups' claim for %s", user.pk)
            apply_group_paths(user, paths)
        else:
            logger.debug("No 'groups' claim; reading membership from the Admin API for %s", user.pk)
            sync_user_groups(user)
    except Exception as exc:
        # Group synchronisation must never break a login.
        logger.warning("Could not synchronise groups at login for %s: %s", user.pk, exc)


def user_login(request: Any, user: Any) -> None:
    """Write the tokens stashed by :func:`get_user`, now that the session row exists."""
    raw = pop_tokens(user)
    if raw is None or not app_settings.STORE_TOKENS:
        return
    session = find_session(request, user)
    if session is None:
        logger.warning("No OIDCSession found for this login; tokens were not stored.")
        return
    try:
        store_tokens(session=session, user=user, raw=raw, is_offline=bool(app_settings.REQUEST_OFFLINE_ACCESS))
    except Exception as exc:
        logger.warning("Could not store tokens for %s: %s", user.pk, exc)


def user_logout(user_request: Any, logout_request_args: Any = None) -> Any:
    """Purge stored tokens as the user logs out."""
    try:
        session = find_session(user_request)
        if session is not None:
            purge_for_session(session)
    except Exception as exc:
        logger.warning("Could not purge tokens at logout: %s", exc)
    return logout_request_args


def session_logout(session: Any) -> None:
    """Purge stored tokens on a back-channel logout."""
    try:
        purge_for_session(session)
    except Exception as exc:
        logger.warning("Could not purge tokens at back-channel logout: %s", exc)
