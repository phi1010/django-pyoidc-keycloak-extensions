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
from datetime import UTC, datetime
from typing import Any

from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation
from django.utils import timezone

from django_pyoidc_keycloak.backends import resolve_session_backend_path
from django_pyoidc_keycloak.conf import app_settings
from django_pyoidc_keycloak.models import KeycloakUser
from django_pyoidc_keycloak.scrub import scrub_exception
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

    user_model: type[KeycloakUser] = get_user_model()
    keycloak_id = uuid.UUID(str(sub))
    logger.debug("Resolving the local user for Keycloak %s at login", keycloak_id)

    try:
        user = user_model.objects.get(keycloak_id=keycloak_id)
        created = False
    except user_model.DoesNotExist:
        user = user_model(keycloak_id=keycloak_id)
        created = True

    if app_settings.SYNC_ON_LOGIN or created:
        representation = _representation_from_claims(tokens, str(sub))
        apply_representation(user, representation)
        user.last_synced_at = timezone.now()
    user.save()

    logger.debug(
        "Login %s local user %s for Keycloak %s (SYNC_ON_LOGIN=%s)",
        "created" if created else "matched",
        user.pk,
        keycloak_id,
        app_settings.SYNC_ON_LOGIN,
    )

    if created:
        user_created.send(sender=user_model, user=user, representation={"id": str(sub)})

    _sync_authorization_from_login(user, tokens, client)

    # Keep the raw tokens until hook_user_login can attach them to the session row.
    if app_settings.STORE_TOKENS:
        stash_tokens(user, extract_raw_tokens(client, tokens))

    # auth.login() records this path in the session; get_user() resolves the user through it.
    user.backend = resolve_session_backend_path()
    return user


def _issued_at(tokens: dict[str, Any]) -> datetime | None:
    """When the token was issued, from its ``iat`` claim."""
    raw = _claim(tokens, "iat")
    if raw is None:
        return None
    try:
        return datetime.fromtimestamp(int(raw), tz=UTC)
    except TypeError, ValueError, OverflowError, OSError:
        return None


def _sync_authorization_from_login(user: Any, tokens: dict[str, Any], client: Any) -> None:
    """Groups, roles and the staff flags from the claims, unless reconciled data is newer.

    Each kind prefers its claim and falls back to the Admin API only when the claim is
    absent altogether.  The stamp written afterwards is the token's ``iat``, not now: the
    data is only as fresh as the token, and a reconcile that ran in between must win.
    """
    from django_pyoidc_keycloak.sync.groups import apply_group_paths, sync_user_groups
    from django_pyoidc_keycloak.sync.roles import (
        REALM,
        apply_flag_roles,
        apply_role_names,
        read_user_roles,
        role_clients,
    )

    issued_at = _issued_at(tokens)
    synced_at = user.authorization_synced_at
    if issued_at is not None and synced_at is not None and synced_at > issued_at:
        logger.debug(
            "Authorization data for %s was synchronised at %s, after this token was issued at %s; keeping it",
            user.pk,
            synced_at.isoformat(),
            issued_at.isoformat(),
        )
        return

    try:
        if app_settings.SYNC_GROUPS:
            _sync_groups_from_claims(user, tokens, apply_group_paths, sync_user_groups)

        realm_access = _claim(tokens, "realm_access")
        resource_access = _claim(tokens, "resource_access")
        names: dict[str, list[str]] | None
        if isinstance(realm_access, dict) or isinstance(resource_access, dict):
            realm_access = realm_access if isinstance(realm_access, dict) else {}
            resource_access = resource_access if isinstance(resource_access, dict) else {}
            names = {REALM: [str(name) for name in realm_access.get("roles") or []]}
            for client_id in role_clients():
                # Keycloak omits a client from resource_access when the user holds no role on it.
                entry = resource_access.get(client_id)
                roles = entry.get("roles") if isinstance(entry, dict) else None
                names[client_id] = [str(name) for name in roles or []]
            logger.debug("Applying roles from the realm_access/resource_access claims for %s", user.pk)
        elif app_settings.SYNC_ROLES or app_settings.STAFF_ROLES or app_settings.SUPERUSER_ROLES:
            logger.debug("No role claims; reading roles from the Admin API for %s", user.pk)
            names = read_user_roles(user)
        else:
            names = None

        changed: list[str] = []
        if names is not None:
            if app_settings.SYNC_ROLES:
                apply_role_names(user, names)
            changed = apply_flag_roles(user, names)

        user.authorization_synced_at = issued_at or timezone.now()
        user.save(update_fields=[*changed, "authorization_synced_at"])
    except Exception as exc:
        # Authorization synchronisation must never break a login.
        logger.warning("Could not synchronise authorization at login for %s: %s", user.pk, scrub_exception(exc))


def _sync_groups_from_claims(user: Any, tokens: dict[str, Any], apply_group_paths: Any, sync_user_groups: Any) -> None:
    """Prefer a ``groups`` claim; fall back to the Admin API only if there is none."""
    claim = _claim(tokens, "groups")
    if claim:
        paths = [str(entry) if str(entry).startswith("/") else f"/{entry}" for entry in claim]
        logger.debug("Applying group membership from the 'groups' claim for %s", user.pk)
        apply_group_paths(user, paths)
    else:
        logger.debug("No 'groups' claim; reading membership from the Admin API for %s", user.pk)
        sync_user_groups(user)


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
        store_tokens(session=session, user=user, raw=raw)
    except Exception as exc:
        logger.warning("Could not store tokens for %s: %s", user.pk, scrub_exception(exc))


def user_logout(user_request: Any, logout_request_args: Any = None) -> Any:
    """Purge stored tokens as the user logs out."""
    try:
        session = find_session(user_request, getattr(user_request, "user", None))
        if session is not None:
            purge_for_session(session)
    except Exception as exc:
        logger.warning("Could not purge tokens at logout: %s", scrub_exception(exc))
    return logout_request_args


def session_logout(session: Any) -> None:
    """Purge stored tokens on a back-channel logout."""
    try:
        purge_for_session(session)
    except Exception as exc:
        logger.warning("Could not purge tokens at back-channel logout: %s", scrub_exception(exc))
