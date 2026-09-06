"""System checks: fail loudly at start-up rather than mysteriously at runtime."""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.checks import Error, Warning, register

from django_pyoidc_keycloak.conf import app_settings

MODEL_BACKEND = "django.contrib.auth.backends.ModelBackend"


@register()
def check_authentication_backends(app_configs: Any, **kwargs: Any) -> list:
    """The stock ModelBackend would reintroduce database-backed permission lookups."""
    problems = []
    backends = list(getattr(settings, "AUTHENTICATION_BACKENDS", []))

    if MODEL_BACKEND in backends:
        problems.append(
            Error(
                "django.contrib.auth.backends.ModelBackend is in AUTHENTICATION_BACKENDS.",
                hint=(
                    "This library stores no permissions; ModelBackend would answer has_perm() from "
                    "auth_permission rows instead of your policy engine. Remove it and configure "
                    "your own authorization backend."
                ),
                id="keycloak.E001",
            )
        )

    if not backends:
        problems.append(
            Error(
                "AUTHENTICATION_BACKENDS is empty.",
                hint="Configure the authorization backend that answers has_perm() and get_user().",
                id="keycloak.E002",
            )
        )

    configured = app_settings.AUTH_BACKEND
    if configured is None and len(backends) > 1:
        problems.append(
            Error(
                "Several authentication backends are configured but KEYCLOAK['AUTH_BACKEND'] is unset.",
                hint=(
                    "hook_get_user must stamp user.backend before auth.login(), and Django cannot "
                    "guess which backend to record. Name it in KEYCLOAK['AUTH_BACKEND']."
                ),
                id="keycloak.E003",
            )
        )
    elif configured is not None and configured not in backends:
        problems.append(
            Error(
                f"KEYCLOAK['AUTH_BACKEND'] is {configured!r}, which is not in AUTHENTICATION_BACKENDS.",
                id="keycloak.E004",
            )
        )

    return problems


@register()
def check_encryption_key(app_configs: Any, **kwargs: Any) -> list:
    """Token encryption needs SALT_KEY; without it the field raises on first write."""
    if not app_settings.STORE_TOKENS:
        return []
    if not getattr(settings, "SALT_KEY", None):
        return [
            Error(
                "SALT_KEY is not set, but token storage is enabled.",
                hint=(
                    "django-fernet-encrypted-fields derives its key from SECRET_KEY and SALT_KEY. "
                    "Set SALT_KEY to a long random string kept out of version control, or disable "
                    "storage with KEYCLOAK['STORE_TOKENS'] = False."
                ),
                id="keycloak.E005",
            )
        ]
    return []


@register()
def check_user_model(app_configs: Any, **kwargs: Any) -> list:
    """The user model must carry our mixin, or has_perm() would never reach the backend."""
    from django.contrib.auth import get_user_model

    from django_pyoidc_keycloak.permissions import KeycloakAuthorizationMixin

    try:
        user_model = get_user_model()
    except Exception:  # pragma: no cover - misconfiguration reported by Django itself
        return []

    if not issubclass(user_model, KeycloakAuthorizationMixin):
        return [
            Warning(
                f"{user_model._meta.label} does not inherit KeycloakAuthorizationMixin.",
                hint=(
                    "Subclass AbstractKeycloakUser (or add the mixin) so permission checks are "
                    "delegated to your authorization backend and keycloak_id is available."
                ),
                id="keycloak.W001",
            )
        ]
    return []


@register()
def check_offline_access(app_configs: Any, **kwargs: Any) -> list:
    """An offline token is useless if the scope never made it into the request."""
    if not app_settings.REQUEST_OFFLINE_ACCESS:
        return []

    providers = getattr(settings, "DJANGO_PYOIDC", None) or {}
    op_name = app_settings.get("OP_NAME")
    names = [op_name] if op_name else list(providers)

    missing = [
        name for name in names if name in providers and "offline_access" not in (providers[name].get("scopes") or [])
    ]
    if missing:
        return [
            Warning(
                f"KEYCLOAK['REQUEST_OFFLINE_ACCESS'] is on but offline_access is not in the "
                f"requested scopes for: {', '.join(missing)}.",
                hint=(
                    "The app adds it at start-up, so this usually means the provider was read "
                    "before this app was ready. Add 'offline_access' to that provider's "
                    "'scopes' list in DJANGO_PYOIDC explicitly."
                ),
                id="keycloak.W002",
            )
        ]
    return []


@register()
def check_app_order(app_configs: Any, **kwargs: Any) -> list:
    """Permission creation can only be disconnected if contrib.auth is ready first."""
    installed = list(getattr(settings, "INSTALLED_APPS", []))
    if app_settings.CREATE_DJANGO_PERMISSIONS:
        return []
    try:
        auth_index = next(i for i, app in enumerate(installed) if app.startswith("django.contrib.auth"))
        ours = next(i for i, app in enumerate(installed) if app.startswith("django_pyoidc_keycloak"))
    except StopIteration:
        return []
    if ours < auth_index:
        return [
            Warning(
                "django_pyoidc_keycloak is listed before django.contrib.auth in INSTALLED_APPS.",
                hint=(
                    "Permission creation is disconnected in this app's ready(), which only works "
                    "if django.contrib.auth is ready first. Move it after django.contrib.auth, "
                    "or auth_permission will be populated anyway."
                ),
                id="keycloak.W003",
            )
        ]
    return []


@register()
def check_token_exchange(app_configs: Any, **kwargs: Any) -> list:
    """Keycloak refuses token exchange from a public client."""
    if not app_settings.TOKEN_EXCHANGE_ENABLED:
        return []
    from django.core.exceptions import ImproperlyConfigured

    from django_pyoidc_keycloak.admin_api.provider import get_connection

    try:
        connection = get_connection()
    except ImproperlyConfigured as exc:
        return [Error(str(exc), id="keycloak.E006")]

    if not connection.client_secret:
        return [
            Error(
                "Token exchange is enabled but the client has no secret.",
                hint="Keycloak only allows confidential clients to exchange tokens.",
                id="keycloak.E007",
            )
        ]
    return []
