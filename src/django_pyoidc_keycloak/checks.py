"""System checks: fail loudly at start-up rather than mysteriously at runtime."""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.checks import Error, Warning, register
from django.utils.module_loading import import_string

from django_pyoidc_keycloak.backends import KeycloakSessionBackend
from django_pyoidc_keycloak.conf import app_settings

MODEL_BACKEND = "django.contrib.auth.backends.ModelBackend"


@register()
def check_authentication_backends(app_configs: Any, **kwargs: Any) -> list:
    """The stock ModelBackend would reintroduce database-backed permission lookups."""
    problems: list[Error | Warning] = []
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
                hint="Configure the authorization backend that answers has_perm().",
                id="keycloak.E002",
            )
        )

    if not _has_session_backend(backends):
        problems.append(
            Error(
                "No KeycloakSessionBackend in AUTHENTICATION_BACKENDS.",
                hint=(
                    "auth.get_user() resolves the logged-in user by calling get_user() on the "
                    "backend recorded in the session, and ignores a backend that is not listed -- "
                    "every request would silently be anonymous. Add "
                    "'django_pyoidc_keycloak.backends.KeycloakSessionBackend'."
                ),
                id="keycloak.E004",
            )
        )

    if "AUTH_BACKEND" in (getattr(settings, "KEYCLOAK", {}) or {}):
        problems.append(
            Warning(
                "KEYCLOAK['AUTH_BACKEND'] is set but no longer used.",
                hint=(
                    "The library now resolves sessions through its own KeycloakSessionBackend, so "
                    "your authorization backend no longer needs a get_user(). Remove the setting."
                ),
                id="keycloak.W004",
            )
        )

    return problems


def _has_session_backend(backends: list) -> bool:
    """True when one of the configured backends can resolve a session to a user."""
    for path in backends:
        try:
            backend = import_string(path)
        except ImportError:
            # A backend that cannot even be imported is Django's own error to report.
            continue
        # issubclass, not isinstance: a system check must not instantiate project backends.
        if isinstance(backend, type) and issubclass(backend, KeycloakSessionBackend):
            return True
    return False


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


@register()
def check_cache_backend(app_configs: Any, **kwargs: Any) -> list:
    """The token-refresh mutex needs django-redis's distributed lock.

    redis-py's ``Lock`` -- which django-redis's ``cache.client.lock()`` returns -- acquires
    with ``SET NX PX`` and releases through a token-checked Lua script. The previous
    ``cache.get()``/``cache.delete()`` pair raced with lock expiry and could release
    another worker's lock (SECURITY_REVIEW.md, finding 3), and no cache backend without a
    token-checked release can stand in for it.
    """
    if not app_settings.STORE_TOKENS:
        return []
    backend = (getattr(settings, "CACHES", {}) or {}).get("default", {}).get("BACKEND", "")
    if backend == "django_redis.cache.RedisCache":
        return []
    return [
        Error(
            "CACHES['default'] must use django_redis.cache.RedisCache.",
            hint=(
                "Token refresh takes its mutex through cache.client.lock(), which needs "
                "django-redis. Point CACHES['default'] at "
                "'django_redis.cache.RedisCache' with a Redis LOCATION."
            ),
            id="keycloak.E008",
        )
    ]


@register()
def check_model_base(app_configs: Any, **kwargs: Any) -> list:
    """A swapped-in model base may only add columns to models the project also swapped.

    The library ships migrations for its concrete models, and they know nothing about the
    extra columns a custom base declares; ``migrate`` would leave the tables short.
    """
    from django.apps import apps

    from django_pyoidc_keycloak.models.base import MODEL_BASE_FIELDS, ModelBase

    extra = sorted(f.name for f in ModelBase._meta.local_fields if f.name not in MODEL_BASE_FIELDS)
    extra += sorted(f.name for f in ModelBase._meta.local_many_to_many)
    if not extra:
        return []

    library_defaults = {
        app_settings.user_model: "keycloak.KeycloakUser",
        app_settings.group_model: "keycloak.KeycloakGroup",
        app_settings.membership_model: "keycloak.GroupMembership",
        app_settings.role_model: "keycloak.KeycloakRole",
        app_settings.role_assignment_model: "keycloak.RoleAssignment",
    }
    unswapped = sorted(
        label
        for label, default in library_defaults.items()
        if label.lower() == default.lower() and apps.is_installed("django_pyoidc_keycloak")
    )
    if not unswapped:
        return []
    return [
        Error(
            f"KEYCLOAK_MODEL_BASE {app_settings.model_base!r} adds the field(s) {', '.join(extra)}, but "
            f"{', '.join(unswapped)} still use the library's own migrations.",
            hint=(
                "Subclass the abstract models in your own app, point AUTH_USER_MODEL and the "
                "KEYCLOAK_*_MODEL settings at them, and run makemigrations there. The library's "
                "migrations cannot know about columns your base class adds."
            ),
            id="keycloak.E009",
        )
    ]


@register()
def check_role_references(app_configs: Any, **kwargs: Any) -> list:
    """Every STAFF_ROLES / SUPERUSER_ROLES entry must name a client whose roles are mirrored."""
    from django.core.exceptions import ImproperlyConfigured

    from django_pyoidc_keycloak.sync.roles import REALM, parse_role_reference, role_clients

    try:
        clients = set(role_clients())
    except ImproperlyConfigured:
        return []  # the connection checks report that one
    problems: list[Error | Warning] = []
    for setting in ("STAFF_ROLES", "SUPERUSER_ROLES"):
        for entry in app_settings.get(setting) or []:
            client_id, _name = parse_role_reference(str(entry), next(iter(sorted(clients))))
            if client_id != REALM and client_id not in clients:
                problems.append(
                    Error(
                        f"KEYCLOAK[{setting!r}] entry {entry!r} names client {client_id!r}, "
                        "whose roles are not mirrored.",
                        hint="Add that client to KEYCLOAK['ROLE_CLIENTS'], or use 'realm:<name>' for a realm role.",
                        id="keycloak.E010",
                    )
                )
    return problems
