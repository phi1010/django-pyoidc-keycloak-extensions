"""Settings access for django-pyoidc-keycloak-extensions.

All configuration lives under a single ``KEYCLOAK`` dict in Django settings.  Keycloak
connection credentials are *not* duplicated here: by default they are read from the
django-pyoidc provider configuration, so a project configures its client exactly once.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

DEFAULTS: dict[str, Any] = {
    # Connection. Empty means "take it from the django-pyoidc provider config".
    "OP_NAME": None,
    "SERVER_URL": None,
    "REALM": None,
    "ADMIN_CLIENT_ID": None,
    "ADMIN_CLIENT_SECRET": None,
    # Synchronisation behaviour.
    "IMPORT_ALL_USERS": False,
    "SYNC_ON_LOGIN": True,
    "SYNC_GROUPS": True,
    "USERNAME_STRATEGY": "django_pyoidc_keycloak.sync.usernames.derive_username",
    "STAFF_ROLES": [],
    "SUPERUSER_ROLES": [],
    "EVENT_OVERLAP_SECONDS": 300,
    "EVENT_PAGE_SIZE": 100,
    "USER_PAGE_SIZE": 100,
    "ADMIN_BULK_INLINE_LIMIT": 50,
    # Authorization. Permissions are never stored locally; a project's own backend decides.
    "AUTH_BACKEND": None,
    "CREATE_DJANGO_PERMISSIONS": False,
    # Tokens.
    "STORE_TOKENS": True,
    "REQUEST_OFFLINE_ACCESS": False,
    "TOKEN_REFRESH_LEEWAY": 60,
    "TOKEN_EXCHANGE_ENABLED": False,
    # HTTP.
    "REQUEST_TIMEOUT": 10.0,
    "MAX_RETRIES": 3,
}

#: Settings that are read from the django-pyoidc provider config when unset here.
_PROVIDER_DERIVED = frozenset({"SERVER_URL", "REALM", "ADMIN_CLIENT_ID", "ADMIN_CLIENT_SECRET"})


class AppSettings:
    """Lazy accessor for the ``KEYCLOAK`` settings dict."""

    def __getattr__(self, name: str) -> Any:
        if name not in DEFAULTS:
            msg = f"Unknown setting KEYCLOAK[{name!r}]"
            raise AttributeError(msg)
        return self.get(name)

    def get(self, name: str, default: Any = None) -> Any:
        user_settings = getattr(settings, "KEYCLOAK", {}) or {}
        if name in user_settings and user_settings[name] is not None:
            return user_settings[name]
        if name in DEFAULTS:
            return DEFAULTS[name]
        return default

    def require(self, name: str) -> Any:
        value = self.get(name)
        if value in (None, ""):
            msg = f"KEYCLOAK[{name!r}] is required but not configured."
            raise ImproperlyConfigured(msg)
        return value

    @property
    def user_model(self) -> str:
        return settings.AUTH_USER_MODEL

    @property
    def group_model(self) -> str:
        return getattr(settings, "KEYCLOAK_GROUP_MODEL", "keycloak.KeycloakGroup")

    @property
    def membership_model(self) -> str:
        return getattr(settings, "KEYCLOAK_MEMBERSHIP_MODEL", "keycloak.GroupMembership")


app_settings = AppSettings()
