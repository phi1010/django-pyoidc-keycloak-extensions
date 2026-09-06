"""App configuration and start-up validation."""

from __future__ import annotations

from django.apps import AppConfig

from django_pyoidc_keycloak.conf import app_settings


class KeycloakConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "django_pyoidc_keycloak"
    label = "keycloak"
    verbose_name = "Keycloak"

    def ready(self) -> None:
        from django_pyoidc_keycloak import checks as keycloak_checks  # noqa: F401  (registers checks)

        self._disable_permission_creation()
        self._request_offline_access()

    def _request_offline_access(self) -> None:
        """Add ``offline_access`` to the provider's requested scopes when asked to.

        An offline token is the supported way to act on a user's behalf while they are away:
        unlike a session refresh token it is not capped by SSO Session Max.  Off by default,
        because it is a meaningfully longer-lived credential.

        Safe to do here: django-pyoidc reads DJANGO_PYOIDC when it builds its (memoised)
        OIDCSettings, which happens on the first OIDCClient -- after every app is ready.
        """
        if not app_settings.REQUEST_OFFLINE_ACCESS:
            return

        from django.conf import settings

        providers = getattr(settings, "DJANGO_PYOIDC", None) or {}
        op_name = app_settings.get("OP_NAME")
        targets = [op_name] if op_name else list(providers)

        for name in targets:
            provider = providers.get(name)
            if provider is None:
                continue
            key = "scopes" if "scopes" in provider else "SCOPES" if "SCOPES" in provider else "scopes"
            scopes = list(provider.get(key) or ["openid"])
            if "offline_access" not in scopes:
                provider[key] = [*scopes, "offline_access"]

    def _disable_permission_creation(self) -> None:
        """Stop Django from populating ``auth_permission``.

        This library stores no permissions -- an external policy engine answers every
        ``has_perm`` -- so generating a Permission row per model per app would only create
        rows nothing ever reads.  The two ``contrib.auth`` tables themselves still exist,
        because ``django.contrib.auth`` cannot be removed from INSTALLED_APPS, but they
        stay empty.
        """
        if app_settings.CREATE_DJANGO_PERMISSIONS:
            return
        from django.contrib.auth.management import create_permissions
        from django.db.models.signals import post_migrate

        post_migrate.disconnect(create_permissions, dispatch_uid="django.contrib.auth.management.create_permissions")
        # Older Django versions connect it without a dispatch_uid.
        post_migrate.disconnect(create_permissions)
