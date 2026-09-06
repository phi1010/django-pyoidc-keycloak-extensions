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
