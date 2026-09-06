"""User manager for the Keycloak-backed user model."""

from __future__ import annotations

from typing import Any

from django.contrib.auth.base_user import BaseUserManager


class KeycloakUserManager(BaseUserManager):
    """Creates users the way Django expects, with Keycloak's UUID as an optional extra.

    Locally created users have ``keycloak_id = None``: they are *unmanaged*, and
    synchronisation never renames, disables, deletes or anonymises them.  That is what makes
    a bootstrap superuser survive a full reconciliation.
    """

    use_in_migrations = True

    def _create_user(self, username: str, email: str | None, password: str | None, **extra: Any) -> Any:
        if not username:
            msg = "A username is required."
            raise ValueError(msg)
        email = self.normalize_email(email) if email else ""
        user = self.model(username=self.model.normalize_username(username), email=email, **extra)
        if password:
            user.set_password(password)
        else:
            # Authentication happens through Keycloak; there is no local password to check.
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_user(self, username: str, email: str | None = None, password: str | None = None, **extra: Any) -> Any:
        extra.setdefault("is_staff", False)
        extra.setdefault("is_superuser", False)
        return self._create_user(username, email, password, **extra)

    def create_superuser(self, username: str, email: str | None = None, password: str | None = None, **extra: Any):
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        if extra.get("is_staff") is not True:
            msg = "A superuser must have is_staff=True."
            raise ValueError(msg)
        if extra.get("is_superuser") is not True:
            msg = "A superuser must have is_superuser=True."
            raise ValueError(msg)
        return self._create_user(username, email, password, **extra)

    def managed(self):
        """Users that Keycloak owns."""
        return self.get_queryset().filter(keycloak_id__isnull=False)

    def unmanaged(self):
        """Local-only users that synchronisation must never touch."""
        return self.get_queryset().filter(keycloak_id__isnull=True)

    def get_by_keycloak_id(self, keycloak_id: Any):
        return self.get_queryset().get(keycloak_id=keycloak_id)
