"""Abstract models. Projects needing extra fields subclass these instead of the concrete ones."""

from __future__ import annotations

import uuid

from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.utils.translation import gettext_lazy as _

from django_pyoidc_keycloak.conf import app_settings
from django_pyoidc_keycloak.managers import KeycloakUserManager
from django_pyoidc_keycloak.permissions import KeycloakAuthorizationMixin


class MembershipSource(models.TextChoices):
    """Where a group membership came from, which decides who may remove it."""

    KEYCLOAK = "keycloak", _("Keycloak")
    MANUAL = "manual", _("Manual override")


class AbstractKeycloakUser(KeycloakAuthorizationMixin, AbstractBaseUser):
    """A Django user whose identity is a Keycloak UUID.

    The primary key is a locally generated UUID rather than Keycloak's ``sub`` so that
    local-only accounts can exist.  ``keycloak_id`` is the link to Keycloak and, when it is
    ``NULL``, marks the account as unmanaged.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    keycloak_id = models.UUIDField(
        _("Keycloak ID"),
        unique=True,
        null=True,
        blank=True,
        db_index=True,
        help_text=_("The Keycloak 'sub'. Empty means a local account that synchronisation ignores."),
    )

    username = models.CharField(
        _("username"),
        max_length=150,
        unique=True,
        help_text=_("Derived from Keycloak's preferred_username, with a suffix if that name is taken."),
    )
    email = models.EmailField(_("email address"), blank=True)
    first_name = models.CharField(_("first name"), max_length=150, blank=True)
    last_name = models.CharField(_("last name"), max_length=150, blank=True)
    email_verified = models.BooleanField(_("email verified"), default=False)

    is_active = models.BooleanField(
        _("active"),
        default=True,
        help_text=_("Mirrors Keycloak's 'enabled' flag for managed users."),
    )
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Whether this user may enter the admin site."),
    )

    keycloak_attributes = models.JSONField(_("Keycloak attributes"), default=dict, blank=True)
    date_joined = models.DateTimeField(_("date joined"), null=True, blank=True)
    last_synced_at = models.DateTimeField(_("last synchronised"), null=True, blank=True)
    is_anonymized = models.BooleanField(
        _("anonymised"),
        default=False,
        help_text=_("Set when the Keycloak account was deleted but local data could not be removed."),
    )

    USERNAME_FIELD = "username"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS: list[str] = []

    objects = KeycloakUserManager()

    class Meta:
        abstract = True
        verbose_name = _("user")
        verbose_name_plural = _("users")

    def __str__(self) -> str:
        return self.username

    @property
    def is_managed(self) -> bool:
        """Whether Keycloak owns this account."""
        return self.keycloak_id is not None

    def get_full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip() or self.username

    def get_short_name(self) -> str:
        return self.first_name or self.username


class AbstractKeycloakGroup(models.Model):
    """A group mirrored from Keycloak.

    Carries no permissions: it is membership metadata for an external policy engine to read.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    keycloak_id = models.UUIDField(
        _("Keycloak ID"),
        unique=True,
        null=True,
        blank=True,
        db_index=True,
        help_text=_("Empty for groups created locally in the admin."),
    )
    name = models.CharField(_("name"), max_length=255)
    path = models.CharField(
        _("path"),
        max_length=1000,
        unique=True,
        help_text=_("Keycloak's full group path, for example /staff/support."),
    )
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="children",
        verbose_name=_("parent group"),
    )
    description = models.TextField(_("description"), blank=True)
    keycloak_attributes = models.JSONField(_("Keycloak attributes"), default=dict, blank=True)
    last_synced_at = models.DateTimeField(_("last synchronised"), null=True, blank=True)

    class Meta:
        abstract = True
        ordering = ["path"]
        verbose_name = _("group")
        verbose_name_plural = _("groups")

    def __str__(self) -> str:
        return self.path or self.name

    @property
    def is_managed(self) -> bool:
        return self.keycloak_id is not None


class AbstractGroupMembership(models.Model):
    """Explicit through model, so a manual membership can be time-boxed.

    Keycloak owns every ``source="keycloak"`` row: reconciliation adds and removes them to
    match the realm exactly.  ``source="manual"`` rows are an admin override that survives
    synchronisation and disappears when ``expires_at`` passes.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        app_settings.user_model,
        on_delete=models.CASCADE,
        related_name="memberships",
        verbose_name=_("user"),
    )
    group = models.ForeignKey(
        app_settings.group_model,
        on_delete=models.CASCADE,
        related_name="memberships",
        verbose_name=_("group"),
    )
    source = models.CharField(
        _("source"),
        max_length=16,
        choices=MembershipSource.choices,
        default=MembershipSource.KEYCLOAK,
    )
    expires_at = models.DateTimeField(
        _("expires at"),
        null=True,
        blank=True,
        help_text=_("Only for manual overrides. Empty means it does not expire."),
    )
    note = models.CharField(_("note"), max_length=255, blank=True)
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    created_by = models.ForeignKey(
        app_settings.user_model,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
        verbose_name=_("created by"),
    )

    class Meta:
        abstract = True
        constraints = [
            models.UniqueConstraint(fields=["user", "group"], name="%(app_label)s_%(class)s_unique_membership"),
        ]
        verbose_name = _("group membership")
        verbose_name_plural = _("group memberships")

    def __str__(self) -> str:
        return f"{self.user_id} in {self.group_id} ({self.source})"

    @property
    def is_expired(self) -> bool:
        from django.utils import timezone

        return self.expires_at is not None and self.expires_at <= timezone.now()
