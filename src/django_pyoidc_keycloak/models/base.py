"""Abstract models. Projects needing extra fields subclass these instead of the concrete ones.

Every domain model inherits from the abstract base named by ``KEYCLOAK_MODEL_BASE`` (default
:class:`KeycloakModelBase`), which supplies the primary key and the ``created_at`` /
``updated_at`` columns.  A project can point that setting at its own abstract model -- one with
soft deletion or history, say -- and every user, group, membership, role and assignment picks
it up.  If that base adds columns, the project must also swap the concrete models
(``AUTH_USER_MODEL``, ``KEYCLOAK_*_MODEL``) and own their migrations; system check
``keycloak.E009`` says so.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.utils.translation import gettext_lazy as _

from django_pyoidc_keycloak.conf import DEFAULT_MODEL_BASE, app_settings
from django_pyoidc_keycloak.managers import KeycloakUserManager
from django_pyoidc_keycloak.permissions import KeycloakAuthorizationMixin


class KeycloakModelBase(models.Model):
    """The default base: a UUID primary key and creation / modification timestamps."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)

    class Meta:
        abstract = True


#: Column names the default base defines; a swapped-in base may add more only on swapped models.
MODEL_BASE_FIELDS = frozenset({"id", "created_at", "updated_at"})


def _resolve_model_base() -> type[models.Model]:
    if app_settings.model_base == DEFAULT_MODEL_BASE:
        return KeycloakModelBase
    return app_settings.resolve_model_base()


if TYPE_CHECKING:
    ModelBase = KeycloakModelBase
else:
    ModelBase = _resolve_model_base()


class MembershipSource(models.TextChoices):
    """Where a membership or role assignment came from, which decides who may remove it."""

    KEYCLOAK = "keycloak", _("Keycloak")
    MANUAL = "manual", _("Manual override")


class AbstractKeycloakUser(KeycloakAuthorizationMixin, ModelBase, AbstractBaseUser):
    """A Django user whose identity is a Keycloak UUID.

    The primary key is a locally generated UUID rather than Keycloak's ``sub`` so that
    local-only accounts can exist.  ``keycloak_id`` is the link to Keycloak and, when it is
    ``NULL``, marks the account as unmanaged.
    """

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
    authorization_synced_at = models.DateTimeField(
        _("authorization synchronised"),
        null=True,
        blank=True,
        help_text=_(
            "When group membership, role assignments and the staff flags were last taken from Keycloak. "
            "A login whose token was issued before this leaves them alone."
        ),
    )
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


class AbstractKeycloakMirrored(ModelBase):
    """Something copied from the realm: a group or a role.

    ``keycloak_id`` is ``NULL`` for rows created locally in the admin; synchronisation never
    prunes those and never grants them through a claim.
    """

    keycloak_id = models.UUIDField(
        _("Keycloak ID"),
        unique=True,
        null=True,
        blank=True,
        db_index=True,
        help_text=_("Empty for rows created locally in the admin."),
    )
    keycloak_attributes = models.JSONField(_("Keycloak attributes"), default=dict, blank=True)
    last_synced_at = models.DateTimeField(_("last synchronised"), null=True, blank=True)

    class Meta:
        abstract = True

    @property
    def is_managed(self) -> bool:
        return self.keycloak_id is not None


class AbstractKeycloakGroup(AbstractKeycloakMirrored):
    """A group mirrored from Keycloak.

    Carries no permissions: it is membership metadata for an external policy engine to read.
    """

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

    class Meta:
        abstract = True
        ordering = ["path"]
        verbose_name = _("group")
        verbose_name_plural = _("groups")

    def __str__(self) -> str:
        return self.path or self.name


class AbstractKeycloakRole(AbstractKeycloakMirrored):
    """A realm or client role mirrored from Keycloak.

    ``client_id`` is empty for a realm role and Keycloak's ``clientId`` (not its UUID) for a
    client role, so a policy can read ``django-app:feature1-editor`` without a join.
    """

    name = models.CharField(_("name"), max_length=255)
    client_id = models.CharField(
        _("client"),
        max_length=255,
        blank=True,
        default="",
        help_text=_("The Keycloak client this role belongs to. Empty for a realm role."),
    )
    description = models.TextField(_("description"), blank=True)
    composite = models.BooleanField(_("composite"), default=False)

    class Meta:
        abstract = True
        ordering = ["client_id", "name"]
        constraints = [
            models.UniqueConstraint(fields=["client_id", "name"], name="%(app_label)s_%(class)s_unique_role"),
        ]
        verbose_name = _("role")
        verbose_name_plural = _("roles")

    def __str__(self) -> str:
        return self.name if not self.client_id else f"{self.client_id}:{self.name}"

    @property
    def is_realm_role(self) -> bool:
        return self.client_id == ""


class AbstractGrant(ModelBase):
    """What a group membership and a role assignment have in common.

    Subclasses add the ``user`` foreign key themselves, because its ``related_name`` differs.

    Keycloak owns every ``source="keycloak"`` row: reconciliation adds and removes them to
    match the realm exactly.  ``source="manual"`` rows are an admin override that survives
    synchronisation and disappears when ``expires_at`` passes.
    """

    source = models.CharField(
        _("source"),
        max_length=16,
        choices=MembershipSource.choices,
        # Manual is the safe default: synchronisation always passes source= explicitly, so
        # anything created another way (an admin inline, a shell) is an override that sync
        # must not revoke.
        default=MembershipSource.MANUAL,
    )
    expires_at = models.DateTimeField(
        _("expires at"),
        null=True,
        blank=True,
        help_text=_("Only for manual overrides. Empty means it does not expire."),
    )
    note = models.CharField(_("note"), max_length=255, blank=True)
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

    @property
    def is_expired(self) -> bool:
        from django.utils import timezone

        return self.expires_at is not None and self.expires_at <= timezone.now()


class AbstractGroupMembership(AbstractGrant):
    """Explicit through model, so a manual membership can be time-boxed."""

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

    class Meta:
        abstract = True
        constraints = [
            models.UniqueConstraint(fields=["user", "group"], name="%(app_label)s_%(class)s_unique_membership"),
        ]
        verbose_name = _("group membership")
        verbose_name_plural = _("group memberships")

    def __str__(self) -> str:
        return f"{self.user_id} in {self.group_id} ({self.source})"


class AbstractRoleAssignment(AbstractGrant):
    """Explicit through model between users and roles, with the same override semantics."""

    user = models.ForeignKey(
        app_settings.user_model,
        on_delete=models.CASCADE,
        related_name="role_assignments",
        verbose_name=_("user"),
    )
    role = models.ForeignKey(
        app_settings.role_model,
        on_delete=models.CASCADE,
        related_name="assignments",
        verbose_name=_("role"),
    )

    class Meta:
        abstract = True
        constraints = [
            models.UniqueConstraint(fields=["user", "role"], name="%(app_label)s_%(class)s_unique_assignment"),
        ]
        verbose_name = _("role assignment")
        verbose_name_plural = _("role assignments")

    def __str__(self) -> str:
        return f"{self.user_id} has {self.role_id} ({self.source})"
