"""Authorization without stored permissions.

This library stores no permission data at all: no ``user_permissions`` M2M, no group
``permissions`` M2M, no ``auth.Group`` rows.  Every ``has_perm`` call is delegated to the
authentication backends, so a project's own policy engine (for example Open Policy Agent)
is the single decision point.

``is_superuser`` and ``is_staff`` remain meaningful: ``is_staff`` gates admin access and an
active superuser short-circuits every permission check without consulting a backend.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from django.contrib import auth
from django.core.exceptions import PermissionDenied
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from django_pyoidc_keycloak.conf import app_settings


@runtime_checkable
class AuthorizationBackendProtocol(Protocol):
    """The contract a project's authorization backend must satisfy.

    ``get_user`` is not optional: Django's session authentication calls it on every request
    to resolve the logged-in user.  ``authenticate`` may return ``None``, since logging in
    happens through OIDC rather than through the backend.
    """

    def has_perm(self, user_obj: Any, perm: str, obj: Any = None) -> bool: ...

    def has_module_perms(self, user_obj: Any, app_label: str) -> bool: ...

    def get_user(self, user_id: Any) -> Any: ...


def _delegate(user: Any, method: str, *args: Any) -> bool:
    """Ask every backend in turn, exactly as Django's ``_user_has_perm`` does."""
    for backend in auth.get_backends():
        handler = getattr(backend, method, None)
        if handler is None:
            continue
        try:
            if handler(user, *args):
                return True
        except PermissionDenied:
            return False
    return False


class KeycloakAuthorizationMixin(models.Model):
    """The delegating half of Django's ``PermissionsMixin``, with no permission storage.

    Deliberately absent: ``user_permissions``, ``get_user_permissions`` and
    ``get_group_permissions`` -- there is nothing local for them to read.
    """

    is_superuser = models.BooleanField(
        _("superuser status"),
        default=False,
        help_text=_("Grants every permission without consulting the authorization backend."),
    )
    groups = models.ManyToManyField(
        app_settings.group_model,
        through=app_settings.membership_model,
        # GroupMembership has a second FK to the user model (created_by), so name the pair.
        through_fields=("user", "group"),
        related_name="users",
        blank=True,
        verbose_name=_("groups"),
        help_text=_("Group membership, mirrored from Keycloak. Grants no permission by itself."),
    )

    class Meta:
        abstract = True

    def has_perm(self, perm: str, obj: Any = None) -> bool:
        if self.is_active and self.is_superuser:
            return True
        return _delegate(self, "has_perm", perm, obj)

    def has_perms(self, perm_list: Any, obj: Any = None) -> bool:
        if isinstance(perm_list, str):
            msg = "has_perms() takes an iterable of permissions, not a single string."
            raise ValueError(msg)
        return all(self.has_perm(perm, obj) for perm in perm_list)

    def has_module_perms(self, app_label: str) -> bool:
        if self.is_active and self.is_superuser:
            return True
        return _delegate(self, "has_module_perms", app_label)

    def get_all_permissions(self, obj: Any = None) -> set[str]:
        """Union of what the backends report. Nothing is read from the database."""
        permissions: set[str] = set()
        for backend in auth.get_backends():
            getter = getattr(backend, "get_all_permissions", None)
            if getter is not None:
                permissions.update(getter(self, obj))
        return permissions

    def active_groups(self) -> models.QuerySet:
        """Groups whose membership has not expired -- what a policy should consult."""
        return self.groups.filter(
            Q(memberships__expires_at__isnull=True) | Q(memberships__expires_at__gt=timezone.now()),
            memberships__user=self,
        ).distinct()
