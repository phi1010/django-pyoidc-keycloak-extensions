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

    Authorization only: resolving the logged-in user from the session is a separate job,
    handled by :class:`~django_pyoidc_keycloak.backends.KeycloakSessionBackend` so that a
    policy engine is only ever asked whether a permission is granted.  ``authenticate`` is
    not required either, since logging in happens through OIDC rather than through a
    backend.

    ``get_all_permissions`` is optional; the admin index page and some third-party apps call
    it when it is present.
    """

    def has_perm(self, user_obj: Any, perm: str, obj: Any = None) -> bool: ...

    def has_module_perms(self, user_obj: Any, app_label: str) -> bool: ...


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
    # ``groups`` and ``roles`` are deliberately *properties* rather than ManyToManyFields.
    #
    # As fields they made the user model depend on GroupMembership and RoleAssignment, which
    # in turn have foreign keys back to AUTH_USER_MODEL. Inside this app that is harmless --
    # one app, one migration graph -- but a project that points AUTH_USER_MODEL at its own
    # subclass of AbstractKeycloakUser then has a genuine circular migration dependency
    # (CircularDependencyError: keycloak.0003, <project>.0001) that it can only escape by
    # hand-splitting its initial migration in two. Nothing was gained in exchange: both
    # through models carry extra columns, so ``.add()`` / ``.set()`` were never usable, and
    # every write in this library goes through the through models directly.
    #
    # Reads are unchanged -- these return the same queryset the descriptors did, so
    # ``user.groups.filter(...)``, ``.values_list(...)`` and iteration all still work.

    class Meta:
        abstract = True

    @property
    def groups(self) -> models.QuerySet:
        """Every group this user belongs to, expired memberships included."""
        from django.apps import apps

        group_model = apps.get_model(app_settings.group_model)
        return group_model.objects.filter(memberships__user=self).distinct()

    @property
    def roles(self) -> models.QuerySet:
        """Every role assigned to this user, expired assignments included."""
        from django.apps import apps

        role_model = apps.get_model(app_settings.role_model)
        return role_model.objects.filter(assignments__user=self).distinct()

    def has_perm(self, perm: str, obj: Any = None) -> bool:
        if not self.is_active:
            # Matches ModelBackend, and means a user disabled in Keycloak loses access as soon
            # as sync flips is_active, without waiting for the policy backend to notice.
            return False
        if self.is_superuser:
            return True
        return _delegate(self, "has_perm", perm, obj)

    def has_perms(self, perm_list: Any, obj: Any = None) -> bool:
        if isinstance(perm_list, str):
            msg = "has_perms() takes an iterable of permissions, not a single string."
            raise ValueError(msg)
        return all(self.has_perm(perm, obj) for perm in perm_list)

    def has_module_perms(self, app_label: str) -> bool:
        if not self.is_active:
            return False
        if self.is_superuser:
            return True
        return _delegate(self, "has_module_perms", app_label)

    def get_all_permissions(self, obj: Any = None) -> set[str]:
        """Union of what the backends report. Nothing is read from the database."""
        if not self.is_active:
            return set()
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
        )

    def active_roles(self) -> models.QuerySet:
        """Roles whose assignment has not expired."""
        return self.roles.filter(
            Q(assignments__expires_at__isnull=True) | Q(assignments__expires_at__gt=timezone.now()),
            assignments__user=self,
        )

    def has_role(self, name: str, client_id: str = "") -> bool:
        """Whether an unexpired assignment grants this role. ``client_id=""`` means a realm role."""
        return self.active_roles().filter(name=name, client_id=client_id).exists()
