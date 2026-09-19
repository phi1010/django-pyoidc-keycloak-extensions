"""Admin integration.

Two things worth noting:

* Django's native groups are unregistered, because this library replaces them with a UUID
  group model mirrored from Keycloak.
* Fields Keycloak owns are read-only.  Synchronisation is one-way, so an edit here would be
  silently reverted on the next pass -- better to not offer it.
* ``OIDCTokenSet`` is deliberately *not* registered: it holds secret material.  The user
  page shows only whether tokens exist and when they expire.
"""

from __future__ import annotations

import logging
from typing import Any

from django.contrib import admin, messages
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group as DjangoGroup
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponseRedirect
from django.urls import path, reverse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext
from django.views.decorators.http import require_POST

from django_pyoidc_keycloak.admin_api.exceptions import KeycloakError, KeycloakUserNotFound
from django_pyoidc_keycloak.conf import app_settings
from django_pyoidc_keycloak.models import (
    GroupMembership,
    KeycloakGroup,
    KeycloakRole,
    RoleAssignment,
    SyncRun,
)
from django_pyoidc_keycloak.models.base import MembershipSource
from django_pyoidc_keycloak.sync.reconcile import sync_users
from django_pyoidc_keycloak.sync.users import handle_missing_user, sync_user
from django_pyoidc_keycloak.tasks import CELERY_AVAILABLE

logger = logging.getLogger(__name__)

# Native groups are replaced by the Keycloak-mirrored model.
try:
    admin.site.unregister(DjangoGroup)
except admin.sites.NotRegistered:
    pass


KEYCLOAK_OWNED_USER_FIELDS = (
    "keycloak_id",
    "username",
    "email",
    "first_name",
    "last_name",
    "email_verified",
    "is_active",
    "date_joined",
    "last_synced_at",
    "authorization_synced_at",
    "keycloak_attributes",
    "is_anonymized",
    "created_at",
    "updated_at",
)


class ManagedFilter(admin.SimpleListFilter):
    """Separates Keycloak-owned accounts from local-only ones."""

    title = _("managed by Keycloak")
    parameter_name = "managed"

    def lookups(self, request: HttpRequest, model_admin: Any) -> list[tuple[str, str]]:
        return [("yes", _("Keycloak")), ("no", _("Local only"))]

    def queryset(self, request: HttpRequest, queryset: Any) -> Any:
        if self.value() == "yes":
            return queryset.filter(keycloak_id__isnull=False)
        if self.value() == "no":
            return queryset.filter(keycloak_id__isnull=True)
        return queryset


class SyncPermissionMixin:
    """Adds a per-model ``sync`` verb, independent of Django's four.

    Synchronising is neither reading nor editing: it pulls the record from Keycloak and, when
    the account has gone, deletes or anonymises it locally.  Gating it on ``change`` would
    conflate "may correct this row by hand" with "may re-pull it from the realm", and a policy
    has good reason to grant either without the other -- an operator who may repair drift but
    not edit fields, or an administrator who may edit local-only accounts but must not trigger
    Admin API traffic.

    The codename is derived per model, so a project that swaps the user model gets the verb on
    *its* model: ``<app_label>.sync_<model_name>``, for example ``keycloak.sync_keycloakuser``.
    """

    opts: Any

    def has_sync_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        """Django's action machinery calls this with the request alone, as it does for delete."""
        return request.user.has_perm(f"{self.opts.app_label}.sync_{self.opts.model_name}")


class GroupMembershipInline(admin.TabularInline):
    """Memberships on the user page. Keycloak-sourced rows cannot be edited here."""

    model = GroupMembership
    fk_name = "user"
    extra = 0
    autocomplete_fields = ["group"]
    fields = ("group", "source", "expires_at", "note", "created_by", "created_at")
    readonly_fields = ("created_at",)

    def get_readonly_fields(self, request: HttpRequest, obj: Any = None) -> tuple[str, ...]:
        return self.readonly_fields


class RoleAssignmentInline(admin.TabularInline):
    """Role assignments on the user page. Keycloak-sourced rows cannot be edited here."""

    model = RoleAssignment
    fk_name = "user"
    extra = 0
    autocomplete_fields = ["role"]
    fields = ("role", "source", "expires_at", "note", "created_by", "created_at")
    readonly_fields = ("created_at",)


class KeycloakUserAdmin(SyncPermissionMixin, admin.ModelAdmin):
    list_display = ("username", "email", "is_active", "is_staff", "is_superuser", "managed", "last_synced_at")
    list_filter = (ManagedFilter, "is_active", "is_staff", "is_superuser", "is_anonymized")
    search_fields = ("username", "email", "first_name", "last_name", "keycloak_id")
    ordering = ("username",)
    inlines = [GroupMembershipInline, RoleAssignmentInline]
    actions = ["action_sync_selected", "action_sync_all"]

    fieldsets = (
        (None, {"fields": ("id", "keycloak_id", "username", "email")}),
        (_("Name"), {"fields": ("first_name", "last_name", "email_verified")}),
        (
            _("Permissions"),
            {
                "fields": ("is_active", "is_staff", "is_superuser"),
                "description": _(
                    "Permissions themselves are decided by the authorization backend; nothing is stored here. "
                    "is_staff controls admin access and is_superuser bypasses every check."
                ),
            },
        ),
        (
            _("Keycloak"),
            {
                "fields": (
                    "keycloak_attributes",
                    "date_joined",
                    "last_synced_at",
                    "authorization_synced_at",
                    "is_anonymized",
                    "created_at",
                    "updated_at",
                )
            },
        ),
        (_("Tokens"), {"fields": ("token_status",)}),
    )

    def get_readonly_fields(self, request: HttpRequest, obj: Any = None) -> tuple[str, ...]:
        readonly = ["id", "token_status", "created_at", "updated_at"]
        if obj is not None and obj.keycloak_id is not None:
            # One-way synchronisation: editing these would be undone on the next pass.
            readonly.extend(KEYCLOAK_OWNED_USER_FIELDS)
        return tuple(dict.fromkeys(readonly))

    @admin.display(boolean=True, description=_("Keycloak"))
    def managed(self, obj: Any) -> bool:
        return obj.keycloak_id is not None

    @admin.display(description=_("stored tokens"))
    def token_status(self, obj: Any) -> str:
        """Presence and expiry only -- the tokens themselves are never rendered."""
        if obj.pk is None:
            return _("-")
        token_set = obj.token_sets.order_by("-updated_at").first()
        if token_set is None:
            return _("No tokens stored.")
        expiry = token_set.access_token_expires_at
        when = expiry.strftime("%Y-%m-%d %H:%M") if expiry else _("unknown")
        kind = _("offline") if token_set.is_offline else _("session")
        has_refresh = _("yes") if token_set.refresh_token else _("no")
        return format_html(
            "{} ({}), access token expires {}, refresh token stored: {}",
            _("Stored"),
            kind,
            when,
            has_refresh,
        )

    # -- actions --------------------------------------------------------

    def get_urls(self) -> list:
        urls = super().get_urls()
        custom = [
            path(
                "<path:object_id>/sync/",
                self.admin_site.admin_view(self.sync_single_view),
                name="keycloak_keycloakuser_sync",
            )
        ]
        return custom + urls

    @method_decorator(require_POST)
    def sync_single_view(self, request: HttpRequest, object_id: str) -> Any:
        """The 'Sync now' button on the change form.

        POST-only and permission-checked on purpose.  ``admin_site.admin_view`` only proves
        the caller is staff, and this view changes state -- on a 404 from Keycloak it deletes
        or anonymises the account.  As a GET link it would also have been reachable by CSRF,
        since Django does not protect GET.

        The verb is ``sync``, not ``change``: see :class:`SyncPermissionMixin`.
        """
        if not self.has_sync_permission(request):
            logger.debug("Refusing a 'Sync now' request from user %s: no sync permission", request.user.pk)
            raise PermissionDenied

        user = self.get_object(request, object_id)
        if user is None:
            self.message_user(request, _("That user no longer exists."), messages.WARNING)
            return HttpResponseRedirect(reverse("admin:keycloak_keycloakuser_changelist"))

        if user.keycloak_id is None:
            self.message_user(request, _("This is a local-only account; there is nothing to sync."), messages.WARNING)
        else:
            try:
                sync_user(keycloak_id=user.keycloak_id, create=True)
                self.message_user(request, _("Synchronised from Keycloak."), messages.SUCCESS)
            except KeycloakUserNotFound:
                outcome = handle_missing_user(user)
                self.message_user(
                    request,
                    _("The account no longer exists in Keycloak (%(outcome)s).") % {"outcome": outcome},
                    messages.WARNING,
                )
                return HttpResponseRedirect(reverse("admin:keycloak_keycloakuser_changelist"))
            except KeycloakError as exc:
                self.message_user(request, str(exc), messages.ERROR)

        return HttpResponseRedirect(reverse("admin:keycloak_keycloakuser_change", args=[object_id]))

    def save_formset(self, request: HttpRequest, form: Any, formset: Any, change: bool) -> None:
        """Memberships and assignments added here are manual overrides, like those added on their own page.

        Without this they would inherit no author and read as ordinary rows; the model default
        already keeps synchronisation from revoking them.
        """
        instances = formset.save(commit=False)
        for obj in formset.deleted_objects:
            obj.delete()
        for instance in instances:
            if isinstance(instance, GroupMembership | RoleAssignment) and instance._state.adding:
                instance.source = MembershipSource.MANUAL
                instance.created_by = request.user
            instance.save()
        formset.save_m2m()

    def change_view(self, request: HttpRequest, object_id: str, form_url: str = "", extra_context: Any = None) -> Any:
        extra_context = extra_context or {}
        if self.has_sync_permission(request):
            # The template guards on this being present, so a user without the verb is not
            # shown a button that would only 403.
            extra_context["keycloak_sync_url"] = reverse("admin:keycloak_keycloakuser_sync", args=[object_id])
        return super().change_view(request, object_id, form_url, extra_context)

    # ``permissions`` is what makes Django check: without it a custom action runs for any
    # staff user who can open the changelist, since only delete_selected is gated by default.
    @admin.action(description=_("Synchronise selected users from Keycloak"), permissions=["sync"])
    def action_sync_selected(self, request: HttpRequest, queryset: Any) -> None:
        self._run_sync(request, queryset)

    @admin.action(description=_("Synchronise ALL users from Keycloak"), permissions=["sync"])
    def action_sync_all(self, request: HttpRequest, queryset: Any) -> None:
        self._run_sync(request, self.model.objects.filter(keycloak_id__isnull=False), all_users=True)

    def _run_sync(self, request: HttpRequest, queryset: Any, *, all_users: bool = False) -> None:
        """Enqueue when Celery is available, otherwise run inline within a size cap."""
        pks = list(queryset.filter(keycloak_id__isnull=False).values_list("pk", flat=True))
        logger.debug(
            "Admin synchronisation requested by user %s for %d managed user(s) (all_users=%s, celery=%s)",
            request.user.pk,
            len(pks),
            all_users,
            CELERY_AVAILABLE,
        )
        if not pks:
            self.message_user(request, _("None of the selected users are managed by Keycloak."), messages.WARNING)
            return

        if CELERY_AVAILABLE:
            from django_pyoidc_keycloak.tasks import sync_users_task

            sync_users_task.delay([str(pk) for pk in pks])
            self.message_user(
                request,
                ngettext(
                    "Queued %(count)d user for synchronisation.",
                    "Queued %(count)d users for synchronisation.",
                    len(pks),
                )
                % {"count": len(pks)},
                messages.INFO,
            )
            return

        limit = int(app_settings.ADMIN_BULK_INLINE_LIMIT)
        if len(pks) > limit:
            self.message_user(
                request,
                _(
                    "Refusing to synchronise %(count)d users inline: that would block this request. "
                    "Install Celery, run `manage.py keycloak_reconcile`, or raise "
                    "KEYCLOAK['ADMIN_BULK_INLINE_LIMIT'] (currently %(limit)d)."
                )
                % {"count": len(pks), "limit": limit},
                messages.ERROR,
            )
            return

        stats = sync_users(self.model.objects.filter(pk__in=pks))
        self.message_user(
            request,
            _("Updated %(updated)d, deleted %(deleted)d, anonymised %(anonymized)d, %(errors)d error(s).") % stats,
            messages.SUCCESS if not stats["errors"] else messages.WARNING,
        )


@admin.register(KeycloakGroup)
class KeycloakGroupAdmin(admin.ModelAdmin):
    list_display = ("path", "name", "managed", "member_count", "last_synced_at")
    list_filter = ("last_synced_at",)
    search_fields = ("name", "path", "keycloak_id")
    ordering = ("path",)

    @admin.display(boolean=True, description=_("Keycloak"))
    def managed(self, obj: Any) -> bool:
        return obj.keycloak_id is not None

    @admin.display(description=_("members"))
    def member_count(self, obj: Any) -> int:
        return obj.memberships.count()

    def get_readonly_fields(self, request: HttpRequest, obj: Any = None) -> tuple[str, ...]:
        if obj is not None and obj.keycloak_id is not None:
            return ("id", "keycloak_id", "name", "path", "parent", "keycloak_attributes", "last_synced_at")
        return ("id",)


@admin.register(KeycloakRole)
class KeycloakRoleAdmin(admin.ModelAdmin):
    list_display = ("__str__", "client_id", "name", "managed", "composite", "assignment_count", "last_synced_at")
    list_filter = ("client_id", "composite", "last_synced_at")
    search_fields = ("name", "client_id", "keycloak_id")
    ordering = ("client_id", "name")

    @admin.display(boolean=True, description=_("Keycloak"))
    def managed(self, obj: Any) -> bool:
        return obj.keycloak_id is not None

    @admin.display(description=_("assignments"))
    def assignment_count(self, obj: Any) -> int:
        return obj.assignments.count()

    def get_readonly_fields(self, request: HttpRequest, obj: Any = None) -> tuple[str, ...]:
        if obj is not None and obj.keycloak_id is not None:
            return (
                "id",
                "keycloak_id",
                "name",
                "client_id",
                "description",
                "composite",
                "keycloak_attributes",
                "last_synced_at",
            )
        return ("id",)


class GrantAdmin(admin.ModelAdmin):
    """Shared behaviour of the membership and assignment pages."""

    readonly_fields = ("created_at",)
    #: The FK to the granted object, ``group`` or ``role``.
    target_field = ""

    @admin.display(boolean=True, description=_("expired"))
    def expired(self, obj: Any) -> bool:
        return obj.expires_at is not None and obj.expires_at <= timezone.now()

    def save_model(self, request: HttpRequest, obj: Any, form: Any, change: bool) -> None:
        if not change:
            # Anything added by hand is an override that synchronisation must not remove.
            obj.source = MembershipSource.MANUAL
            obj.created_by = request.user
        super().save_model(request, obj, form, change)

    def get_readonly_fields(self, request: HttpRequest, obj: Any = None) -> tuple[str, ...]:
        if obj is not None and obj.source == MembershipSource.KEYCLOAK:
            return ("user", self.target_field, "source", "created_at", "created_by")
        return self.readonly_fields


@admin.register(RoleAssignment)
class RoleAssignmentAdmin(GrantAdmin):
    """Assignment as its own page, so a temporary override can be granted and audited."""

    target_field = "role"
    list_display = ("user", "role", "source", "expires_at", "expired", "created_by", "created_at")
    list_filter = ("source", "role__client_id")
    search_fields = ("user__username", "role__name", "role__client_id", "note")
    autocomplete_fields = ("user", "role")


@admin.register(GroupMembership)
class GroupMembershipAdmin(GrantAdmin):
    """Membership as its own page, so a temporary override can be granted and audited."""

    target_field = "group"
    list_display = ("user", "group", "source", "expires_at", "expired", "created_by", "created_at")
    list_filter = ("source",)
    search_fields = ("user__username", "group__path", "note")
    autocomplete_fields = ("user", "group")


@admin.register(SyncRun)
class SyncRunAdmin(admin.ModelAdmin):
    """Read-only audit view: why did this user change?"""

    list_display = ("started_at", "kind", "realm", "status", "created", "updated", "deleted", "anonymized", "errors")
    list_filter = ("kind", "status", "realm")
    date_hierarchy = "started_at"
    ordering = ("-started_at",)

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def get_readonly_fields(self, request: HttpRequest, obj: Any = None) -> list[str]:
        return [field.name for field in self.model._meta.fields]


# Registered explicitly, and against whatever AUTH_USER_MODEL resolves to.
#
# `@admin.register(KeycloakUser)` looked equivalent but was not: AdminSite.register silently
# ignores a model that has been swapped out, so a project pointing AUTH_USER_MODEL at its own
# subclass got no user admin at all -- and then admin.E039 on the two inlines below, whose
# autocomplete_fields reference a user admin that was never registered.
admin.site.register(get_user_model(), KeycloakUserAdmin)
