"""Bringing local users into line with Keycloak."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.db.models import ProtectedError, RestrictedError
from django.utils import timezone
from django.utils.module_loading import import_string

from django_pyoidc_keycloak.admin_api.client import get_admin_client
from django_pyoidc_keycloak.conf import app_settings
from django_pyoidc_keycloak.signals import user_anonymized, user_created, user_deleted, user_synced

logger = logging.getLogger(__name__)

#: Fields copied straight across from the Keycloak user representation.
SIMPLE_FIELDS = {
    "email": "email",
    "firstName": "first_name",
    "lastName": "last_name",
    "emailVerified": "email_verified",
}


def _username_strategy():
    return import_string(app_settings.USERNAME_STRATEGY)


def _to_datetime(milliseconds: Any) -> Any:
    if not milliseconds:
        return None
    return datetime.fromtimestamp(int(milliseconds) / 1000, tz=UTC)


def _role_names(client, keycloak_id: str) -> set[str]:
    try:
        return {role.get("name", "") for role in client.get_user_realm_roles(keycloak_id)}
    except Exception as exc:  # a missing role-mapping read must not fail the whole sync
        logger.warning("Could not read realm roles for %s: %s", keycloak_id, exc)
        return set()


def apply_representation(user: Any, representation: dict[str, Any], *, client=None) -> list[str]:
    """Copy Keycloak's view of the account onto the local row. Returns the changed fields."""
    changed: list[str] = []

    for source, target in SIMPLE_FIELDS.items():
        if source in representation:
            value = representation[source] or ("" if target != "email_verified" else False)
            if getattr(user, target) != value:
                setattr(user, target, value)
                changed.append(target)

    if "enabled" in representation:
        enabled = bool(representation["enabled"])
        if user.is_active != enabled:
            user.is_active = enabled
            changed.append("is_active")

    attributes = representation.get("attributes") or {}
    if user.keycloak_attributes != attributes:
        user.keycloak_attributes = attributes
        changed.append("keycloak_attributes")

    created = _to_datetime(representation.get("createdTimestamp"))
    if created and user.date_joined != created:
        user.date_joined = created
        changed.append("date_joined")

    # Username may have been renamed in Keycloak, or may now collide with another local row.
    derive = _username_strategy()
    desired = derive(representation, exclude_pk=user.pk)
    if user.username != desired:
        user.username = desired
        changed.append("username")

    staff_roles = set(app_settings.STAFF_ROLES or [])
    superuser_roles = set(app_settings.SUPERUSER_ROLES or [])
    if (staff_roles or superuser_roles) and client is not None and representation.get("id"):
        roles = _role_names(client, str(representation["id"]))
        if staff_roles:
            is_staff = bool(roles & staff_roles)
            if user.is_staff != is_staff:
                user.is_staff = is_staff
                changed.append("is_staff")
        if superuser_roles:
            is_superuser = bool(roles & superuser_roles)
            if user.is_superuser != is_superuser:
                user.is_superuser = is_superuser
                changed.append("is_superuser")

    return changed


def sync_user(
    representation: dict[str, Any] | None = None,
    *,
    keycloak_id: str | uuid.UUID | None = None,
    client=None,
    create: bool | None = None,
    sync_groups: bool | None = None,
) -> Any:
    """Create or refresh one local user.

    Pass ``keycloak_id`` alone and the representation is re-read from the Admin API.  Events
    are only ever treated as triggers, so this is the normal path from event polling: the
    event's own ``representation`` blob is never trusted.
    """
    client = client or get_admin_client()

    if representation is None:
        if keycloak_id is None:
            msg = "sync_user() needs either a representation or a keycloak_id."
            raise ValueError(msg)
        representation = client.get_user(str(keycloak_id))

    kc_id = representation.get("id") or keycloak_id
    if kc_id is None:
        msg = "The Keycloak representation has no id."
        raise ValueError(msg)
    kc_id = uuid.UUID(str(kc_id))

    user_model = get_user_model()
    created_now = False
    try:
        user = user_model.objects.get(keycloak_id=kc_id)
    except user_model.DoesNotExist:
        if create is False:
            return None
        user = user_model(keycloak_id=kc_id)
        user.set_unusable_password()
        created_now = True

    if user.is_anonymized:
        # The account was deleted in Keycloak once already; do not resurrect it.
        return user

    changed = apply_representation(user, representation, client=client)
    user.last_synced_at = timezone.now()
    user.save()

    if sync_groups is None:
        sync_groups = bool(app_settings.SYNC_GROUPS)
    if sync_groups:
        from django_pyoidc_keycloak.sync.groups import sync_user_groups

        sync_user_groups(user, client=client)

    if created_now:
        user_created.send(sender=user_model, user=user, representation=representation)
    else:
        user_synced.send(sender=user_model, user=user, representation=representation, changed_fields=changed)
    return user


def _create_savepoint():
    """Django 6 renamed transaction.savepoint() to savepoint_create()."""
    create = getattr(transaction, "savepoint_create", None)
    return create() if create is not None else transaction.savepoint()


def anonymize(user: Any) -> None:
    """Strip the account of personal data while keeping the row that others reference."""
    user.username = f"deleted-{uuid.uuid4().hex[:12]}"
    user.email = ""
    user.first_name = ""
    user.last_name = ""
    user.email_verified = False
    user.is_active = False
    user.is_staff = False
    user.is_superuser = False
    user.keycloak_attributes = {}
    user.is_anonymized = True
    user.set_unusable_password()
    # keycloak_id is deliberately kept as a tombstone, so the same Keycloak account is never
    # re-imported as a fresh user.
    user.save()
    user.memberships.all().delete()
    user_anonymized.send(sender=type(user), user=user)


def delete_or_anonymize(user: Any) -> str:
    """Delete the user, or anonymise them when something in the database still needs the row.

    Returns ``"deleted"`` or ``"anonymized"``.
    """
    if user.keycloak_id is None:
        # Unmanaged local accounts are not Keycloak's to remove.
        msg = "Refusing to delete an unmanaged user (keycloak_id is NULL)."
        raise ValueError(msg)

    keycloak_id = user.keycloak_id
    username = user.username
    user_model = type(user)

    with transaction.atomic():
        savepoint = _create_savepoint()
        try:
            user.delete()
        except ProtectedError, RestrictedError, IntegrityError:
            # Something references this user with PROTECT/RESTRICT, or a database-level
            # foreign key rejected the delete. Keep the row, drop the personal data.
            transaction.savepoint_rollback(savepoint)
            user.refresh_from_db()
            anonymize(user)
            return "anonymized"
        transaction.savepoint_commit(savepoint)

    user_deleted.send(sender=user_model, keycloak_id=keycloak_id, username=username)
    return "deleted"


def handle_missing_user(user: Any) -> str:
    """The user is gone from Keycloak. Remove or anonymise them locally."""
    logger.info("User %s no longer exists in Keycloak", user.keycloak_id)
    return delete_or_anonymize(user)
