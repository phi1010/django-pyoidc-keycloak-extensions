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
from django_pyoidc_keycloak.models import KeycloakUser
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


def apply_representation(user: Any, representation: dict[str, Any], *, client=None) -> list[str]:
    """Copy Keycloak's view of the account onto the local row. Returns the changed fields.

    Profile fields only: groups, roles and the staff flags are authorization data and are
    handled by :func:`sync_authorization` so that the login hook can apply the same rules.
    ``client`` is accepted for backwards compatibility and no longer used.
    """
    # Keys only: the values are the account's personal data, and this runs on every login.
    logger.debug(
        "Applying a Keycloak representation to user %s; it carries the keys %s",
        user.pk,
        sorted(representation),
    )
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

    if "attributes" in representation:
        # Only when Keycloak actually said something about them: the claims-built
        # representation used at login has no "attributes" key, and absence is not emptiness.
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

    # Field names only -- never the old or new values.
    logger.debug("Representation changed %d field(s) on user %s: %s", len(changed), user.pk, changed or "none")
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
        logger.debug("No representation given for %s; reading it from the Admin API", keycloak_id)
        representation = client.get_user(str(keycloak_id))

    kc_id = representation.get("id") or keycloak_id
    if kc_id is None:
        msg = "The Keycloak representation has no id."
        raise ValueError(msg)
    kc_id = uuid.UUID(str(kc_id))

    user_model: type[KeycloakUser] = get_user_model()
    created_now = False
    try:
        user = user_model.objects.get(keycloak_id=kc_id)
    except user_model.DoesNotExist:
        if create is False:
            logger.debug("No local user for %s and create=False; skipping", kc_id)
            return None
        logger.debug("No local user for %s; creating one", kc_id)
        user = user_model(keycloak_id=kc_id)
        user.set_unusable_password()
        created_now = True

    if user.is_anonymized:
        # The account was deleted in Keycloak once already; do not resurrect it.
        logger.debug("User %s is an anonymised tombstone; refusing to resurrect it", kc_id)
        return user

    changed = apply_representation(user, representation, client=client)
    user.last_synced_at = timezone.now()
    _save_with_username_retry(user, representation)

    logger.debug(
        "%s local user %s from Keycloak %s",
        "Created" if created_now else "Refreshed",
        user.pk,
        kc_id,
    )

    sync_authorization(user, client=client, sync_groups=sync_groups)

    if created_now:
        user_created.send(sender=user_model, user=user, representation=representation)
    else:
        user_synced.send(sender=user_model, user=user, representation=representation, changed_fields=changed)
    return user


def sync_authorization(
    user: Any, *, client=None, sync_groups: bool | None = None, sync_roles: bool | None = None
) -> None:
    """Groups, role assignments and the staff flags, read from the Admin API.

    Stamps ``authorization_synced_at`` with the read time, which is what lets a later login
    with an older token know to leave this data alone.
    """
    from django_pyoidc_keycloak.sync.groups import sync_user_groups
    from django_pyoidc_keycloak.sync.roles import apply_flag_roles, apply_role_names, read_user_roles

    if user.keycloak_id is None:
        return
    client = client or get_admin_client()
    if sync_groups is None:
        sync_groups = bool(app_settings.SYNC_GROUPS)
    if sync_roles is None:
        sync_roles = bool(app_settings.SYNC_ROLES)

    if sync_groups:
        sync_user_groups(user, client=client)

    names = None
    if sync_roles or app_settings.STAFF_ROLES or app_settings.SUPERUSER_ROLES:
        names = read_user_roles(user, client=client)
    if names is not None:
        if sync_roles:
            apply_role_names(user, names)
        changed = apply_flag_roles(user, names)
    else:
        changed = []

    user.authorization_synced_at = timezone.now()
    user.save(update_fields=[*changed, "authorization_synced_at"])


def _save_with_username_retry(user: Any, representation: dict[str, Any], attempts: int = 3) -> None:
    """Save, re-deriving the username if another login claimed it in between.

    The uniqueness check and the save are not one atomic step, so two concurrent logins can
    both decide on the same name. Rather than 500 at login, take the loss and pick again.
    """
    derive = _username_strategy()
    for attempt in range(attempts):
        try:
            with transaction.atomic():
                user.save()
        except IntegrityError:
            if attempt + 1 == attempts:
                logger.debug("Giving up on a free username for %s after %d attempt(s)", user.pk, attempts)
                raise
            # Another login claimed the name between the uniqueness check and the save.
            logger.debug(
                "Username collision saving user %s on attempt %d; deriving another",
                user.pk,
                attempt + 1,
            )
            user.username = derive(representation, exclude_pk=user.pk)
        else:
            return


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
    dropped, _ = user.memberships.all().delete()
    dropped_roles, _ = user.role_assignments.all().delete()
    logger.info(
        "Anonymised user %s (keycloak_id %s), dropping %d membership(s) and %d role assignment(s)",
        user.pk,
        user.keycloak_id,
        dropped,
        dropped_roles,
    )
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
        except (ProtectedError, RestrictedError, IntegrityError) as exc:
            # Something references this user with PROTECT/RESTRICT, or a database-level
            # foreign key rejected the deletion. Keep the row, drop the personal data.
            logger.debug(
                "Deleting user %s was refused by the database (%s); anonymising instead",
                keycloak_id,
                type(exc).__name__,
            )
            transaction.savepoint_rollback(savepoint)
            user.refresh_from_db()
            anonymize(user)
            return "anonymized"
        transaction.savepoint_commit(savepoint)

    logger.info("Deleted local user for Keycloak %s", keycloak_id)
    user_deleted.send(sender=user_model, keycloak_id=keycloak_id, username=username)
    return "deleted"


def handle_missing_user(user: Any) -> str:
    """The user is gone from Keycloak. Remove or anonymise them locally."""
    logger.info("User %s no longer exists in Keycloak", user.keycloak_id)
    return delete_or_anonymize(user)
