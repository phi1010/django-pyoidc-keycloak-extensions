"""Mirroring Keycloak realm and client roles, and the assignments that grant them.

Roles are read *effective*: composites are expanded both on the Admin API (the
``/composite`` endpoints) and in tokens, so the two paths agree.  Only the OIDC client's roles
are mirrored unless ``KEYCLOAK["ROLE_CLIENTS"]`` lists more; realm roles always are.

``source="keycloak"`` assignments are Keycloak's to add and remove.  ``source="manual"`` rows
are an admin override that survives synchronisation until ``expires_at`` passes.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from django.apps import apps
from django.utils import timezone

from django_pyoidc_keycloak.admin_api.client import get_admin_client
from django_pyoidc_keycloak.admin_api.provider import get_connection
from django_pyoidc_keycloak.conf import app_settings
from django_pyoidc_keycloak.models import KeycloakRole, RoleAssignment
from django_pyoidc_keycloak.models.base import MembershipSource
from django_pyoidc_keycloak.scrub import scrub_exception
from django_pyoidc_keycloak.signals import role_assignment_changed, role_synced

logger = logging.getLogger(__name__)

#: The ``client_id`` value of a realm role, and the prefix that names one in a role reference.
REALM = ""
REALM_PREFIX = "realm"

#: Role names by client: ``{"": [realm roles], "django-app": [client roles], ...}``.
RolesByClient = dict[str, list[str]]


def get_role_model() -> type[KeycloakRole]:
    return apps.get_model(app_settings.role_model)


def get_role_assignment_model() -> type[RoleAssignment]:
    return apps.get_model(app_settings.role_assignment_model)


def oidc_client_id() -> str:
    """The client users log in through; the default scope of a bare role reference."""
    return get_connection().client_id


def role_clients() -> list[str]:
    """Which clients' roles are mirrored. Defaults to the OIDC client alone."""
    configured = app_settings.ROLE_CLIENTS
    if configured:
        return [str(entry) for entry in configured]
    return [oidc_client_id()]


def parse_role_reference(reference: str, default_client: str | None = None) -> tuple[str, str]:
    """Turn a ``STAFF_ROLES`` entry into ``(client_id, name)``.

    ``"app-staff"`` is a role on the OIDC client, ``"realm:app-staff"`` a realm role and
    ``"reports-api:reader"`` a role on another client.
    """
    if ":" not in reference:
        return (default_client if default_client is not None else oidc_client_id(), reference)
    scope, name = reference.split(":", 1)
    if scope == REALM_PREFIX:
        return (REALM, name)
    return (scope, name)


# -- the role catalogue -------------------------------------------------


def sync_role(representation: dict[str, Any], *, client_id: str = REALM) -> Any:
    """Create or refresh one role."""
    role_model = get_role_model()
    kc_id = uuid.UUID(str(representation["id"]))
    name = representation.get("name", "")

    role, created = role_model.objects.get_or_create(
        keycloak_id=kc_id,
        defaults={"name": name, "client_id": client_id},
    )
    role.name = name or role.name
    role.client_id = client_id
    role.description = representation.get("description") or ""
    role.composite = bool(representation.get("composite"))
    role.keycloak_attributes = representation.get("attributes") or {}
    role.last_synced_at = timezone.now()
    role.save()

    logger.debug("%s role %s (%s)", "Created" if created else "Refreshed", kc_id, role)
    role_synced.send(sender=role_model, role=role, representation=representation)
    return role


def sync_roles(*, client=None, prune: bool = True) -> dict[str, int]:
    """Mirror the realm's roles and those of every configured client."""
    client = client or get_admin_client()
    role_model = get_role_model()
    seen: set[uuid.UUID] = set()
    counts = {"created": 0, "updated": 0, "deleted": 0}

    def absorb(nodes: list[dict[str, Any]], client_id: str) -> None:
        for node in nodes:
            existed = role_model.objects.filter(keycloak_id=uuid.UUID(str(node["id"]))).exists()
            role = sync_role(node, client_id=client_id)
            seen.add(role.keycloak_id)
            counts["updated" if existed else "created"] += 1

    logger.debug("Mirroring realm roles (prune=%s)", prune)
    absorb(client.list_realm_roles(), REALM)

    for client_id in role_clients():
        representation = client.find_client(client_id)
        if representation is None:
            logger.warning("Client %s is configured for role mirroring but the realm has no such client", client_id)
            continue
        logger.debug("Mirroring the roles of client %s", client_id)
        absorb(client.list_client_roles(str(representation["id"])), client_id)

    if prune:
        # Locally created roles (keycloak_id IS NULL) are never pruned.
        stale = role_model.objects.filter(keycloak_id__isnull=False).exclude(keycloak_id__in=seen)
        counts["deleted"] = stale.count()
        if counts["deleted"]:
            logger.debug(
                "Pruning %d role(s) the realm no longer lists: %s",
                counts["deleted"],
                sorted(str(role) for role in stale),
            )
        stale.delete()

    logger.info(
        "Roles synchronised: %d created, %d updated, %d pruned",
        counts["created"],
        counts["updated"],
        counts["deleted"],
    )
    return counts


# -- per-user assignments -----------------------------------------------


def read_user_roles(user: Any, *, client=None) -> RolesByClient | None:
    """Effective role names for a user from the Admin API, or None if they could not be read."""
    if user.keycloak_id is None:
        logger.debug("User %s is not managed by Keycloak; no roles to read", user.pk)
        return None

    client = client or get_admin_client()
    keycloak_id = str(user.keycloak_id)
    names: RolesByClient = {}

    try:
        names[REALM] = [role["name"] for role in client.get_user_realm_roles(keycloak_id) if role.get("name")]
        for client_id in role_clients():
            representation = client.find_client(client_id)
            if representation is None:
                logger.warning("Client %s is configured for role mirroring but the realm has no such client", client_id)
                names[client_id] = []
                continue
            roles = client.get_user_client_roles(keycloak_id, str(representation["id"]))
            names[client_id] = [role["name"] for role in roles if role.get("name")]
    except Exception as exc:
        logger.warning("Could not read roles for %s: %s", user.keycloak_id, scrub_exception(exc))
        return None

    logger.debug("Keycloak reports %d role(s) for user %s", sum(len(v) for v in names.values()), user.pk)
    return names


def sync_user_roles(user: Any, *, client=None) -> RolesByClient | None:
    """Make the user's Keycloak-sourced assignments match the realm. Returns what was read."""
    names = read_user_roles(user, client=client)
    if names is not None:
        apply_role_names(user, names)
    return names


def apply_role_names(user: Any, names_by_client: RolesByClient) -> dict[str, int]:
    """Reconcile Keycloak-sourced assignments against role names grouped by client.

    Used both by Admin API synchronisation and by the login hook, which reads the names from
    the ``realm_access`` and ``resource_access`` claims without any extra network call.
    """
    role_model = get_role_model()
    assignment_model = get_role_assignment_model()

    logger.debug("Reconciling Keycloak role(s) for user %s across %d scope(s)", user.pk, len(names_by_client))

    # Managed roles only: a locally created role (keycloak_id IS NULL) was never granted by
    # Keycloak, however a claim may be shaped.
    wanted: set[Any] = set()
    missing: list[str] = []
    for client_id, names in names_by_client.items():
        found = dict(
            role_model.objects.filter(client_id=client_id, name__in=names, keycloak_id__isnull=False).values_list(
                "name", "pk"
            )
        )
        wanted.update(found.values())
        missing.extend(f"{client_id}:{name}" if client_id else name for name in set(names) - set(found))

    current = set(
        assignment_model.objects.filter(user=user, source=MembershipSource.KEYCLOAK).values_list("role_id", flat=True)
    )

    added = 0
    for role_pk in wanted - current:
        # A manual override for the same role already satisfies it; leave it alone.
        _obj, created = assignment_model.objects.get_or_create(
            user=user,
            role_id=role_pk,
            defaults={"source": MembershipSource.KEYCLOAK},
        )
        if created:
            added += 1
            role_assignment_changed.send(
                sender=assignment_model,
                user=user,
                role=role_model.objects.get(pk=role_pk),
                action="added",
                source=MembershipSource.KEYCLOAK,
            )

    removable = assignment_model.objects.filter(
        user=user,
        source=MembershipSource.KEYCLOAK,
        role_id__in=current - wanted,
    )
    removed = removable.count()
    for assignment in removable:
        role_assignment_changed.send(
            sender=assignment_model,
            user=user,
            role=assignment.role,
            action="removed",
            source=MembershipSource.KEYCLOAK,
        )
    removable.delete()

    if missing:
        logger.info("Keycloak reported roles that do not exist locally yet: %s", sorted(missing))

    if added or removed:
        logger.info("Roles for user %s: %d added, %d removed", user.pk, added, removed)
    else:
        logger.debug("Roles for user %s already match Keycloak", user.pk)

    return {"added": added, "removed": removed}


def apply_flag_roles(user: Any, names_by_client: RolesByClient) -> list[str]:
    """Derive ``is_staff`` and ``is_superuser`` from the configured role references.

    A flag is only touched when its list is configured, so a project that leaves
    ``SUPERUSER_ROLES`` empty keeps managing that flag by hand.  Returns the changed fields.
    """
    changed: list[str] = []
    default_client = oidc_client_id()
    held = {(client_id, name) for client_id, names in names_by_client.items() for name in names}

    for setting, field in (("STAFF_ROLES", "is_staff"), ("SUPERUSER_ROLES", "is_superuser")):
        references = [str(entry) for entry in (app_settings.get(setting) or [])]
        if not references:
            continue
        wanted = {parse_role_reference(reference, default_client) for reference in references}
        value = bool(held & wanted)
        if getattr(user, field) != value:
            setattr(user, field, value)
            changed.append(field)

    logger.debug("Role flags for user %s: %s", user.pk, changed or "unchanged")
    return changed


def sweep_expired_role_assignments() -> int:
    """Drop manual overrides whose time is up."""
    assignment_model = get_role_assignment_model()
    expired = assignment_model.objects.filter(
        source=MembershipSource.MANUAL,
        expires_at__isnull=False,
        expires_at__lte=timezone.now(),
    )
    count = expired.count()
    if count:
        logger.info("Sweeping %d expired manual role assignment(s)", count)
    else:
        logger.debug("No manual role assignments have expired")
    expired.delete()
    return count
