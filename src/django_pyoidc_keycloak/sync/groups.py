"""Mirroring Keycloak groups and membership.

Keycloak owns every ``source="keycloak"`` membership: they are added and removed to match
the realm exactly.  ``source="manual"`` rows are an admin override, survive synchronisation,
and disappear only when their ``expires_at`` passes.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from django.apps import apps
from django.db.models.base import ModelBase
from django.utils import timezone

from django_pyoidc_keycloak.admin_api.client import get_admin_client
from django_pyoidc_keycloak.conf import app_settings
from django_pyoidc_keycloak.models import GroupMembership, KeycloakGroup
from django_pyoidc_keycloak.models.base import MembershipSource
from django_pyoidc_keycloak.scrub import scrub_exception
from django_pyoidc_keycloak.signals import group_synced, membership_changed

logger = logging.getLogger(__name__)


def get_group_model() -> type[KeycloakGroup]:
    # TODO add django check that ensures that this typing constraint holds with the settings configured.
    return apps.get_model(app_settings.group_model)


def get_membership_model() -> type[GroupMembership]:
    # TODO add django check that ensures that this typing constraint holds with the settings configured.
    return apps.get_model(app_settings.membership_model)


def sync_group(representation: dict[str, Any], *, parent: Any = None) -> Any:
    """Create or refresh one group. Does not recurse -- see ``sync_groups``."""
    group_model = get_group_model()
    kc_id = uuid.UUID(str(representation["id"]))

    group, created = group_model.objects.get_or_create(
        keycloak_id=kc_id,
        defaults={
            "name": representation.get("name", ""),
            "path": representation.get("path") or f"/{representation.get('name', '')}",
        },
    )
    group.name = representation.get("name", group.name)
    group.path = representation.get("path") or group.path
    group.parent = parent
    group.keycloak_attributes = representation.get("attributes") or {}
    group.last_synced_at = timezone.now()
    group.save()

    logger.debug(
        "%s group %s at path %s (parent %s)",
        "Created" if created else "Refreshed",
        kc_id,
        group.path,
        parent.path if parent is not None else "-",
    )
    group_synced.send(sender=group_model, group=group, representation=representation)
    return group


def sync_groups(*, client=None, prune: bool = True) -> dict[str, int]:
    """Mirror the realm's whole group tree."""
    client = client or get_admin_client()
    group_model = get_group_model()
    seen: set[uuid.UUID] = set()
    counts = {"created": 0, "updated": 0, "deleted": 0}

    def children_of(node: dict[str, Any]) -> list[dict[str, Any]]:
        """Subgroups, however this Keycloak version chooses to report them.

        Current releases return an empty ``subGroups`` list plus ``subGroupCount`` and serve
        the children from a separate endpoint; older ones inline them.
        """
        inline = node.get("subGroups") or []
        if inline:
            logger.debug("Group %s inlined %d subgroup(s)", node.get("id"), len(inline))
            return inline
        if node.get("subGroupCount"):
            logger.debug(
                "Group %s reports %s child(ren); reading them separately", node.get("id"), node["subGroupCount"]
            )
            return client.get_group_children(str(node["id"]))
        return []

    def walk(nodes: list[dict[str, Any]], parent: Any) -> None:
        for node in nodes:
            existed = group_model.objects.filter(keycloak_id=uuid.UUID(str(node["id"]))).exists()
            group = sync_group(node, parent=parent)
            seen.add(group.keycloak_id)
            counts["updated" if existed else "created"] += 1
            walk(children_of(node), group)

    logger.debug("Mirroring the realm group tree (prune=%s)", prune)
    walk(client.list_groups(), None)

    if prune:
        # Locally created groups (keycloak_id IS NULL) are never pruned.
        stale = group_model.objects.filter(keycloak_id__isnull=False).exclude(keycloak_id__in=seen)
        counts["deleted"] = stale.count()
        if counts["deleted"]:
            logger.debug(
                "Pruning %d group(s) the realm no longer lists: %s",
                counts["deleted"],
                sorted(stale.values_list("path", flat=True)),
            )
        stale.delete()

    logger.info(
        "Group tree synchronised: %d created, %d updated, %d pruned",
        counts["created"],
        counts["updated"],
        counts["deleted"],
    )
    return counts


def sync_user_groups(user: Any, *, client=None) -> dict[str, int]:
    """Make the user's Keycloak-sourced memberships match the realm."""
    if user.keycloak_id is None:
        logger.debug("User %s is not managed by Keycloak; leaving membership alone", user.pk)
        return {"added": 0, "removed": 0}

    client = client or get_admin_client()

    try:
        remote = client.get_user_groups(str(user.keycloak_id))
    except Exception as exc:
        logger.warning("Could not read groups for %s: %s", user.keycloak_id, scrub_exception(exc))
        return {"added": 0, "removed": 0}

    logger.debug("Keycloak reports %d group(s) for user %s", len(remote), user.pk)

    # TODO type check or conversion!
    return apply_group_paths(user, [entry.get("path") for entry in remote if entry.get("path")])


def apply_group_paths(user: Any, paths: list[str]) -> dict[str, int]:
    """Reconcile Keycloak-sourced memberships against a list of group paths.

    Used both by admin-API synchronisation and by the login hook, which can read the paths
    from a ``groups`` claim without any extra network call.
    """
    group_model = get_group_model()
    membership_model = get_membership_model()

    logger.debug("Reconciling %d Keycloak group path(s) for user %s", len(paths), user.pk)

    # Managed groups only. A locally created group (keycloak_id IS NULL) may share a path
    # with something Keycloak reports -- or with something a user can influence through a
    # misconfigured group mapper -- and Keycloak never authorised membership in it.
    wanted = set(group_model.objects.filter(path__in=paths, keycloak_id__isnull=False).values_list("pk", flat=True))
    current = set(
        membership_model.objects.filter(user=user, source=MembershipSource.KEYCLOAK).values_list("group_id", flat=True)
    )

    added = 0
    for group_pk in wanted - current:
        # A manual override for the same group already satisfies membership; leave it alone.
        _obj, created = membership_model.objects.get_or_create(
            user=user,
            group_id=group_pk,
            defaults={"source": MembershipSource.KEYCLOAK},
        )
        if created:
            added += 1
            membership_changed.send(
                sender=membership_model,
                user=user,
                group=group_model.objects.get(pk=group_pk),
                action="added",
                source=MembershipSource.KEYCLOAK,
            )

    removable = membership_model.objects.filter(
        user=user,
        source=MembershipSource.KEYCLOAK,
        group_id__in=current - wanted,
    )
    removed = removable.count()
    for membership in removable:
        membership_changed.send(
            sender=membership_model,
            user=user,
            group=membership.group,
            action="removed",
            source=MembershipSource.KEYCLOAK,
        )
    removable.delete()

    missing = set(paths) - set(
        group_model.objects.filter(path__in=paths, keycloak_id__isnull=False).values_list("path", flat=True)
    )
    if missing:
        logger.info("Keycloak reported groups that do not exist locally yet: %s", sorted(missing))

    if added or removed:
        logger.info("Membership for user %s: %d added, %d removed", user.pk, added, removed)
    else:
        logger.debug("Membership for user %s already matches Keycloak", user.pk)

    return {"added": added, "removed": removed}


def sweep_expired_memberships() -> int:
    """Drop manual overrides whose time is up."""
    membership_model = get_membership_model()
    expired = membership_model.objects.filter(
        source=MembershipSource.MANUAL,
        expires_at__isnull=False,
        expires_at__lte=timezone.now(),
    )
    count = expired.count()
    if count:
        logger.info("Sweeping %d expired manual membership override(s)", count)
    else:
        logger.debug("No manual membership overrides have expired")
    expired.delete()
    return count
