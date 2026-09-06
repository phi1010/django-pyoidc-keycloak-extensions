"""Full reconciliation -- the correctness backstop behind event polling.

Event streams miss LDAP-federated changes and expire, so this pass compares the whole realm
against the local database.  It is safe to run on a schedule and safe to interrupt.
"""

from __future__ import annotations

import logging
from typing import Any

from django.contrib.auth import get_user_model

from django_pyoidc_keycloak.admin_api.client import get_admin_client
from django_pyoidc_keycloak.admin_api.exceptions import KeycloakUserNotFound
from django_pyoidc_keycloak.conf import app_settings
from django_pyoidc_keycloak.models.sync import SyncKind
from django_pyoidc_keycloak.sync.groups import sweep_expired_memberships, sync_groups
from django_pyoidc_keycloak.sync.runs import record_error, sync_run
from django_pyoidc_keycloak.sync.users import handle_missing_user, sync_user

logger = logging.getLogger(__name__)


def full_reconcile(*, client=None, import_all: bool | None = None, dry_run: bool = False) -> dict[str, int]:
    """Bring every local user and group into line with the realm.

    Users with ``keycloak_id IS NULL`` are unmanaged and never touched.  Users already
    flagged ``is_anonymized`` are skipped: their Keycloak account is gone by definition, so
    re-checking would only 404 again and risk hard-deleting the tombstone on a second pass.
    """
    client = client or get_admin_client()
    user_model = get_user_model()
    if import_all is None:
        import_all = bool(app_settings.IMPORT_ALL_USERS)

    stats = {"created": 0, "updated": 0, "deleted": 0, "anonymized": 0, "skipped": 0, "groups": 0}

    with sync_run(SyncKind.RECONCILE, realm=client.connection.realm) as run:
        if app_settings.SYNC_GROUPS and not dry_run:
            group_counts = sync_groups(client=client)
            stats["groups"] = group_counts["created"] + group_counts["updated"]

        seen_ids: set[str] = set()
        for representation in client.iter_users():
            keycloak_id = str(representation.get("id"))
            seen_ids.add(keycloak_id)

            exists_locally = user_model.objects.filter(keycloak_id=keycloak_id).exists()
            if not exists_locally and not import_all:
                stats["skipped"] += 1
                run.skipped += 1
                continue

            if dry_run:
                stats["created" if not exists_locally else "updated"] += 1
                continue

            try:
                sync_user(representation, client=client, create=True)
            except Exception as exc:
                record_error(run, f"Syncing {keycloak_id}: {exc}")
                continue

            if exists_locally:
                stats["updated"] += 1
                run.updated += 1
            else:
                stats["created"] += 1
                run.created += 1

        stats.update(_remove_vanished_users(client, seen_ids, run=run, dry_run=dry_run))

        if not dry_run:
            sweep_expired_memberships()

    return stats


def _remove_vanished_users(client, seen_ids: set[str], *, run, dry_run: bool) -> dict[str, int]:
    """Confirm and remove local users that the realm listing did not mention."""
    user_model = get_user_model()
    counts = {"deleted": 0, "anonymized": 0}

    candidates = user_model.objects.filter(keycloak_id__isnull=False, is_anonymized=False).exclude(
        keycloak_id__in=seen_ids
    )

    for user in candidates.iterator():
        try:
            # The listing may simply have raced with a change; confirm before deleting.
            client.get_user(str(user.keycloak_id))
        except KeycloakUserNotFound:
            if dry_run:
                counts["deleted"] += 1
                continue
            outcome = handle_missing_user(user)
            counts["deleted" if outcome == "deleted" else "anonymized"] += 1
            if outcome == "deleted":
                run.deleted += 1
            else:
                run.anonymized += 1
        except Exception as exc:
            record_error(run, f"Confirming {user.keycloak_id}: {exc}")

    return counts


def sync_users(users: Any, *, client=None) -> dict[str, int]:
    """Refresh a specific set of users. Used by the admin's bulk actions."""
    client = client or get_admin_client()
    stats = {"updated": 0, "deleted": 0, "anonymized": 0, "errors": 0}

    with sync_run(SyncKind.MANUAL, realm=client.connection.realm) as run:
        for user in users:
            if user.keycloak_id is None:
                run.skipped += 1
                continue
            try:
                sync_user(keycloak_id=user.keycloak_id, client=client, create=True)
                stats["updated"] += 1
                run.updated += 1
            except KeycloakUserNotFound:
                outcome = handle_missing_user(user)
                stats["deleted" if outcome == "deleted" else "anonymized"] += 1
                if outcome == "deleted":
                    run.deleted += 1
                else:
                    run.anonymized += 1
            except Exception as exc:
                stats["errors"] += 1
                record_error(run, f"Syncing {user.keycloak_id}: {exc}")

    return stats
