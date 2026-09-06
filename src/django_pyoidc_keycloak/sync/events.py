"""Incremental synchronisation from Keycloak's event streams.

Events are treated as *triggers only*: the affected id is extracted and the user is then
re-read from ``/users/{id}``.  The event's own ``representation`` blob is never trusted,
which also makes replaying a window harmless.

Two Keycloak facts shape this module:

* Admin events only cover changes made through the Admin API or console.  Self-service
  edits in the account console appear in the separate *user* event stream, and changes made
  by LDAP federation produce no events at all.  Event polling is therefore a latency
  optimisation, never a correctness guarantee -- ``reconcile`` is the backstop.
* ``dateFrom`` is day-granular, so every poll re-reads a window and de-duplicates against
  the cursor.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from django.contrib.auth import get_user_model
from django.utils import timezone

from django_pyoidc_keycloak.admin_api.client import get_admin_client
from django_pyoidc_keycloak.admin_api.exceptions import KeycloakUserNotFound
from django_pyoidc_keycloak.conf import app_settings
from django_pyoidc_keycloak.models.sync import SyncCursor, SyncKind
from django_pyoidc_keycloak.sync.runs import record_error, sync_run
from django_pyoidc_keycloak.sync.users import handle_missing_user, sync_user

logger = logging.getLogger(__name__)

USER_RESOURCE_TYPES = {"USER", "GROUP_MEMBERSHIP", "REALM_ROLE_MAPPING", "CLIENT_ROLE_MAPPING"}
GROUP_RESOURCE_TYPES = {"GROUP"}

#: Account-console self-service actions that change data we mirror.
USER_EVENT_TYPES = ["UPDATE_PROFILE", "UPDATE_EMAIL", "UPDATE_PASSWORD", "VERIFY_EMAIL", "REGISTER"]

_USER_PATH = re.compile(r"users/(?P<id>[0-9a-fA-F-]{36})")
_GROUP_PATH = re.compile(r"groups/(?P<id>[0-9a-fA-F-]{36})")


def _fingerprint(event: dict[str, Any]) -> str:
    """A stable identity for an event, since Keycloak does not give admin events an id."""
    return "|".join(
        str(event.get(key, "")) for key in ("time", "operationType", "resourceType", "resourcePath", "type", "userId")
    )


def _window_start(cursor: SyncCursor) -> datetime:
    overlap = timedelta(seconds=int(app_settings.EVENT_OVERLAP_SECONDS))
    if cursor.last_event_time:
        return cursor.last_event_time - overlap
    return timezone.now() - timedelta(days=1)


def _date_from(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%d")


def _get_cursor(realm: str, stream: str) -> SyncCursor:
    cursor, _ = SyncCursor.objects.get_or_create(realm=realm, stream=stream)
    return cursor


def _event_time(event: dict[str, Any]) -> datetime | None:
    raw = event.get("time")
    if not raw:
        return None
    return datetime.fromtimestamp(int(raw) / 1000, tz=UTC)


def _fetch_all(fetch, *, date_from: str, page_size: int) -> list[dict[str, Any]]:
    """Page through an event endpoint until it runs out."""
    events: list[dict[str, Any]] = []
    first = 0
    while True:
        page = fetch(date_from=date_from, first=first, maximum=page_size)
        events.extend(page)
        if len(page) < page_size:
            return events
        first += page_size


def poll_admin_events(*, client=None) -> dict[str, int]:
    """Process admin events since the cursor and advance it."""
    client = client or get_admin_client()
    realm = client.connection.realm
    page_size = int(app_settings.EVENT_PAGE_SIZE)
    counts = {"processed": 0, "skipped": 0}

    with sync_run(SyncKind.EVENTS, realm=realm) as run:
        cursor = _get_cursor(realm, "admin")
        start = _window_start(cursor)
        events = _fetch_all(client.get_admin_events, date_from=_date_from(start), page_size=page_size)

        latest = cursor.last_event_time
        processed_fingerprints: list[str] = []

        for event in sorted(events, key=lambda item: item.get("time") or 0):
            moment = _event_time(event)
            if moment and moment < start:
                continue
            fingerprint = _fingerprint(event)
            if cursor.has_seen(fingerprint):
                counts["skipped"] += 1
                continue

            try:
                _handle_admin_event(event, client=client, run=run)
            except Exception as exc:
                record_error(run, f"Admin event {event.get('resourcePath')}: {exc}")
            else:
                counts["processed"] += 1

            processed_fingerprints.append(fingerprint)
            if moment and (latest is None or moment > latest):
                latest = moment

        cursor.remember(processed_fingerprints)
        cursor.last_event_time = latest or timezone.now()
        cursor.save()

    return counts


def _handle_admin_event(event: dict[str, Any], *, client, run) -> None:
    resource_type = event.get("resourceType") or ""
    operation = (event.get("operationType") or "").upper()
    path = event.get("resourcePath") or ""

    if resource_type in GROUP_RESOURCE_TYPES:
        from django_pyoidc_keycloak.sync.groups import sync_groups

        sync_groups(client=client)
        return

    if resource_type not in USER_RESOURCE_TYPES:
        return

    match = _USER_PATH.search(path)
    if not match:
        return
    keycloak_id = match.group("id")

    if operation == "DELETE" and resource_type == "USER" and _is_user_root(path):
        _delete_local_user(keycloak_id, run=run)
        return

    try:
        # Re-read rather than trusting the event payload.
        sync_user(keycloak_id=keycloak_id, client=client, create=bool(app_settings.IMPORT_ALL_USERS))
        run.updated += 1
    except KeycloakUserNotFound:
        _delete_local_user(keycloak_id, run=run)


def _is_user_root(path: str) -> bool:
    """True for ``users/<id>``, false for ``users/<id>/groups/<id>`` and friends."""
    tail = path.split("users/", 1)[-1]
    return "/" not in tail.strip("/")


def _delete_local_user(keycloak_id: str, *, run) -> None:
    user_model = get_user_model()
    try:
        user = user_model.objects.get(keycloak_id=keycloak_id)
    except user_model.DoesNotExist:
        return
    if user.is_anonymized:
        # Already handled once; replaying the event must not now hard-delete the tombstone.
        return
    outcome = handle_missing_user(user)
    if outcome == "deleted":
        run.deleted += 1
    else:
        run.anonymized += 1


def poll_user_events(*, client=None) -> dict[str, int]:
    """Process account-console self-service events, which admin events do not cover."""
    client = client or get_admin_client()
    realm = client.connection.realm
    page_size = int(app_settings.EVENT_PAGE_SIZE)
    counts = {"processed": 0, "skipped": 0}

    with sync_run(SyncKind.EVENTS, realm=realm) as run:
        cursor = _get_cursor(realm, "user")
        start = _window_start(cursor)

        def fetch(*, date_from: str, first: int, maximum: int):
            return client.get_user_events(date_from=date_from, types=USER_EVENT_TYPES, first=first, maximum=maximum)

        events = _fetch_all(fetch, date_from=_date_from(start), page_size=page_size)

        latest = cursor.last_event_time
        processed_fingerprints: list[str] = []

        for event in sorted(events, key=lambda item: item.get("time") or 0):
            moment = _event_time(event)
            if moment and moment < start:
                continue
            fingerprint = _fingerprint(event)
            if cursor.has_seen(fingerprint):
                counts["skipped"] += 1
                continue

            keycloak_id = event.get("userId")
            if keycloak_id:
                try:
                    sync_user(keycloak_id=keycloak_id, client=client, create=bool(app_settings.IMPORT_ALL_USERS))
                    run.updated += 1
                    counts["processed"] += 1
                except KeycloakUserNotFound:
                    _delete_local_user(str(keycloak_id), run=run)
                except Exception as exc:
                    record_error(run, f"User event for {keycloak_id}: {exc}")

            processed_fingerprints.append(fingerprint)
            if moment and (latest is None or moment > latest):
                latest = moment

        cursor.remember(processed_fingerprints)
        cursor.last_event_time = latest or timezone.now()
        cursor.save()

    return counts


def poll_events(*, client=None) -> dict[str, int]:
    """Poll both streams."""
    admin = poll_admin_events(client=client)
    user = poll_user_events(client=client)
    return {key: admin.get(key, 0) + user.get(key, 0) for key in set(admin) | set(user)}
