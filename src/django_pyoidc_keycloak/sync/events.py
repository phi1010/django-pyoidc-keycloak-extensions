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
from django_pyoidc_keycloak.models import KeycloakUser
from django_pyoidc_keycloak.models.sync import SyncCursor, SyncKind
from django_pyoidc_keycloak.scrub import scrub_exception
from django_pyoidc_keycloak.sync.runs import record_error, sync_run
from django_pyoidc_keycloak.sync.users import handle_missing_user, sync_user

logger = logging.getLogger(__name__)

USER_RESOURCE_TYPES = {"USER", "GROUP_MEMBERSHIP", "REALM_ROLE_MAPPING", "CLIENT_ROLE_MAPPING"}
GROUP_RESOURCE_TYPES = {"GROUP"}
ROLE_RESOURCE_TYPES = {"REALM_ROLE", "CLIENT_ROLE"}

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
        logger.debug("Event page from %s at offset %d returned %d event(s)", date_from, first, len(page))
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
        logger.debug(
            "Polling admin events for realm %s from %s (cursor at %s, %ds overlap)",
            realm,
            start.isoformat(),
            cursor.last_event_time.isoformat() if cursor.last_event_time else "never",
            int(app_settings.EVENT_OVERLAP_SECONDS),
        )
        events = _fetch_all(client.get_admin_events, date_from=_date_from(start), page_size=page_size)
        logger.debug("Fetched %d admin event(s) to consider", len(events))

        latest = cursor.last_event_time
        processed_fingerprints: list[str] = []

        for event in sorted(events, key=lambda item: item.get("time") or 0):
            moment = _event_time(event)
            if moment and moment < start:
                logger.debug("Admin event at %s predates the window; ignoring", moment.isoformat())
                continue
            fingerprint = _fingerprint(event)
            if cursor.has_seen(fingerprint):
                # The day-granular dateFrom means every poll re-reads a window.
                logger.debug("Admin event already processed in an earlier poll; skipping")
                counts["skipped"] += 1
                continue

            try:
                _handle_admin_event(event, client=client, run=run)
            except Exception as exc:
                record_error(run, f"Admin event {event.get('resourcePath')}: {scrub_exception(exc)}")
            else:
                counts["processed"] += 1

            processed_fingerprints.append(fingerprint)
            if moment and (latest is None or moment > latest):
                latest = moment

        cursor.remember(processed_fingerprints)
        cursor.last_event_time = latest or timezone.now()
        cursor.save()
        logger.info(
            "Admin event poll for realm %s: %d processed, %d already seen; cursor now at %s",
            realm,
            counts["processed"],
            counts["skipped"],
            cursor.last_event_time.isoformat(),
        )

    return counts


def _handle_admin_event(event: dict[str, Any], *, client, run) -> None:
    resource_type = event.get("resourceType") or ""
    operation = (event.get("operationType") or "").upper()
    path = event.get("resourcePath") or ""

    logger.debug("Admin event: %s %s on %s", operation or "?", resource_type or "?", path or "?")

    if resource_type in GROUP_RESOURCE_TYPES:
        from django_pyoidc_keycloak.sync.groups import sync_groups

        logger.debug("Group event on %s; re-reading the whole group tree", path or "?")
        sync_groups(client=client)
        return

    if resource_type in ROLE_RESOURCE_TYPES:
        from django_pyoidc_keycloak.sync.roles import sync_roles

        logger.debug("Role event on %s; re-reading the role catalogue", path or "?")
        sync_roles(client=client)
        return

    if resource_type not in USER_RESOURCE_TYPES:
        logger.debug("Resource type %r is not mirrored locally; ignoring", resource_type)
        return

    match = _USER_PATH.search(path)
    if not match:
        # Keycloak's resourcePath shape varies by version and by resource, and without an id
        # there is nothing to re-read. Returning silently made that indistinguishable from a
        # successful no-op.
        logger.debug(
            "Admin event of type %s carries no user id in its resourcePath %r; nothing to sync",
            resource_type,
            path,
        )
        return
    keycloak_id = match.group("id")

    if operation == "DELETE" and resource_type == "USER" and _is_user_root(path):
        logger.debug("Admin event deletes user %s at the realm", keycloak_id)
        _delete_local_user(keycloak_id, run=run)
        return

    try:
        # Re-read rather than trusting the event payload.
        logger.debug("Re-reading user %s from the Admin API after a %s event", keycloak_id, resource_type)
        sync_user(keycloak_id=keycloak_id, client=client, create=bool(app_settings.IMPORT_ALL_USERS))
        run.updated += 1
    except KeycloakUserNotFound:
        logger.debug("User %s was already gone when re-read; removing locally", keycloak_id)
        _delete_local_user(keycloak_id, run=run)


def _is_user_root(path: str) -> bool:
    """True for ``users/<id>``, false for ``users/<id>/groups/<id>`` and friends."""
    tail = path.split("users/", 1)[-1]
    return "/" not in tail.strip("/")


def _delete_local_user(keycloak_id: str, *, run) -> None:
    # TODO add django check that ensures that this typing constraint holds with the settings configured.
    user_model: type[KeycloakUser] = get_user_model()
    try:
        user = user_model.objects.get(keycloak_id=keycloak_id)
    except user_model.DoesNotExist:
        # Normal when the account was never imported (IMPORT_ALL_USERS is off), so not a
        # warning -- but it is the difference between "nothing to do" and a missed import.
        logger.debug("Keycloak reported a deletion for %s, which has no local row", keycloak_id)
        return
    if user.is_anonymized:
        # Already handled once; replaying the event must not now hard-delete the tombstone.
        logger.debug("User %s is already an anonymised tombstone; leaving it alone", keycloak_id)
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

        logger.debug(
            "Polling user events for realm %s from %s (types: %s)",
            realm,
            start.isoformat(),
            ", ".join(USER_EVENT_TYPES),
        )
        events = _fetch_all(fetch, date_from=_date_from(start), page_size=page_size)
        logger.debug("Fetched %d user event(s) to consider", len(events))

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
            if not keycloak_id:
                logger.debug("User event of type %r carries no userId; nothing to sync", event.get("type"))
            else:
                logger.debug("User event %r for %s; re-reading from the Admin API", event.get("type"), keycloak_id)
                try:
                    sync_user(keycloak_id=keycloak_id, client=client, create=bool(app_settings.IMPORT_ALL_USERS))
                    run.updated += 1
                    counts["processed"] += 1
                except KeycloakUserNotFound:
                    logger.debug("User %s was already gone when re-read; removing locally", keycloak_id)
                    _delete_local_user(str(keycloak_id), run=run)
                except Exception as exc:
                    record_error(run, f"User event for {keycloak_id}: {scrub_exception(exc)}")

            processed_fingerprints.append(fingerprint)
            if moment and (latest is None or moment > latest):
                latest = moment

        cursor.remember(processed_fingerprints)
        cursor.last_event_time = latest or timezone.now()
        cursor.save()
        logger.info(
            "User event poll for realm %s: %d processed, %d already seen; cursor now at %s",
            realm,
            counts["processed"],
            counts["skipped"],
            cursor.last_event_time.isoformat(),
        )

    return counts


def poll_events(*, client=None) -> dict[str, int]:
    """Poll both streams."""
    logger.debug("Polling both Keycloak event streams")
    admin = poll_admin_events(client=client)
    user = poll_user_events(client=client)
    return {key: admin.get(key, 0) + user.get(key, 0) for key in set(admin) | set(user)}
