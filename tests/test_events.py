"""Event polling: triggers only, idempotent, and cursor-driven."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest import mock

import pytest
from django.contrib.auth import get_user_model

from django_pyoidc_keycloak.models import SyncCursor, SyncRun
from django_pyoidc_keycloak.sync.events import poll_admin_events, poll_user_events
from django_pyoidc_keycloak.sync.users import sync_user
from tests.conftest import kc_user
from tests.testapp.models import ProtectedDocument

pytestmark = pytest.mark.django_db

NOW_MS = int(datetime.now(tz=UTC).timestamp() * 1000)


def admin_event(**overrides):
    event = {
        "time": NOW_MS,
        "operationType": "UPDATE",
        "resourceType": "USER",
        "resourcePath": f"users/{uuid.uuid4()}",
        "realmId": "demo",
    }
    event.update(overrides)
    return event


@pytest.fixture
def client_stub(connection):
    stub = mock.Mock()
    stub.connection = connection
    stub.get_user_groups.return_value = []
    stub.get_user_realm_roles.return_value = []
    stub.get_user_client_roles.return_value = []
    stub.list_realm_roles.return_value = []
    stub.list_client_roles.return_value = []
    stub.find_client.return_value = None
    stub.get_user_events.return_value = []
    stub.get_admin_events.return_value = []
    return stub


def test_an_update_event_re_reads_the_user(client_stub):
    """The event payload is never trusted; the user is fetched fresh."""
    representation = kc_user()
    client_stub.get_user.return_value = representation
    client_stub.get_admin_events.side_effect = [
        [admin_event(resourcePath=f"users/{representation['id']}", representation={"username": "LIES"})],
        [],
    ]

    poll_admin_events(client=client_stub)

    client_stub.get_user.assert_called_with(representation["id"])
    assert get_user_model().objects.count() == 0  # IMPORT_ALL_USERS is off


def test_an_update_event_refreshes_a_known_user(client_stub):
    representation = kc_user()
    sync_user(representation, client=client_stub)
    representation["email"] = "changed@example.org"
    client_stub.get_user.return_value = representation
    client_stub.get_admin_events.side_effect = [
        [admin_event(resourcePath=f"users/{representation['id']}")],
        [],
    ]

    poll_admin_events(client=client_stub)

    assert get_user_model().objects.get().email == "changed@example.org"


def test_a_delete_event_removes_the_user(client_stub):
    representation = kc_user()
    user = sync_user(representation, client=client_stub)
    client_stub.get_admin_events.side_effect = [
        [admin_event(operationType="DELETE", resourcePath=f"users/{representation['id']}")],
        [],
    ]

    poll_admin_events(client=client_stub)

    assert not get_user_model().objects.filter(pk=user.pk).exists()


def test_a_delete_event_anonymises_a_protected_user(client_stub):
    representation = kc_user()
    user = sync_user(representation, client=client_stub)
    ProtectedDocument.objects.create(owner=user, title="an invoice")
    client_stub.get_admin_events.side_effect = [
        [admin_event(operationType="DELETE", resourcePath=f"users/{representation['id']}")],
        [],
    ]

    poll_admin_events(client=client_stub)

    user.refresh_from_db()
    assert user.is_anonymized is True
    assert SyncRun.objects.get().anonymized == 1


def test_a_membership_delete_is_not_a_user_delete(client_stub):
    """`users/<id>/groups/<id>` must not be read as 'the user was deleted'."""
    representation = kc_user()
    user = sync_user(representation, client=client_stub)
    client_stub.get_user.return_value = representation
    client_stub.get_admin_events.side_effect = [
        [
            admin_event(
                operationType="DELETE",
                resourceType="GROUP_MEMBERSHIP",
                resourcePath=f"users/{representation['id']}/groups/{uuid.uuid4()}",
            )
        ],
        [],
    ]

    poll_admin_events(client=client_stub)

    user.refresh_from_db()
    assert user.is_anonymized is False


def test_replaying_the_same_window_changes_nothing(client_stub):
    """dateFrom is day-granular, so every poll re-reads events it has already seen."""
    representation = kc_user()
    sync_user(representation, client=client_stub)
    client_stub.get_user.return_value = representation
    event = admin_event(resourcePath=f"users/{representation['id']}")

    client_stub.get_admin_events.side_effect = [[event], []]
    first = poll_admin_events(client=client_stub)

    client_stub.get_admin_events.side_effect = [[event], []]
    second = poll_admin_events(client=client_stub)

    assert first["processed"] == 1
    assert second["processed"] == 0
    assert second["skipped"] == 1


def test_the_cursor_advances_to_the_newest_event(client_stub):
    client_stub.get_admin_events.side_effect = [[admin_event()], []]

    poll_admin_events(client=client_stub)

    cursor = SyncCursor.objects.get(realm="demo", stream="admin")
    assert cursor.last_event_time is not None
    assert cursor.seen_event_ids


def test_a_failing_event_is_recorded_without_stopping_the_poll(client_stub):
    client_stub.get_user.side_effect = RuntimeError("Keycloak said no")
    client_stub.get_admin_events.side_effect = [
        [admin_event(resourcePath=f"users/{uuid.uuid4()}")],
        [],
    ]

    poll_admin_events(client=client_stub)

    run = SyncRun.objects.get()
    assert run.errors == 1
    assert "Keycloak said no" in run.error_detail


def test_a_failing_admin_event_is_scrubbed_at_the_source(client_stub, monkeypatch):
    """Finding 1: every other call site passes a scrubbed message to record_error; the
    admin-event handler interpolated the raw exception and leaned on the sink's scrub.

    This spies on the message itself: with the fix it arrives already redacted, so the
    guarantee no longer depends on record_error scrubbing last."""
    from django_pyoidc_keycloak.sync import events as events_module
    from django_pyoidc_keycloak.sync import runs as runs_module

    received: list[str] = []
    real_record_error = runs_module.record_error

    def spy(run, message):
        received.append(message)
        return real_record_error(run, message)

    monkeypatch.setattr(events_module, "record_error", spy)

    opaque = "A" * 48  # long enough for scrub_text's opaque-token pattern to catch
    client_stub.get_user.side_effect = RuntimeError(f"Keycloak said no to {opaque}")
    client_stub.get_admin_events.side_effect = [
        [admin_event(resourcePath=f"users/{uuid.uuid4()}")],
        [],
    ]

    poll_admin_events(client=client_stub)

    assert received, "the failing event never reached record_error"
    for message in received:
        assert opaque not in message, "the raw exception reached record_error unscrubbed"
        assert "[redacted]" in message

    run = SyncRun.objects.get()
    assert run.errors == 1
    assert opaque not in run.error_detail


def test_account_console_edits_come_from_the_user_event_stream(client_stub):
    """Self-service profile edits produce no admin event at all."""
    representation = kc_user()
    sync_user(representation, client=client_stub)
    representation["email"] = "self-service@example.org"
    client_stub.get_user.return_value = representation
    client_stub.get_user_events.side_effect = [
        [{"time": NOW_MS, "type": "UPDATE_PROFILE", "userId": representation["id"]}],
        [],
    ]

    poll_user_events(client=client_stub)

    assert get_user_model().objects.get().email == "self-service@example.org"


def test_the_two_streams_keep_separate_cursors(client_stub):
    client_stub.get_admin_events.side_effect = [[admin_event()], []]
    client_stub.get_user_events.side_effect = [[], []]

    poll_admin_events(client=client_stub)
    poll_user_events(client=client_stub)

    assert SyncCursor.objects.filter(realm="demo").count() == 2


def test_a_replayed_delete_does_not_hard_delete_a_tombstone(client_stub):
    """The protecting row may be gone by then; the tombstone must still survive."""
    representation = kc_user()
    user = sync_user(representation, client=client_stub)
    document = ProtectedDocument.objects.create(owner=user, title="an invoice")
    event = admin_event(operationType="DELETE", resourcePath=f"users/{representation['id']}")

    client_stub.get_admin_events.side_effect = [[event], []]
    poll_admin_events(client=client_stub)
    document.delete()

    SyncCursor.objects.all().delete()  # as if the cursor had been reset or the window re-read
    client_stub.get_admin_events.side_effect = [[event], []]
    poll_admin_events(client=client_stub)

    user.refresh_from_db()
    assert user.is_anonymized is True
