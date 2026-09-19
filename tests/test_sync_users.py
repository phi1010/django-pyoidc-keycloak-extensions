"""User synchronisation, deletion and anonymisation."""

from __future__ import annotations

import uuid
from unittest import mock

import pytest
from django.contrib.auth import get_user_model

from django_pyoidc_keycloak.models import KeycloakGroup, KeycloakRole
from django_pyoidc_keycloak.signals import user_anonymized, user_created, user_deleted, user_synced
from django_pyoidc_keycloak.sync.users import anonymize, apply_representation, delete_or_anonymize, sync_user
from tests.conftest import kc_user
from tests.testapp.models import CascadingNote, ProtectedDocument

pytestmark = pytest.mark.django_db


@pytest.fixture
def client_stub():
    """A stand-in Admin API client; no HTTP happens in these tests."""
    stub = mock.Mock()
    stub.get_user_groups.return_value = []
    stub.get_user_realm_roles.return_value = []
    stub.get_user_client_roles.return_value = []
    stub.list_realm_roles.return_value = []
    stub.list_client_roles.return_value = []
    stub.find_client.return_value = None
    return stub


def test_creates_a_user_from_a_representation(client_stub):
    representation = kc_user()

    user = sync_user(representation, client=client_stub)

    assert user.username == "alice"
    assert user.email == "alice@example.org"
    assert user.first_name == "Alice"
    assert user.email_verified is True
    assert str(user.keycloak_id) == representation["id"]
    assert user.has_usable_password() is False


def test_the_primary_key_is_not_the_keycloak_id(client_stub):
    """A local UUID PK is what lets unmanaged accounts exist."""
    representation = kc_user()

    user = sync_user(representation, client=client_stub)

    assert isinstance(user.pk, uuid.UUID)
    assert user.pk != user.keycloak_id


def test_updates_an_existing_user_matched_on_keycloak_id(client_stub):
    representation = kc_user()
    sync_user(representation, client=client_stub)

    representation["email"] = "alice@new.example.org"
    representation["lastName"] = "Smith"
    user = sync_user(representation, client=client_stub)

    assert get_user_model().objects.count() == 1
    assert user.email == "alice@new.example.org"
    assert user.last_name == "Smith"


def test_a_rename_in_keycloak_renames_locally(client_stub):
    representation = kc_user()
    sync_user(representation, client=client_stub)

    representation["preferred_username"] = "alice.jones"
    user = sync_user(representation, client=client_stub)

    assert user.username == "alice.jones"


def test_a_rename_that_collides_gets_a_suffix(client_stub):
    get_user_model().objects.create_user(username="taken")
    representation = kc_user()
    sync_user(representation, client=client_stub)

    representation["preferred_username"] = "taken"
    user = sync_user(representation, client=client_stub)

    assert user.username == "taken-2"


def test_disabled_in_keycloak_becomes_inactive(client_stub):
    representation = kc_user(enabled=False)

    user = sync_user(representation, client=client_stub)

    assert user.is_active is False


def test_re_reads_the_user_when_given_only_an_id(client_stub):
    """Events are triggers only: the representation is always re-fetched."""
    representation = kc_user()
    client_stub.get_user.return_value = representation

    user = sync_user(keycloak_id=representation["id"], client=client_stub)

    client_stub.get_user.assert_called_once_with(representation["id"])
    assert user.username == "alice"


def test_does_not_create_when_create_is_false(client_stub):
    assert sync_user(kc_user(), client=client_stub, create=False) is None
    assert get_user_model().objects.count() == 0


def test_created_timestamp_becomes_date_joined(client_stub):
    user = sync_user(kc_user(), client=client_stub)

    assert user.date_joined is not None
    assert user.date_joined.year == 2023


def test_client_roles_map_to_staff_and_superuser(client_stub):
    """The defaults: app-staff and app-superuser on the OIDC client itself."""
    client_stub.find_client.return_value = {"id": "client-uuid", "clientId": "django-app"}
    client_stub.get_user_client_roles.return_value = [{"name": "app-staff"}]

    user = sync_user(kc_user(), client=client_stub)

    assert user.is_staff is True
    assert user.is_superuser is False
    assert user.authorization_synced_at is not None


def test_a_realm_role_reference_needs_the_prefix(client_stub, settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "STAFF_ROLES": ["realm:support"], "SUPERUSER_ROLES": ["realm:admin"]}
    client_stub.get_user_realm_roles.return_value = [{"name": "support"}]

    user = sync_user(kc_user(), client=client_stub)

    assert user.is_staff is True
    assert user.is_superuser is False


def test_a_bare_reference_does_not_match_a_realm_role(client_stub, settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "STAFF_ROLES": ["support"]}
    client_stub.get_user_realm_roles.return_value = [{"name": "support"}]

    user = sync_user(kc_user(), client=client_stub)

    assert user.is_staff is False


def test_an_unreadable_role_mapping_leaves_the_flags_alone(client_stub):
    client_stub.get_user_realm_roles.side_effect = RuntimeError("boom")
    user = sync_user(kc_user(), client=client_stub)
    user.is_staff = True
    user.save()

    sync_user(kc_user(id=str(user.keycloak_id)), client=client_stub)

    user.refresh_from_db()
    assert user.is_staff is True


def test_sync_emits_created_then_synced(client_stub):
    seen = []
    user_created.connect(lambda **kw: seen.append("created"), weak=False)
    user_synced.connect(lambda **kw: seen.append("synced"), weak=False)

    representation = kc_user()
    sync_user(representation, client=client_stub)
    sync_user(representation, client=client_stub)

    assert seen == ["created", "synced"]


# -- deletion -----------------------------------------------------------


def test_deletes_a_user_nothing_references(client_stub):
    user = sync_user(kc_user(), client=client_stub)
    CascadingNote.objects.create(owner=user, body="goes away too")

    assert delete_or_anonymize(user) == "deleted"
    assert get_user_model().objects.count() == 0


def test_anonymises_when_a_protected_row_blocks_deletion(client_stub):
    user = sync_user(kc_user(), client=client_stub)
    ProtectedDocument.objects.create(owner=user, title="an invoice")
    keycloak_id = user.keycloak_id

    assert delete_or_anonymize(user) == "anonymized"

    user.refresh_from_db()
    assert user.is_anonymized is True
    assert user.is_active is False
    assert user.email == ""
    assert user.first_name == ""
    assert user.username.startswith("deleted-")
    # The tombstone is what stops the account being re-imported as a fresh user.
    assert user.keycloak_id == keycloak_id
    assert ProtectedDocument.objects.count() == 1


def test_anonymising_drops_group_memberships_and_role_assignments(client_stub):
    user = sync_user(kc_user(), client=client_stub)
    group = KeycloakGroup.objects.create(name="staff", path="/staff")
    role = KeycloakRole.objects.create(name="feature1-viewer", client_id="django-app")
    user.memberships.create(group=group)
    user.role_assignments.create(role=role)

    anonymize(user)

    assert user.memberships.count() == 0
    assert user.role_assignments.count() == 0


def test_deletion_signals_carry_the_identity(client_stub):
    events = []
    user_deleted.connect(lambda **kw: events.append(("deleted", kw["keycloak_id"])), weak=False)
    user_anonymized.connect(lambda **kw: events.append(("anonymized", kw["user"].pk)), weak=False)

    user = sync_user(kc_user(), client=client_stub)
    delete_or_anonymize(user)

    assert events[0][0] == "deleted"


def test_refuses_to_delete_an_unmanaged_user():
    user = get_user_model().objects.create_user(username="local-admin")

    with pytest.raises(ValueError, match="unmanaged user"):
        delete_or_anonymize(user)


def test_a_tombstoned_user_is_never_resurrected(client_stub):
    representation = kc_user()
    user = sync_user(representation, client=client_stub)
    ProtectedDocument.objects.create(owner=user, title="an invoice")
    delete_or_anonymize(user)

    returned = sync_user(representation, client=client_stub)

    assert returned.is_anonymized is True
    assert returned.username.startswith("deleted-")


def test_apply_representation_reports_what_changed(client_stub):
    user = sync_user(kc_user(), client=client_stub)

    changed = apply_representation(user, kc_user(id=str(user.keycloak_id), email="new@example.org"))

    assert "email" in changed
    assert "first_name" not in changed
