"""Group mirroring, and the manual override that survives it."""

from __future__ import annotations

import uuid
from unittest import mock

import pytest
from django.utils import timezone

from django_pyoidc_keycloak.models import GroupMembership, KeycloakGroup
from django_pyoidc_keycloak.models.base import MembershipSource
from django_pyoidc_keycloak.signals import membership_changed
from django_pyoidc_keycloak.sync.groups import (
    apply_group_paths,
    sweep_expired_memberships,
    sync_groups,
    sync_user_groups,
)
from django_pyoidc_keycloak.sync.users import sync_user
from tests.conftest import kc_user

pytestmark = pytest.mark.django_db


def kc_group(name, path=None, children=None):
    return {
        "id": str(uuid.uuid4()),
        "name": name,
        "path": path or f"/{name}",
        "subGroups": children or [],
    }


@pytest.fixture
def client_stub(connection):
    stub = mock.Mock()
    stub.connection = connection
    stub.get_user_groups.return_value = []
    stub.get_user_realm_roles.return_value = []
    return stub


@pytest.fixture
def user(client_stub):
    return sync_user(kc_user(), client=client_stub)


def test_mirrors_the_group_tree(client_stub):
    child = kc_group("support", "/staff/support")
    client_stub.list_groups.return_value = [kc_group("staff", "/staff", [child])]

    sync_groups(client=client_stub)

    staff = KeycloakGroup.objects.get(path="/staff")
    support = KeycloakGroup.objects.get(path="/staff/support")
    assert support.parent == staff


def test_a_group_removed_in_keycloak_is_pruned(client_stub):
    client_stub.list_groups.return_value = [kc_group("staff")]
    sync_groups(client=client_stub)

    client_stub.list_groups.return_value = []
    sync_groups(client=client_stub)

    assert KeycloakGroup.objects.count() == 0


def test_locally_created_groups_are_never_pruned(client_stub):
    KeycloakGroup.objects.create(name="local", path="/local")
    client_stub.list_groups.return_value = []

    sync_groups(client=client_stub)

    assert KeycloakGroup.objects.filter(path="/local").exists()


def test_membership_follows_keycloak(client_stub, user):
    KeycloakGroup.objects.create(name="staff", path="/staff")
    client_stub.get_user_groups.return_value = [{"path": "/staff"}]

    sync_user_groups(user, client=client_stub)

    assert user.memberships.get().group.path == "/staff"


def test_membership_removed_in_keycloak_is_removed_locally(client_stub, user):
    group = KeycloakGroup.objects.create(name="staff", path="/staff")
    GroupMembership.objects.create(user=user, group=group, source=MembershipSource.KEYCLOAK)
    client_stub.get_user_groups.return_value = []

    sync_user_groups(user, client=client_stub)

    assert user.memberships.count() == 0


def test_a_manual_override_survives_synchronisation(client_stub, user):
    """The whole point of the source field: an admin grant is not Keycloak's to revoke."""
    group = KeycloakGroup.objects.create(name="staff", path="/staff")
    GroupMembership.objects.create(user=user, group=group, source=MembershipSource.MANUAL)
    client_stub.get_user_groups.return_value = []

    sync_user_groups(user, client=client_stub)

    assert user.memberships.get().source == MembershipSource.MANUAL


def test_expired_overrides_are_swept(user):
    group = KeycloakGroup.objects.create(name="temp", path="/temp")
    GroupMembership.objects.create(
        user=user,
        group=group,
        source=MembershipSource.MANUAL,
        expires_at=timezone.now() - timezone.timedelta(seconds=1),
    )

    assert sweep_expired_memberships() == 1
    assert user.memberships.count() == 0


def test_keycloak_memberships_are_not_swept_by_expiry(user):
    group = KeycloakGroup.objects.create(name="staff", path="/staff")
    GroupMembership.objects.create(
        user=user,
        group=group,
        source=MembershipSource.KEYCLOAK,
        expires_at=timezone.now() - timezone.timedelta(seconds=1),
    )

    assert sweep_expired_memberships() == 0


def test_membership_changes_are_announced(user):
    KeycloakGroup.objects.create(name="staff", path="/staff")
    seen = []
    membership_changed.connect(lambda **kw: seen.append(kw["action"]), weak=False)

    apply_group_paths(user, ["/staff"])
    apply_group_paths(user, [])

    assert seen == ["added", "removed"]


def test_unknown_group_paths_are_ignored_not_invented(user):
    apply_group_paths(user, ["/not-synced-yet"])

    assert user.memberships.count() == 0
