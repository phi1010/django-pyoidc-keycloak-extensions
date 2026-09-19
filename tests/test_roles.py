"""Role mirroring, assignments, the manual override, and the staff-flag mapping."""

from __future__ import annotations

import uuid
from unittest import mock

import pytest
from django.utils import timezone

from django_pyoidc_keycloak.admin_api.exceptions import KeycloakNotFound
from django_pyoidc_keycloak.models import KeycloakRole, RoleAssignment
from django_pyoidc_keycloak.models.base import MembershipSource
from django_pyoidc_keycloak.signals import role_assignment_changed
from django_pyoidc_keycloak.sync.roles import (
    apply_flag_roles,
    apply_role_names,
    parse_role_reference,
    role_clients,
    sweep_expired_role_assignments,
    sync_roles,
    sync_roles_by_ids,
    sync_user_roles,
)
from django_pyoidc_keycloak.sync.users import sync_user
from tests.conftest import kc_user

pytestmark = pytest.mark.django_db

CLIENT_UUID = "6a5a4f3e-0000-4000-8000-000000000001"


def kc_role(name, **extra):
    return {"id": str(uuid.uuid4()), "name": name, "composite": False, **extra}


@pytest.fixture
def client_stub(connection):
    stub = mock.Mock()
    stub.connection = connection
    stub.get_user_groups.return_value = []
    stub.get_user_realm_roles.return_value = []
    stub.get_user_client_roles.return_value = []
    stub.list_realm_roles.return_value = []
    stub.list_client_roles.return_value = []
    stub.find_client.return_value = {"id": CLIENT_UUID, "clientId": "django-app"}
    return stub


@pytest.fixture
def user(client_stub):
    return sync_user(kc_user(), client=client_stub)


def managed_role(name, client_id="django-app"):
    return KeycloakRole.objects.create(name=name, client_id=client_id, keycloak_id=uuid.uuid4())


# -- the catalogue ------------------------------------------------------


def test_mirrors_realm_and_client_roles(client_stub):
    client_stub.list_realm_roles.return_value = [kc_role("app-admin", description="realm-wide")]
    client_stub.list_client_roles.return_value = [kc_role("feature1-viewer"), kc_role("feature1-editor")]

    counts = sync_roles(client=client_stub)

    assert counts == {"created": 3, "updated": 0, "deleted": 0}
    assert KeycloakRole.objects.get(name="app-admin").client_id == ""
    assert KeycloakRole.objects.get(name="feature1-viewer").client_id == "django-app"
    client_stub.find_client.assert_called_once_with("django-app")
    client_stub.list_client_roles.assert_called_once_with(CLIENT_UUID)


def test_only_the_oidc_client_is_mirrored_by_default(connection):
    assert role_clients() == ["django-app"]


def test_role_clients_can_be_extended(settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "ROLE_CLIENTS": ["django-app", "reports-api"]}

    assert role_clients() == ["django-app", "reports-api"]


def test_a_missing_client_is_skipped_with_a_warning(client_stub, caplog):
    client_stub.find_client.return_value = None

    counts = sync_roles(client=client_stub)

    assert counts["created"] == 0
    assert "no such client" in caplog.text


def test_a_role_removed_in_keycloak_is_pruned(client_stub):
    client_stub.list_client_roles.return_value = [kc_role("gone")]
    sync_roles(client=client_stub)

    client_stub.list_client_roles.return_value = []
    sync_roles(client=client_stub)

    assert KeycloakRole.objects.count() == 0


def test_locally_created_roles_are_never_pruned(client_stub):
    KeycloakRole.objects.create(name="local", client_id="django-app")

    sync_roles(client=client_stub)

    assert KeycloakRole.objects.filter(name="local").exists()


# -- assignments --------------------------------------------------------


def test_assignments_follow_keycloak(client_stub, user):
    managed_role("feature1-viewer")
    managed_role("app-admin", client_id="")
    client_stub.get_user_client_roles.return_value = [{"name": "feature1-viewer"}]
    client_stub.get_user_realm_roles.return_value = [{"name": "app-admin"}]

    sync_user_roles(user, client=client_stub)

    assert set(user.roles.values_list("name", flat=True)) == {"feature1-viewer", "app-admin"}
    assert user.role_assignments.filter(source=MembershipSource.KEYCLOAK).count() == 2

    client_stub.get_user_client_roles.return_value = []
    sync_user_roles(user, client=client_stub)

    assert list(user.roles.values_list("name", flat=True)) == ["app-admin"]


def test_a_manual_override_survives_synchronisation(client_stub, user):
    role = managed_role("feature1-editor")
    RoleAssignment.objects.create(user=user, role=role, source=MembershipSource.MANUAL)

    apply_role_names(user, {"django-app": []})

    assert user.role_assignments.get().source == MembershipSource.MANUAL


def test_an_unmanaged_role_cannot_be_granted_through_names(user):
    """A role created in the admin was never granted by Keycloak, however the claim is shaped."""
    KeycloakRole.objects.create(name="superpowers", client_id="django-app")

    apply_role_names(user, {"django-app": ["superpowers"]})

    assert user.role_assignments.count() == 0


def test_a_realm_role_and_a_client_role_of_the_same_name_are_distinct(user):
    realm = managed_role("viewer", client_id="")
    managed_role("viewer")

    apply_role_names(user, {"": ["viewer"]})

    assert user.role_assignments.get().role == realm


def test_assignment_changes_are_signalled(user):
    managed_role("feature1-viewer")
    seen = []
    role_assignment_changed.connect(lambda **kw: seen.append((kw["action"], kw["role"].name)), weak=False)

    apply_role_names(user, {"django-app": ["feature1-viewer"]})
    apply_role_names(user, {"django-app": []})

    assert seen == [("added", "feature1-viewer"), ("removed", "feature1-viewer")]


def test_active_roles_and_has_role_ignore_expired_overrides(user):
    current = managed_role("feature1-viewer")
    expired = managed_role("feature1-editor")
    RoleAssignment.objects.create(user=user, role=current, source=MembershipSource.MANUAL)
    RoleAssignment.objects.create(
        user=user,
        role=expired,
        source=MembershipSource.MANUAL,
        expires_at=timezone.now() - timezone.timedelta(minutes=1),
    )

    assert list(user.active_roles()) == [current]
    assert user.has_role("feature1-viewer", "django-app") is True
    assert user.has_role("feature1-editor", "django-app") is False
    assert user.has_role("feature1-viewer") is False  # that is a client role, not a realm role


def test_expired_manual_assignments_are_swept(user):
    role = managed_role("feature1-viewer")
    RoleAssignment.objects.create(
        user=user,
        role=role,
        source=MembershipSource.MANUAL,
        expires_at=timezone.now() - timezone.timedelta(minutes=1),
    )

    assert sweep_expired_role_assignments() == 1
    assert user.role_assignments.count() == 0


# -- staff and superuser flags ------------------------------------------


def test_role_references(connection):
    assert parse_role_reference("app-staff") == ("django-app", "app-staff")
    assert parse_role_reference("realm:app-staff") == ("", "app-staff")
    assert parse_role_reference("reports-api:reader") == ("reports-api", "reader")


def test_the_default_flags_come_from_client_roles(user):
    changed = apply_flag_roles(user, {"": [], "django-app": ["app-staff", "app-superuser"]})

    assert changed == ["is_staff", "is_superuser"]
    assert user.is_staff is True
    assert user.is_superuser is True

    assert apply_flag_roles(user, {"": ["app-staff"], "django-app": []}) == ["is_staff", "is_superuser"]
    assert user.is_staff is False


def test_an_empty_list_leaves_that_flag_alone(user, settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "SUPERUSER_ROLES": []}
    user.is_superuser = True

    apply_flag_roles(user, {"django-app": []})

    assert user.is_superuser is True
    assert user.is_staff is False


# -- synchronising only the selected roles ------------------------------


def test_sync_roles_by_ids_refreshes_only_those_roles(client_stub):
    viewer = kc_role("feature1-viewer")
    editor = kc_role("feature1-editor")
    client_stub.list_client_roles.return_value = [viewer, editor]
    sync_roles(client=client_stub)
    client_stub.get_role_by_id.return_value = {**viewer, "description": "may read"}

    counts = sync_roles_by_ids([uuid.UUID(viewer["id"])], client=client_stub)

    assert counts == {"created": 0, "updated": 1, "deleted": 0, "errors": 0}
    assert KeycloakRole.objects.get(keycloak_id=viewer["id"]).description == "may read"
    assert KeycloakRole.objects.filter(keycloak_id=editor["id"]).exists()


def test_sync_roles_by_ids_keeps_the_client(client_stub):
    """/roles-by-id reports the container as a UUID; the local row already knows the clientId."""
    role = kc_role("feature1-viewer")
    client_stub.list_client_roles.return_value = [role]
    sync_roles(client=client_stub)
    client_stub.get_role_by_id.return_value = role

    sync_roles_by_ids([uuid.UUID(role["id"])], client=client_stub)

    assert KeycloakRole.objects.get(keycloak_id=role["id"]).client_id == "django-app"


def test_sync_roles_by_ids_removes_a_role_the_realm_has_dropped(client_stub):
    role = kc_role("gone")
    client_stub.list_realm_roles.return_value = [role]
    sync_roles(client=client_stub)
    client_stub.get_role_by_id.side_effect = KeycloakNotFound("404")

    counts = sync_roles_by_ids([uuid.UUID(role["id"])], client=client_stub)

    assert counts["deleted"] == 1
    assert not KeycloakRole.objects.filter(keycloak_id=role["id"]).exists()


def test_sync_roles_by_ids_skips_local_only_roles(client_stub):
    local = KeycloakRole.objects.create(name="local", client_id="")

    counts = sync_roles_by_ids([local.keycloak_id], client=client_stub)

    assert counts == {"created": 0, "updated": 0, "deleted": 0, "errors": 0}
    assert client_stub.get_role_by_id.call_count == 0
    assert KeycloakRole.objects.filter(pk=local.pk).exists()
