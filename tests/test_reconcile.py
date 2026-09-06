"""Full reconciliation: the backstop that event polling cannot be."""

from __future__ import annotations

from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from django_pyoidc_keycloak.admin_api.exceptions import KeycloakUserNotFound
from django_pyoidc_keycloak.models import GroupMembership, KeycloakGroup, SyncRun
from django_pyoidc_keycloak.models.base import MembershipSource
from django_pyoidc_keycloak.sync.reconcile import full_reconcile
from django_pyoidc_keycloak.sync.users import sync_user
from tests.conftest import kc_user
from tests.testapp.models import ProtectedDocument

pytestmark = pytest.mark.django_db


@pytest.fixture
def client_stub(connection):
    stub = mock.Mock()
    stub.connection = connection
    stub.get_user_groups.return_value = []
    stub.get_user_realm_roles.return_value = []
    stub.list_groups.return_value = []
    stub.iter_users.return_value = iter([])
    return stub


def test_users_who_never_logged_in_are_skipped_by_default(client_stub):
    client_stub.iter_users.return_value = iter([kc_user()])

    stats = full_reconcile(client=client_stub)

    assert get_user_model().objects.count() == 0
    assert stats["skipped"] == 1


def test_import_all_creates_them(client_stub):
    client_stub.iter_users.return_value = iter([kc_user()])

    stats = full_reconcile(client=client_stub, import_all=True)

    assert get_user_model().objects.count() == 1
    assert stats["created"] == 1


def test_a_user_missing_from_keycloak_is_deleted(client_stub):
    user = sync_user(kc_user(), client=client_stub)
    client_stub.iter_users.return_value = iter([])
    client_stub.get_user.side_effect = KeycloakUserNotFound("gone")

    stats = full_reconcile(client=client_stub)

    assert not get_user_model().objects.filter(pk=user.pk).exists()
    assert stats["deleted"] == 1


def test_the_listing_is_confirmed_before_deleting(client_stub):
    """A user missing from a paged listing may just have raced with a change."""
    user = sync_user(kc_user(), client=client_stub)
    client_stub.iter_users.return_value = iter([])
    client_stub.get_user.return_value = kc_user(id=str(user.keycloak_id))

    stats = full_reconcile(client=client_stub)

    assert get_user_model().objects.filter(pk=user.pk).exists()
    assert stats["deleted"] == 0


def test_unmanaged_users_are_never_touched(client_stub):
    """This is what lets a bootstrap superuser survive a reconciliation."""
    local = get_user_model().objects.create_superuser(username="root")
    client_stub.iter_users.return_value = iter([])
    client_stub.get_user.side_effect = KeycloakUserNotFound("gone")

    full_reconcile(client=client_stub)

    local.refresh_from_db()
    assert local.is_superuser is True
    assert local.is_anonymized is False


def test_a_tombstone_is_not_re_examined(client_stub):
    """Otherwise every pass would 404 again and could hard-delete the tombstone."""
    user = sync_user(kc_user(), client=client_stub)
    ProtectedDocument.objects.create(owner=user, title="an invoice")
    client_stub.iter_users.return_value = iter([])
    client_stub.get_user.side_effect = KeycloakUserNotFound("gone")
    full_reconcile(client=client_stub)

    client_stub.get_user.reset_mock()
    client_stub.iter_users.return_value = iter([])
    stats = full_reconcile(client=client_stub)

    assert stats["deleted"] == 0
    assert stats["anonymized"] == 0
    client_stub.get_user.assert_not_called()
    assert get_user_model().objects.filter(pk=user.pk).exists()


def test_dry_run_changes_nothing(client_stub):
    client_stub.iter_users.return_value = iter([kc_user()])

    stats = full_reconcile(client=client_stub, import_all=True, dry_run=True)

    assert stats["created"] == 1
    assert get_user_model().objects.count() == 0


def test_expired_manual_memberships_are_swept(client_stub):
    user = sync_user(kc_user(), client=client_stub)
    group = KeycloakGroup.objects.create(name="temp", path="/temp")
    keeper = KeycloakGroup.objects.create(name="perm", path="/perm")
    GroupMembership.objects.create(
        user=user,
        group=group,
        source=MembershipSource.MANUAL,
        expires_at=timezone.now() - timezone.timedelta(minutes=1),
    )
    GroupMembership.objects.create(user=user, group=keeper, source=MembershipSource.MANUAL)
    client_stub.iter_users.return_value = iter([])
    client_stub.get_user.return_value = kc_user(id=str(user.keycloak_id))

    full_reconcile(client=client_stub)

    assert list(user.memberships.values_list("group__path", flat=True)) == ["/perm"]


def test_the_run_is_recorded_for_audit(client_stub):
    client_stub.iter_users.return_value = iter([kc_user()])

    full_reconcile(client=client_stub, import_all=True)

    run = SyncRun.objects.get()
    assert run.kind == "reconcile"
    assert run.status == "success"
    assert run.created == 1
    assert run.finished_at is not None


def test_the_service_account_user_is_imported_like_any_other(client_stub):
    """Reusing the login client materialises service-account-<client_id> in the realm."""
    representation = kc_user(
        username="service-account-django-app",
        email=None,
        serviceAccountClientId="django-app",
    )
    client_stub.iter_users.return_value = iter([representation])

    full_reconcile(client=client_stub, import_all=True)

    user = get_user_model().objects.get()
    assert user.username == "service-account-django-app"
    assert user.is_staff is False
    assert user.is_superuser is False
