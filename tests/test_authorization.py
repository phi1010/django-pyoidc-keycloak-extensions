"""Authorization is delegated, and nothing about permissions is stored locally."""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.utils import timezone

from django_pyoidc_keycloak.models import GroupMembership, KeycloakGroup
from django_pyoidc_keycloak.models.base import MembershipSource
from tests.testproject.backend import StubPolicyBackend

pytestmark = pytest.mark.django_db


@pytest.fixture
def user():
    return get_user_model().objects.create_user(username="alice")


def test_has_perm_is_answered_by_the_backend(user):
    StubPolicyBackend.policy = {"shop.view_order": {"alice"}}

    assert user.has_perm("shop.view_order") is True
    assert user.has_perm("shop.delete_order") is False
    assert ("has_perm", "alice", "shop.view_order") in StubPolicyBackend.calls


def test_superuser_short_circuits_without_asking_the_backend(user):
    user.is_superuser = True

    assert user.has_perm("anything.at_all") is True
    assert StubPolicyBackend.calls == []


def test_an_inactive_superuser_gets_no_shortcut(user):
    user.is_superuser = True
    user.is_active = False

    assert user.has_perm("anything.at_all") is False
    assert StubPolicyBackend.calls  # it had to ask


def test_has_module_perms_delegates(user):
    StubPolicyBackend.policy = {"shop.view_order": {"alice"}}

    assert user.has_module_perms("shop") is True
    assert user.has_module_perms("billing") is False


def test_has_perms_requires_all_of_them(user):
    StubPolicyBackend.policy = {"a.one": {"alice"}, "a.two": {"alice"}}

    assert user.has_perms(["a.one", "a.two"]) is True
    assert user.has_perms(["a.one", "a.three"]) is False


def test_has_perms_rejects_a_bare_string(user):
    with pytest.raises(ValueError, match="iterable of permissions"):
        user.has_perms("a.one")


def test_get_all_permissions_comes_from_the_backend(user):
    StubPolicyBackend.policy = {"a.one": {"alice"}, "a.two": {"bob"}}

    assert user.get_all_permissions() == {"a.one"}


def test_no_permission_rows_are_created_by_migrations():
    """The post_migrate hook that populates auth_permission is disconnected."""
    assert Permission.objects.count() == 0


def test_the_models_have_no_permission_fields():
    user_fields = {field.name for field in get_user_model()._meta.get_fields()}
    group_fields = {field.name for field in KeycloakGroup._meta.get_fields()}

    assert "user_permissions" not in user_fields
    assert "permissions" not in group_fields


def test_the_user_model_has_no_link_to_django_groups():
    """`groups` points at the Keycloak group model, not auth.Group."""
    related = get_user_model()._meta.get_field("groups").related_model

    assert related is KeycloakGroup


def test_active_groups_excludes_expired_memberships(user):
    live = KeycloakGroup.objects.create(name="live", path="/live")
    stale = KeycloakGroup.objects.create(name="stale", path="/stale")
    GroupMembership.objects.create(user=user, group=live, source=MembershipSource.KEYCLOAK)
    GroupMembership.objects.create(
        user=user,
        group=stale,
        source=MembershipSource.MANUAL,
        expires_at=timezone.now() - timezone.timedelta(hours=1),
    )

    assert list(user.active_groups()) == [live]


def test_a_future_expiry_still_counts(user):
    group = KeycloakGroup.objects.create(name="temp", path="/temp")
    GroupMembership.objects.create(
        user=user,
        group=group,
        source=MembershipSource.MANUAL,
        expires_at=timezone.now() + timezone.timedelta(hours=1),
    )

    assert list(user.active_groups()) == [group]
