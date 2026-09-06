"""System checks and the admin surface."""

from __future__ import annotations

import pytest
from django.contrib import admin
from django.contrib.auth.models import Group as DjangoGroup
from django.test import RequestFactory

from django_pyoidc_keycloak.checks import (
    check_authentication_backends,
    check_encryption_key,
    check_token_exchange,
    check_user_model,
)
from django_pyoidc_keycloak.models import GroupMembership, KeycloakGroup, KeycloakUser, SyncRun
from django_pyoidc_keycloak.models.base import MembershipSource

pytestmark = pytest.mark.django_db


# -- checks -------------------------------------------------------------


def test_model_backend_is_rejected(settings):
    settings.AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]

    ids = [problem.id for problem in check_authentication_backends(None)]

    assert "keycloak.E001" in ids


def test_an_empty_backend_list_is_rejected(settings):
    settings.AUTHENTICATION_BACKENDS = []

    ids = [problem.id for problem in check_authentication_backends(None)]

    assert "keycloak.E002" in ids


def test_several_backends_need_an_explicit_choice(settings):
    settings.AUTHENTICATION_BACKENDS = ["tests.testproject.backend.StubPolicyBackend", "a.B"]
    settings.KEYCLOAK = {**settings.KEYCLOAK, "AUTH_BACKEND": None}

    ids = [problem.id for problem in check_authentication_backends(None)]

    assert "keycloak.E003" in ids


def test_a_backend_that_is_not_configured_is_rejected(settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "AUTH_BACKEND": "not.Configured"}

    ids = [problem.id for problem in check_authentication_backends(None)]

    assert "keycloak.E004" in ids


def test_the_default_configuration_passes():
    assert check_authentication_backends(None) == []


def test_token_storage_requires_a_salt_key(settings):
    settings.SALT_KEY = ""

    ids = [problem.id for problem in check_encryption_key(None)]

    assert "keycloak.E005" in ids


def test_no_salt_key_is_fine_when_tokens_are_not_stored(settings):
    settings.SALT_KEY = ""
    settings.KEYCLOAK = {**settings.KEYCLOAK, "STORE_TOKENS": False}

    assert check_encryption_key(None) == []


def test_the_user_model_check_passes_for_ours():
    assert check_user_model(None) == []


def test_token_exchange_needs_a_confidential_client(settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "TOKEN_EXCHANGE_ENABLED": True}
    settings.DJANGO_PYOIDC = {
        "sso": {**settings.DJANGO_PYOIDC["sso"], "client_secret": ""},
    }

    ids = [problem.id for problem in check_token_exchange(None)]

    assert ids  # either "no secret" or "cannot build the connection"


# -- admin --------------------------------------------------------------


def test_native_django_groups_are_gone_from_the_admin():
    assert DjangoGroup not in admin.site._registry


def test_the_keycloak_models_are_registered():
    assert KeycloakUser in admin.site._registry
    assert KeycloakGroup in admin.site._registry
    assert SyncRun in admin.site._registry


def test_token_sets_are_not_exposed_in_the_admin():
    """They hold secret material; only presence and expiry are shown on the user page."""
    from django_pyoidc_keycloak.models import OIDCTokenSet

    assert OIDCTokenSet not in admin.site._registry


def test_keycloak_owned_fields_are_read_only():
    user_admin = admin.site._registry[KeycloakUser]
    managed = KeycloakUser.objects.create_user(username="alice", keycloak_id="11111111-1111-1111-1111-111111111111")
    request = RequestFactory().get("/")

    readonly = user_admin.get_readonly_fields(request, managed)

    assert "username" in readonly
    assert "email" in readonly


def test_local_accounts_stay_editable():
    user_admin = admin.site._registry[KeycloakUser]
    local = KeycloakUser.objects.create_user(username="root")
    request = RequestFactory().get("/")

    readonly = user_admin.get_readonly_fields(request, local)

    assert "username" not in readonly


def test_the_token_indicator_shows_no_token_material():
    user_admin = admin.site._registry[KeycloakUser]
    user = KeycloakUser.objects.create_user(username="alice")

    assert "No tokens" in str(user_admin.token_status(user))


def test_sync_runs_cannot_be_edited():
    run_admin = admin.site._registry[SyncRun]
    request = RequestFactory().get("/")

    assert run_admin.has_add_permission(request) is False
    assert run_admin.has_change_permission(request) is False


def test_a_membership_added_by_hand_becomes_a_manual_override():
    """Otherwise the next synchronisation would silently revoke it."""
    membership_admin = admin.site._registry[GroupMembership]
    user = KeycloakUser.objects.create_user(username="alice")
    group = KeycloakGroup.objects.create(name="staff", path="/staff")
    request = RequestFactory().get("/")
    request.user = user
    membership = GroupMembership(user=user, group=group)

    membership_admin.save_model(request, membership, None, change=False)

    membership.refresh_from_db()
    assert membership.source == MembershipSource.MANUAL
    assert membership.created_by == user


def test_the_user_admin_offers_the_sync_actions():
    user_admin = admin.site._registry[KeycloakUser]

    assert "action_sync_selected" in user_admin.actions
    assert "action_sync_all" in user_admin.actions


# -- the admin actually renders -----------------------------------------


@pytest.fixture
def admin_browser(client):
    superuser = KeycloakUser.objects.create_superuser(username="root", password="pw")
    client.force_login(superuser)
    return client


def test_the_user_changelist_renders(admin_browser):
    KeycloakUser.objects.create_user(username="alice", keycloak_id="11111111-1111-1111-1111-111111111111")

    response = admin_browser.get("/admin/keycloak/keycloakuser/")

    assert response.status_code == 200
    assert b"alice" in response.content


def test_the_user_change_page_renders_for_a_managed_user(admin_browser):
    user = KeycloakUser.objects.create_user(username="alice", keycloak_id="11111111-1111-1111-1111-111111111111")

    response = admin_browser.get(f"/admin/keycloak/keycloakuser/{user.pk}/change/")

    assert response.status_code == 200


def test_the_group_and_membership_pages_render(admin_browser):
    KeycloakGroup.objects.create(name="staff", path="/staff")

    assert admin_browser.get("/admin/keycloak/keycloakgroup/").status_code == 200
    assert admin_browser.get("/admin/keycloak/groupmembership/").status_code == 200


def test_the_sync_run_page_renders(admin_browser):
    SyncRun.objects.create(kind="reconcile", realm="demo", status="success")

    assert admin_browser.get("/admin/keycloak/syncrun/").status_code == 200


def test_the_admin_index_has_no_native_groups(admin_browser):
    response = admin_browser.get("/admin/")

    assert response.status_code == 200
    assert b"/admin/auth/group/" not in response.content


def test_sync_now_reports_that_a_local_account_has_nothing_to_sync(admin_browser):
    local = KeycloakUser.objects.create_user(username="local-only")

    response = admin_browser.get(f"/admin/keycloak/keycloakuser/{local.pk}/sync/", follow=True)

    assert response.status_code == 200
    assert b"local-only account" in response.content
