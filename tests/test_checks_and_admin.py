"""System checks and the admin surface."""

from __future__ import annotations

import pytest
from django.contrib import admin
from django.contrib.auth.models import Group as DjangoGroup
from django.test import RequestFactory

from django_pyoidc_keycloak.admin import KeycloakUserAdmin
from django_pyoidc_keycloak.checks import (
    check_authentication_backends,
    check_cache_backend,
    check_encryption_key,
    check_model_base,
    check_role_references,
    check_token_exchange,
    check_user_model,
)
from django_pyoidc_keycloak.models import (
    GroupMembership,
    KeycloakGroup,
    KeycloakRole,
    KeycloakUser,
    RoleAssignment,
    SyncRun,
)
from django_pyoidc_keycloak.models.base import MembershipSource
from tests.testproject.backend import StubPolicyBackend

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


def test_a_missing_session_backend_is_rejected(settings):
    """Without it every request is silently anonymous, so this must be an error."""
    settings.AUTHENTICATION_BACKENDS = ["tests.testproject.backend.StubPolicyBackend"]

    ids = [problem.id for problem in check_authentication_backends(None)]

    assert "keycloak.E004" in ids


def test_a_subclassed_session_backend_satisfies_the_check(settings):
    settings.AUTHENTICATION_BACKENDS = ["tests.testproject.backend.SubclassedSessionBackend"]

    ids = [problem.id for problem in check_authentication_backends(None)]

    assert "keycloak.E004" not in ids


def test_the_retired_auth_backend_setting_is_flagged(settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "AUTH_BACKEND": "myproject.authz.OPABackend"}

    ids = [problem.id for problem in check_authentication_backends(None)]

    assert "keycloak.W004" in ids


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


def test_the_cache_backend_must_be_django_redis(settings):
    """Finding 3's follow-on: the refresh mutex releases through a token-checked Lua
    script, which only django-redis's lock provides."""
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

    ids = [problem.id for problem in check_cache_backend(None)]

    assert "keycloak.E008" in ids


def test_a_non_default_cache_backend_is_not_the_concern(settings):
    """Only the cache the refresh path actually uses is checked."""
    settings.CACHES = {
        "default": {"BACKEND": "django_redis.cache.RedisCache", "LOCATION": "redis://127.0.0.1:6379"},
        "other": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
    }

    assert check_cache_backend(None) == []


def test_no_cache_check_when_tokens_are_not_stored(settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "STORE_TOKENS": False}
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

    assert check_cache_backend(None) == []


def test_the_default_model_base_passes():
    assert check_model_base(None) == []


def test_a_model_base_with_extra_fields_needs_swapped_models(monkeypatch):
    """The library's migrations cannot know about columns a custom base adds."""
    from django.db import models

    from django_pyoidc_keycloak.models import base

    class SoftDeleteBase(models.Model):
        deleted_at = models.DateTimeField(null=True)

        class Meta:
            abstract = True
            app_label = "tests"

    monkeypatch.setattr(base, "ModelBase", SoftDeleteBase)

    ids = [problem.id for problem in check_model_base(None)]

    assert "keycloak.E009" in ids


def test_the_default_role_references_pass():
    assert check_role_references(None) == []


def test_a_role_reference_to_an_unmirrored_client_is_rejected(settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "STAFF_ROLES": ["reports-api:admin"]}

    ids = [problem.id for problem in check_role_references(None)]

    assert "keycloak.E010" in ids


def test_a_realm_role_reference_is_always_fine(settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "STAFF_ROLES": ["realm:app-staff"]}

    assert check_role_references(None) == []


# -- admin --------------------------------------------------------------


def test_native_django_groups_are_gone_from_the_admin():
    assert DjangoGroup not in admin.site._registry


def test_the_keycloak_models_are_registered():
    assert KeycloakUser in admin.site._registry
    assert KeycloakGroup in admin.site._registry
    assert KeycloakRole in admin.site._registry
    assert RoleAssignment in admin.site._registry
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


def test_an_assignment_added_by_hand_becomes_a_manual_override():
    assignment_admin = admin.site._registry[RoleAssignment]
    user = KeycloakUser.objects.create_user(username="alice")
    role = KeycloakRole.objects.create(name="feature1-viewer", client_id="django-app")
    request = RequestFactory().get("/")
    request.user = user
    assignment = RoleAssignment(user=user, role=role)

    assignment_admin.save_model(request, assignment, None, change=False)

    assignment.refresh_from_db()
    assert assignment.source == MembershipSource.MANUAL
    assert assignment.created_by == user


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


def test_the_role_and_assignment_pages_render(admin_browser):
    role = KeycloakRole.objects.create(name="feature1-viewer", client_id="django-app")
    RoleAssignment.objects.create(user=KeycloakUser.objects.get(username="root"), role=role)

    assert admin_browser.get("/admin/keycloak/keycloakrole/").status_code == 200
    assert admin_browser.get(f"/admin/keycloak/keycloakrole/{role.pk}/change/").status_code == 200
    assert admin_browser.get("/admin/keycloak/roleassignment/").status_code == 200


def test_the_sync_run_page_renders(admin_browser):
    SyncRun.objects.create(kind="reconcile", realm="demo", status="success")

    assert admin_browser.get("/admin/keycloak/syncrun/").status_code == 200


def test_the_admin_index_has_no_native_groups(admin_browser):
    response = admin_browser.get("/admin/")

    assert response.status_code == 200
    assert b"/admin/auth/group/" not in response.content


def test_sync_now_reports_that_a_local_account_has_nothing_to_sync(admin_browser):
    local = KeycloakUser.objects.create_user(username="local-only")

    response = admin_browser.post(f"/admin/keycloak/keycloakuser/{local.pk}/sync/", follow=True)

    assert response.status_code == 200
    assert b"local-only account" in response.content


def test_sync_now_refuses_a_get(admin_browser):
    """It changes state -- on a Keycloak 404 it deletes or anonymises the account -- and
    Django does not CSRF-protect GET, so an <img src=...> would have been enough."""
    user = KeycloakUser.objects.create_user(username="alice")

    response = admin_browser.get(f"/admin/keycloak/keycloakuser/{user.pk}/sync/")

    assert response.status_code == 405


# -- the sync verb ------------------------------------------------------
# Synchronising is its own permission, so a policy can grant it without `change` and grant
# `change` without it. Every test here goes through the real policy backend, which proves the
# codename the mixin builds is the one a policy would have to name.

SYNC = "keycloak.sync_keycloakuser"
CHANGE = "keycloak.change_keycloakuser"
VIEW = "keycloak.view_keycloakuser"


@pytest.fixture
def staff():
    return KeycloakUser.objects.create_user(username="staff", password="pw", is_staff=True)


def test_the_codename_is_derived_from_the_model():
    """A project that swaps the user model gets the verb on its own model, not on ours."""
    user_admin = admin.site._registry[KeycloakUser]
    request = RequestFactory().get("/")
    request.user = KeycloakUser(username="nobody", is_superuser=False, is_active=True)

    StubPolicyBackend.policy = {SYNC: {"nobody"}}

    assert user_admin.has_sync_permission(request) is True
    assert ("has_perm", "nobody", SYNC) in StubPolicyBackend.calls


def test_sync_now_is_allowed_by_the_sync_verb_alone(client, staff):
    """No `change` permission anywhere: sync stands on its own."""
    StubPolicyBackend.policy = {SYNC: {"staff"}}
    client.force_login(staff)
    local = KeycloakUser.objects.create_user(username="local-only")

    response = client.post(f"/admin/keycloak/keycloakuser/{local.pk}/sync/")

    assert response.status_code == 302


def test_sync_now_is_refused_to_someone_who_may_only_change(client, staff):
    """The other direction: editing a row does not entitle you to re-pull it from Keycloak."""
    StubPolicyBackend.policy = {CHANGE: {"staff"}, VIEW: {"staff"}}
    client.force_login(staff)
    user = KeycloakUser.objects.create_user(username="alice")

    response = client.post(f"/admin/keycloak/keycloakuser/{user.pk}/sync/")

    assert response.status_code == 403


def test_sync_now_is_refused_to_staff_with_no_permissions(client, staff):
    """Staff alone is not enough: admin_view only proves the caller can open the admin."""
    client.force_login(staff)
    user = KeycloakUser.objects.create_user(username="alice")

    response = client.post(f"/admin/keycloak/keycloakuser/{user.pk}/sync/")

    assert response.status_code == 403


def test_the_sync_actions_are_withheld_without_the_verb(staff):
    user_admin = admin.site._registry[KeycloakUser]
    request = RequestFactory().get("/")
    request.user = staff
    StubPolicyBackend.policy = {CHANGE: {"staff"}, VIEW: {"staff"}}

    actions = user_admin.get_actions(request)

    assert "action_sync_selected" not in actions
    assert "action_sync_all" not in actions


def test_the_sync_actions_are_offered_with_the_verb(staff):
    user_admin = admin.site._registry[KeycloakUser]
    request = RequestFactory().get("/")
    request.user = staff
    StubPolicyBackend.policy = {SYNC: {"staff"}, VIEW: {"staff"}}

    actions = user_admin.get_actions(request)

    assert "action_sync_selected" in actions
    assert "action_sync_all" in actions


def test_a_forged_sync_action_does_not_run_without_the_verb(client, staff, monkeypatch):
    """Django drops an unpermitted action from the form rather than raising, so assert on
    the effect: the synchronisation must not happen."""
    calls = []
    monkeypatch.setattr(KeycloakUserAdmin, "_run_sync", lambda self, *a, **kw: calls.append(a))
    StubPolicyBackend.policy = {CHANGE: {"staff"}, VIEW: {"staff"}}
    client.force_login(staff)
    user = KeycloakUser.objects.create_user(username="alice")

    client.post(
        "/admin/keycloak/keycloakuser/",
        {"action": "action_sync_selected", "_selected_action": [str(user.pk)]},
    )

    assert calls == []


def test_the_sync_button_is_hidden_without_the_verb(client, staff):
    """Offering a button that can only 403 is worse than not offering it."""
    StubPolicyBackend.policy = {CHANGE: {"staff"}, VIEW: {"staff"}}
    client.force_login(staff)
    user = KeycloakUser.objects.create_user(username="alice")

    response = client.get(f"/admin/keycloak/keycloakuser/{user.pk}/change/")

    assert response.status_code == 200
    assert b"Sync now from Keycloak" not in response.content


def test_the_sync_button_is_shown_with_the_verb(client, staff):
    StubPolicyBackend.policy = {SYNC: {"staff"}, CHANGE: {"staff"}, VIEW: {"staff"}}
    client.force_login(staff)
    user = KeycloakUser.objects.create_user(username="alice")

    response = client.get(f"/admin/keycloak/keycloakuser/{user.pk}/change/")

    assert response.status_code == 200
    assert b"Sync now from Keycloak" in response.content
