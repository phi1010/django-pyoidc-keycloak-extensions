"""The django-pyoidc hooks, including the two-phase token handoff."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation
from django.test import RequestFactory
from django_pyoidc.models import OIDCSession

from django_pyoidc_keycloak.hooks import get_user, session_logout, user_login, user_logout
from django_pyoidc_keycloak.models import KeycloakGroup, KeycloakRole, OIDCTokenSet
from django_pyoidc_keycloak.tokens.store import PENDING_ATTR

pytestmark = pytest.mark.django_db

JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.signature"
SUB = str(uuid.uuid4())


class _Token:
    def __init__(self):
        self.access_token = JWT
        self.refresh_token = "refresh-token"
        self.id_token_jwt = "id." + JWT
        self.token_expiration_time = int(datetime.now(tz=UTC).timestamp()) + 300
        self.scope = ["openid"]


class _Client:
    def __init__(self):
        self.consumer = type("C", (), {"grant": {"state": type("G", (), {"tokens": [_Token()]})()}})()


def tokens_for(sub=SUB, **claims):
    payload = {"sub": sub, "preferred_username": "alice", "email": "alice@example.org"}
    payload.update(claims)
    return {"access_token_jwt": JWT, "id_token_claims": payload, "info_token_claims": {"sub": sub}}


def test_resolves_the_user_by_sub_not_email():
    """Emails change and get reused; the sub does not."""
    user = get_user(_Client(), tokens_for())

    assert str(user.keycloak_id) == SUB
    assert user.username == "alice"


def test_a_changed_email_still_finds_the_same_user():
    first = get_user(_Client(), tokens_for())
    second = get_user(_Client(), tokens_for(email="new@example.org"))

    assert first.pk == second.pk
    assert get_user_model().objects.count() == 1
    assert second.email == "new@example.org"


def test_a_login_without_a_sub_is_refused():
    with pytest.raises(SuspiciousOperation, match="no 'sub' claim"):
        get_user(_Client(), {"id_token_claims": {"email": "alice@example.org"}})


def test_the_session_backend_is_stamped_so_auth_login_works():
    """auth.login() refuses to guess with several backends, and auth.get_user() only calls
    get_user() on the backend recorded here -- so it must be the session backend, never the
    project's policy backend."""
    user = get_user(_Client(), tokens_for())

    assert user.backend == "django_pyoidc_keycloak.backends.KeycloakSessionBackend"


def test_a_username_collision_at_login_is_resolved():
    get_user_model().objects.create_user(username="alice")

    user = get_user(_Client(), tokens_for())

    assert user.username == "alice-2"


def test_group_membership_comes_from_the_claim_without_an_api_call():
    KeycloakGroup.objects.create(name="staff", path="/staff", keycloak_id=uuid.uuid4())

    user = get_user(_Client(), tokens_for(groups=["/staff"]))

    assert user.memberships.get().group.path == "/staff"


def test_tokens_are_stashed_for_the_second_hook():
    """hook_get_user runs before the OIDCSession row exists, so it cannot store them yet."""
    user = get_user(_Client(), tokens_for())

    assert getattr(user, PENDING_ATTR).refresh_token == "refresh-token"
    assert OIDCTokenSet.objects.count() == 0


def test_user_login_writes_the_stashed_tokens():
    request = RequestFactory().get("/")
    request.session = type("S", (), {"session_key": "abc"})()
    user = get_user(_Client(), tokens_for())
    session = OIDCSession.objects.create(state="s", sub=SUB, cache_session_key="abc", session_state="ss")

    user_login(request, user)

    token_set = OIDCTokenSet.objects.get()
    assert token_set.session == session
    assert token_set.access_token == JWT
    assert token_set.id_token == "id." + JWT
    assert token_set.refresh_token == "refresh-token"


def test_a_login_without_a_session_row_does_not_explode():
    request = RequestFactory().get("/")
    request.session = type("S", (), {"session_key": "nothing-matches"})()
    user = get_user(_Client(), tokens_for())

    user_login(request, user)

    assert OIDCTokenSet.objects.count() == 0


def test_logging_out_purges_the_tokens():
    request = RequestFactory().get("/")
    request.session = type("S", (), {"session_key": "abc"})()
    user = get_user(_Client(), tokens_for())
    OIDCSession.objects.create(state="s", sub=SUB, cache_session_key="abc", session_state="ss")
    user_login(request, user)

    user_logout(request, {})

    assert OIDCTokenSet.objects.count() == 0


def test_backchannel_logout_purges_the_tokens():
    request = RequestFactory().get("/")
    request.session = type("S", (), {"session_key": "abc"})()
    user = get_user(_Client(), tokens_for())
    session = OIDCSession.objects.create(state="s", sub=SUB, cache_session_key="abc", session_state="ss")
    user_login(request, user)

    session_logout(session)

    assert OIDCTokenSet.objects.count() == 0


def test_token_storage_can_be_switched_off(settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "STORE_TOKENS": False}

    user = get_user(_Client(), tokens_for())

    assert not hasattr(user, PENDING_ATTR)


def test_a_login_does_not_wipe_attributes_fetched_by_the_admin_api():
    """Claims carry no `attributes` key; absence is not emptiness."""
    from django_pyoidc_keycloak.sync.users import sync_user

    stub = type(
        "S",
        (),
        {
            "get_user_groups": lambda *a, **k: [],
            "get_user_realm_roles": lambda *a, **k: [],
            "get_user_client_roles": lambda *a, **k: [],
            "find_client": lambda *a, **k: None,
        },
    )()
    user = sync_user({"id": SUB, "username": "alice", "attributes": {"department": ["ops"]}}, client=stub)

    get_user(_Client(), tokens_for())

    user.refresh_from_db()
    assert user.keycloak_attributes == {"department": ["ops"]}


def test_a_groups_claim_cannot_reach_a_local_only_group():
    """Otherwise a mapper over a user-editable attribute would be an escalation path."""
    KeycloakGroup.objects.create(name="admins", path="/admins")

    user = get_user(_Client(), tokens_for(groups=["/admins"]))

    assert user.memberships.count() == 0


# -- roles and the staff flags at login -----------------------------------


def managed_role(name, client_id="django-app"):
    return KeycloakRole.objects.create(name=name, client_id=client_id, keycloak_id=uuid.uuid4())


def test_roles_come_from_the_claims_without_an_api_call():
    managed_role("feature1-viewer")
    managed_role("app-admin", client_id="")

    user = get_user(
        _Client(),
        tokens_for(
            realm_access={"roles": ["app-admin", "offline_access"]},
            resource_access={"django-app": {"roles": ["feature1-viewer"]}, "account": {"roles": ["view-profile"]}},
        ),
    )

    assert set(user.roles.values_list("name", flat=True)) == {"feature1-viewer", "app-admin"}


def test_the_staff_flags_are_set_at_login_from_the_client_roles():
    user = get_user(_Client(), tokens_for(resource_access={"django-app": {"roles": ["app-staff"]}}))

    assert user.is_staff is True
    assert user.is_superuser is False
    assert user.authorization_synced_at is not None


def test_a_client_missing_from_resource_access_holds_no_roles():
    """Keycloak omits the client entirely when the user has no role on it."""
    managed_role("app-staff")
    user = get_user(_Client(), tokens_for(resource_access={"django-app": {"roles": ["app-staff"]}}))
    assert user.is_staff is True

    user = get_user(_Client(), tokens_for(resource_access={"account": {"roles": ["view-profile"]}}))

    assert user.is_staff is False
    assert user.roles.count() == 0


def test_a_realm_role_reference_reads_realm_access(settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "STAFF_ROLES": ["realm:app-staff"]}

    user = get_user(_Client(), tokens_for(realm_access={"roles": ["app-staff"]}))

    assert user.is_staff is True


def test_a_resource_access_claim_cannot_reach_a_local_only_role():
    KeycloakRole.objects.create(name="feature1-editor", client_id="django-app")

    user = get_user(_Client(), tokens_for(resource_access={"django-app": {"roles": ["feature1-editor"]}}))

    assert user.role_assignments.count() == 0


# -- reconciled data that is newer than the token ---------------------------


def _stamp(user, when):
    type(user).objects.filter(pk=user.pk).update(authorization_synced_at=when)


def test_a_token_older_than_the_last_reconcile_does_not_touch_authorization():
    staff = KeycloakGroup.objects.create(name="staff", path="/staff", keycloak_id=uuid.uuid4())
    issued = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
    user = get_user(_Client(), tokens_for(iat=int(issued.timestamp()), groups=["/staff"]))
    user.memberships.all().delete()
    _stamp(user, issued + timedelta(minutes=5))

    user = get_user(
        _Client(),
        tokens_for(
            iat=int(issued.timestamp()), groups=["/staff"], resource_access={"django-app": {"roles": ["app-staff"]}}
        ),
    )

    assert not user.memberships.filter(group=staff).exists()
    assert user.is_staff is False
    assert user.authorization_synced_at == issued + timedelta(minutes=5)


def test_a_token_newer_than_the_last_reconcile_is_applied():
    KeycloakGroup.objects.create(name="staff", path="/staff", keycloak_id=uuid.uuid4())
    issued = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
    user = get_user(_Client(), tokens_for())
    _stamp(user, issued - timedelta(minutes=5))

    user = get_user(_Client(), tokens_for(iat=int(issued.timestamp()), groups=["/staff"]))

    assert user.memberships.get().group.path == "/staff"
    assert user.authorization_synced_at == issued


def test_a_token_without_iat_is_applied_and_stamped_now():
    KeycloakGroup.objects.create(name="staff", path="/staff", keycloak_id=uuid.uuid4())
    user = get_user(_Client(), tokens_for())
    _stamp(user, datetime(2030, 1, 1, tzinfo=UTC))

    user = get_user(_Client(), tokens_for(groups=["/staff"]))

    assert user.memberships.count() == 1
