"""The django-pyoidc hooks, including the two-phase token handoff."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation
from django.test import RequestFactory
from django_pyoidc.models import OIDCSession

from django_pyoidc_keycloak.hooks import get_user, session_logout, user_login, user_logout
from django_pyoidc_keycloak.models import KeycloakGroup, OIDCTokenSet
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


def test_the_backend_is_stamped_so_auth_login_works():
    """With more than one backend configured, auth.login() raises without this."""
    user = get_user(_Client(), tokens_for())

    assert user.backend == "tests.testproject.backend.StubPolicyBackend"


def test_a_username_collision_at_login_is_resolved():
    get_user_model().objects.create_user(username="alice")

    user = get_user(_Client(), tokens_for())

    assert user.username == "alice-2"


def test_group_membership_comes_from_the_claim_without_an_api_call():
    KeycloakGroup.objects.create(name="staff", path="/staff")

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

    stub = type("S", (), {"get_user_groups": lambda *a, **k: [], "get_user_realm_roles": lambda *a, **k: []})()
    user = sync_user({"id": SUB, "username": "alice", "attributes": {"department": ["ops"]}}, client=stub)

    get_user(_Client(), tokens_for())

    user.refresh_from_db()
    assert user.keycloak_attributes == {"department": ["ops"]}
