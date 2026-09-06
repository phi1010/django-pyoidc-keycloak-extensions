"""Regression tests for the findings in SECURITY_REVIEW.md.

Each test names the behaviour that was wrong, so a future change that reintroduces it fails
here rather than in production.
"""

from __future__ import annotations

import pickle
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django_pyoidc.models import OIDCSession

from django_pyoidc_keycloak.admin_api.exceptions import TokensUnavailable
from django_pyoidc_keycloak.admin_api.provider import get_connection
from django_pyoidc_keycloak.models import OIDCTokenSet
from django_pyoidc_keycloak.scrub import REDACTED, scrub, scrub_text
from django_pyoidc_keycloak.sync.usernames import MAX_LENGTH, derive_username
from django_pyoidc_keycloak.tokens.extract import RawTokens
from django_pyoidc_keycloak.tokens.refresh import get_valid_access_token
from django_pyoidc_keycloak.tokens.store import find_session, get_token_set, store_tokens

pytestmark = pytest.mark.django_db

TOKEN_URL = "https://sso.example.org/realms/demo/protocol/openid-connect/token"
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature"


def a_request(session_key: str | None):
    request = RequestFactory().get("/")
    request.session = type("S", (), {"session_key": session_key})()
    return request


# -- Finding 1: cross-user token leak via find_session --------------------


def test_a_request_without_a_session_key_matches_no_session():
    """It used to fall back to 'the most recent row', which belongs to whoever logged in last."""
    OIDCSession.objects.create(state="s", sub=str(uuid.uuid4()), cache_session_key="bob-key", session_state="ss")

    assert find_session(a_request(None)) is None


def test_a_login_cannot_attach_its_tokens_to_another_users_session():
    user_model = get_user_model()
    bob = user_model.objects.create_user(username="bob", keycloak_id=uuid.uuid4())
    alice = user_model.objects.create_user(username="alice", keycloak_id=uuid.uuid4())
    bobs_session = OIDCSession.objects.create(
        state="s", sub=str(bob.keycloak_id), cache_session_key="bob-key", session_state="ss"
    )
    store_tokens(session=bobs_session, user=bob, raw=RawTokens(access_token="bobs-token", refresh_token="bobs"))

    # Alice logs in, but her request carries no usable session key.
    session = find_session(a_request(None), alice)
    assert session is None
    assert store_tokens(session=session, user=alice, raw=RawTokens(access_token="alices-token")) is None

    # Bob's tokens are untouched, and he cannot be handed Alice's.
    assert OIDCTokenSet.objects.count() == 1
    assert get_token_set(bob).access_token == "bobs-token"
    assert get_token_set(alice) is None


def test_a_session_belonging_to_someone_else_is_not_matched():
    """Even with a matching session key, the Keycloak sub has to line up."""
    user_model = get_user_model()
    bob = user_model.objects.create_user(username="bob", keycloak_id=uuid.uuid4())
    alice = user_model.objects.create_user(username="alice", keycloak_id=uuid.uuid4())
    OIDCSession.objects.create(state="s", sub=str(bob.keycloak_id), cache_session_key="shared-key", session_state="ss")

    assert find_session(a_request("shared-key"), alice) is None
    assert find_session(a_request("shared-key"), bob) is not None


# -- Finding 4: inactive users ------------------------------------------


def test_disabling_a_user_in_keycloak_revokes_access_immediately():
    user = get_user_model().objects.create_user(username="alice")
    user.is_active = False

    assert user.has_perm("shop.view_order") is False
    assert user.has_module_perms("shop") is False


# -- Finding 5: username collisions -------------------------------------


def test_the_suffix_search_is_bounded():
    """A hostile or merely large collision set must not turn into a long scan."""
    user_model = get_user_model()
    user_model.objects.create_user(username="alice")
    for suffix in range(2, 51):
        user_model.objects.create_user(username=f"alice-{suffix}")

    result = derive_username({"preferred_username": "alice", "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"})

    assert result.startswith("alice-")
    assert result not in {f"alice-{n}" for n in range(2, 51)}
    assert len(result) <= MAX_LENGTH


def test_a_concurrent_claim_on_the_same_username_does_not_500(monkeypatch):
    """Two logins can pass the uniqueness check together; the loser picks again.

    Modelled by handing sync_user a stale derivation -- a name that was free when it was
    checked but is taken by the time the INSERT happens.
    """
    from django_pyoidc_keycloak.sync import usernames as usernames_module
    from django_pyoidc_keycloak.sync import users as users_module

    user_model = get_user_model()
    user_model.objects.create_user(username="alice")  # the winner of the race
    stub = type("S", (), {"get_user_groups": lambda *a, **k: [], "get_user_realm_roles": lambda *a, **k: []})()
    representation = {"id": str(uuid.uuid4()), "username": "alice"}

    real_derive = usernames_module.derive_username
    stale = {"used": False}

    def derive_once_stale(rep, *, exclude_pk=None):
        if not stale["used"]:
            stale["used"] = True
            return "alice"  # as if nobody held it when we looked
        return real_derive(rep, exclude_pk=exclude_pk)

    monkeypatch.setattr(users_module, "_username_strategy", lambda: derive_once_stale)

    user = users_module.sync_user(representation, client=stub)

    assert user.username == "alice-2"
    assert user_model.objects.filter(username="alice").count() == 1


# -- Finding 6: scrubbing coverage --------------------------------------


def test_opaque_tokens_are_redacted_too():
    """Keycloak can be configured to issue non-JWT access tokens."""
    opaque = "A" * 48

    assert opaque not in scrub_text(f"failed with token {opaque}")
    assert REDACTED in scrub_text(f"failed with token {opaque}")


def test_ordinary_words_and_identifiers_survive_scrubbing():
    text = "Syncing user alice in realm demo at /admin/realms/demo/users/11111111-1111-1111-1111-111111111111"

    assert scrub_text(text) == text


def test_more_secret_keys_are_recognised():
    result = scrub({"client_assertion": "x", "device_secret": "y", "session_state": "z", "realm": "demo"})

    assert result == {
        "client_assertion": REDACTED,
        "device_secret": REDACTED,
        "session_state": REDACTED,
        "realm": "demo",
    }


# -- Finding 7: pickled secrets -----------------------------------------


def test_pickling_the_connection_drops_the_client_secret():
    connection = get_connection()
    assert connection.client_secret == "s3cr3t"

    revived = pickle.loads(pickle.dumps(connection))

    assert b"s3cr3t" not in pickle.dumps(connection)
    assert revived.client_secret == ""
    assert revived.realm == "demo"


def test_pickling_the_admin_client_drops_the_secret_as_well():
    from django_pyoidc_keycloak.admin_api.client import KeycloakAdminClient

    client = KeycloakAdminClient()

    assert b"s3cr3t" not in pickle.dumps(client)


# -- Finding 8: null access tokens --------------------------------------


@respx.mock
def test_a_refresh_response_without_a_token_raises_rather_than_storing_null():
    user = get_user_model().objects.create_user(username="alice")
    session = OIDCSession.objects.create(state="s", sub="1", cache_session_key="k", session_state="ss")
    token_set = store_tokens(
        session=session,
        user=user,
        raw=RawTokens(
            access_token=JWT,
            refresh_token="refresh-token",
            access_token_expires_at=datetime.now(tz=UTC) - timedelta(seconds=1),
        ),
    )
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"expires_in": 300}))

    with pytest.raises(TokensUnavailable, match="no access_token"):
        get_valid_access_token(token_set)

    token_set.refresh_from_db()
    assert token_set.access_token == JWT  # the old one is still there, not overwritten with None
