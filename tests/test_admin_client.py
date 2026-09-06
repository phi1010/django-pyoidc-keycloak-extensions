"""The Admin API client: credentials, retries, and where the token is *not* kept."""

from __future__ import annotations

import pickle

import httpx
import pytest
import respx
from django.core.cache import cache

from django_pyoidc_keycloak.admin_api.client import KeycloakAdminClient
from django_pyoidc_keycloak.admin_api.exceptions import (
    KeycloakAuthenticationError,
    KeycloakNotFound,
    KeycloakPermissionError,
    KeycloakUserNotFound,
)
from django_pyoidc_keycloak.admin_api.provider import get_connection

TOKEN_URL = "https://sso.example.org/realms/demo/protocol/openid-connect/token"
ADMIN_BASE = "https://sso.example.org/admin/realms/demo"


@pytest.fixture
def client(connection):
    return KeycloakAdminClient(connection)


def mock_token(mock, value="header.payload.signature", expires_in=60):
    return mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": value, "expires_in": expires_in})
    )


@respx.mock
def test_uses_the_django_pyoidc_client_credentials(client):
    route = mock_token(respx)
    respx.get(f"{ADMIN_BASE}/users/1").mock(return_value=httpx.Response(200, json={"id": "1"}))

    client.get_user("1")

    sent = dict(pair.split("=") for pair in route.calls[0].request.content.decode().split("&"))
    assert sent["grant_type"] == "client_credentials"
    assert sent["client_id"] == "django-app"
    assert sent["client_secret"] == "s3cr3t"


@respx.mock
def test_the_service_account_token_never_reaches_the_cache(client):
    """A cache backend is shared, plaintext storage -- not a place for a bearer credential."""
    mock_token(respx, value="header.super-secret.signature")
    respx.get(f"{ADMIN_BASE}/users/1").mock(return_value=httpx.Response(200, json={"id": "1"}))

    client.get_user("1")

    assert cache.get("keycloak:admin-token") is None
    assert not any("secret" in str(cache.get(key) or "") for key in ("keycloak:admin-token", "admin_token", "token"))


@respx.mock
def test_the_token_is_reused_until_it_nearly_expires(client):
    route = mock_token(respx, expires_in=3600)
    respx.get(f"{ADMIN_BASE}/users/1").mock(return_value=httpx.Response(200, json={"id": "1"}))

    client.get_user("1")
    client.get_user("1")

    assert route.call_count == 1


@respx.mock
def test_a_short_lived_token_is_refetched(client):
    """expires_in below the leeway means every call needs a new token."""
    route = mock_token(respx, expires_in=5)
    respx.get(f"{ADMIN_BASE}/users/1").mock(return_value=httpx.Response(200, json={"id": "1"}))

    client.get_user("1")
    client.get_user("1")

    assert route.call_count == 2


@respx.mock
def test_repr_does_not_leak_the_token(client):
    mock_token(respx, value="header.super-secret.signature")
    client.get_access_token()

    assert "super-secret" not in repr(client)
    assert "s3cr3t" not in repr(client)


@respx.mock
def test_pickling_drops_the_token(client):
    mock_token(respx, value="header.super-secret.signature")
    client.get_access_token()

    revived = pickle.loads(pickle.dumps(client))

    assert "super-secret" not in str(pickle.dumps(client))
    assert revived._token is None


@respx.mock
def test_a_404_on_a_user_means_that_user_is_gone(client):
    mock_token(respx)
    user_id = "11111111-1111-1111-1111-111111111111"
    respx.get(f"{ADMIN_BASE}/users/{user_id}").mock(return_value=httpx.Response(404))

    with pytest.raises(KeycloakUserNotFound):
        client.get_user(user_id)


@respx.mock
def test_a_404_elsewhere_is_not_a_missing_user(client):
    """A mistyped path or a gateway 404 must never reach the deletion path."""
    mock_token(respx)
    respx.get(f"{ADMIN_BASE}/groups/abc/children").mock(return_value=httpx.Response(404))

    with pytest.raises(KeycloakNotFound):
        client.request("GET", "/groups/abc/children")

    # It is not the subclass that drives deletion.
    try:
        client.request("GET", "/groups/abc/children")
    except KeycloakNotFound as exc:
        assert not isinstance(exc, KeycloakUserNotFound)


@respx.mock
def test_a_404_on_a_non_uuid_user_path_is_not_a_missing_user(client):
    mock_token(respx)
    respx.get(f"{ADMIN_BASE}/users/count").mock(return_value=httpx.Response(404))

    with pytest.raises(KeycloakNotFound):
        client.count_users()


@respx.mock
def test_a_403_names_the_missing_roles(client):
    mock_token(respx)
    respx.get(f"{ADMIN_BASE}/users/1").mock(return_value=httpx.Response(403))

    with pytest.raises(KeycloakPermissionError, match="view-users"):
        client.get_user("1")


@respx.mock
def test_rejected_credentials_are_reported_clearly(client):
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(401))

    with pytest.raises(KeycloakAuthenticationError):
        client.get_access_token()


@respx.mock
def test_an_expired_token_is_refetched_once(client):
    respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "old", "expires_in": 3600}),
            httpx.Response(200, json={"access_token": "new", "expires_in": 3600}),
        ]
    )
    respx.get(f"{ADMIN_BASE}/users/1").mock(side_effect=[httpx.Response(401), httpx.Response(200, json={"id": "1"})])

    assert client.get_user("1") == {"id": "1"}


@respx.mock
def test_server_errors_are_retried(client):
    mock_token(respx)
    route = respx.get(f"{ADMIN_BASE}/users/1").mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json={"id": "1"})]
    )

    assert client.get_user("1") == {"id": "1"}
    assert route.call_count == 2


@respx.mock
def test_iter_users_pages_until_the_realm_runs_out(client, settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "USER_PAGE_SIZE": 2}
    mock_token(respx)
    respx.get(f"{ADMIN_BASE}/users").mock(
        side_effect=[
            httpx.Response(200, json=[{"id": "1"}, {"id": "2"}]),
            httpx.Response(200, json=[{"id": "3"}]),
        ]
    )

    assert [user["id"] for user in client.iter_users()] == ["1", "2", "3"]


def test_the_connection_comes_from_django_pyoidc_settings():
    connection = get_connection()

    assert connection.server_url == "https://sso.example.org"
    assert connection.realm == "demo"
    assert connection.client_id == "django-app"
    assert connection.token_endpoint == TOKEN_URL


def test_the_connection_repr_hides_the_secret():
    assert "s3cr3t" not in repr(get_connection())
