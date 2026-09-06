"""Shared fixtures."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from django.core.cache import cache

from django_pyoidc_keycloak.admin_api.client import reset_admin_client
from django_pyoidc_keycloak.admin_api.provider import KeycloakConnection
from tests.testproject.backend import StubPolicyBackend


@pytest.fixture(autouse=True)
def _clean_state():
    cache.clear()
    StubPolicyBackend.reset()
    reset_admin_client()
    yield
    cache.clear()
    reset_admin_client()


@pytest.fixture
def connection() -> KeycloakConnection:
    return KeycloakConnection(
        server_url="https://sso.example.org",
        realm="demo",
        client_id="django-app",
        client_secret="s3cr3t",
        op_name="sso",
    )


def kc_user(**overrides: Any) -> dict[str, Any]:
    """A Keycloak user representation with sensible defaults."""
    representation = {
        "id": str(uuid.uuid4()),
        "username": "alice",
        "email": "alice@example.org",
        "firstName": "Alice",
        "lastName": "Jones",
        "enabled": True,
        "emailVerified": True,
        "createdTimestamp": 1700000000000,
        "attributes": {},
    }
    representation.update(overrides)
    return representation


@pytest.fixture
def make_kc_user():
    return kc_user
