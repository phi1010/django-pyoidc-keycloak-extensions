"""A throwaway Keycloak, started under Podman.

testcontainers speaks the Docker API, so the fixture points it at Podman's socket rather
than shelling out.  Two Podman-specific details:

* Rootless Podman exposes its socket at ``/run/user/<uid>/podman/podman.sock``.  If it is
  not running, the fixture starts ``podman system service`` itself.
* Ryuk, testcontainers' reaper, needs privileged access to that socket which rootless Podman
  does not grant, so it is disabled and the fixture cleans up in its own teardown.

If Podman is not installed at all, the whole module is skipped -- the unit suite still runs.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import httpx
import pytest

KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.4"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "admin"
REALM = "testrealm"
CLIENT_ID = "django-app"
CLIENT_SECRET = "test-client-secret"
EXCHANGE_TARGET = "reports-api"

REALM_FILE = Path(__file__).parent / "realm-export.json"


def _podman_socket() -> str | None:
    """Find, or start, a Podman API socket testcontainers can talk to."""
    if not shutil.which("podman"):
        return None

    candidates = [
        f"/run/user/{os.getuid()}/podman/podman.sock",
        "/run/podman/podman.sock",
    ]
    for path in candidates:
        if Path(path).exists():
            return f"unix://{path}"

    target = candidates[0]
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    subprocess.Popen(  # noqa: S603 - fixed command, no user input
        ["podman", "system", "service", "--time=0", f"unix://{target}"],  # noqa: S607
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        if Path(target).exists():
            return f"unix://{target}"
        time.sleep(0.2)
    return None


@pytest.fixture(scope="session")
def podman_socket() -> str:
    socket = _podman_socket()
    if socket is None:
        pytest.skip("Podman is not available; skipping the Keycloak integration tests.")
    return socket


@pytest.fixture(scope="session")
def keycloak(podman_socket: str):
    """Start Keycloak, import the realm, and hand back its base URL."""
    from testcontainers.core.container import DockerContainer

    os.environ["DOCKER_HOST"] = podman_socket
    # Ryuk cannot reap under rootless Podman; teardown below does the cleanup.
    os.environ["TESTCONTAINERS_RYUK_DISABLED"] = "true"

    container = (
        DockerContainer(KEYCLOAK_IMAGE)
        .with_env("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
        .with_env("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .with_env("KC_HEALTH_ENABLED", "true")
        # Standard token exchange (token-exchange-standard:v2) is enabled by default from
        # Keycloak 26.2 onwards, so no KC_FEATURES flag is needed -- and passing the flag to
        # an older image fails at start-up with "unrecognized feature".
        .with_volume_mapping(str(REALM_FILE), "/opt/keycloak/data/import/realm.json", "z")
        .with_exposed_ports(8080)
        .with_command("start-dev --import-realm")
    )

    with container:
        # Readiness is polled over HTTP rather than by matching log lines, which are not a
        # stable interface and differ between Keycloak versions.
        base_url = f"http://{container.get_container_host_ip()}:{container.get_exposed_port(8080)}"
        _wait_until_ready(base_url, timeout=300)
        yield base_url


def _wait_until_ready(base_url: str, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"{base_url}/realms/{REALM}/.well-known/openid-configuration", timeout=2)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    msg = "Keycloak did not become ready in time."
    raise RuntimeError(msg)


@pytest.fixture
def keycloak_settings(keycloak: str, settings):
    """Point the library at the container, per test."""
    settings.DJANGO_PYOIDC = {
        "sso": {
            **settings.DJANGO_PYOIDC["sso"],
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "keycloak_base_uri": keycloak,
            "keycloak_realm": REALM,
        }
    }
    settings.KEYCLOAK = {
        **settings.KEYCLOAK,
        "SERVER_URL": keycloak,
        "REALM": REALM,
        # The integration suite exercises the enabled end of the exchange gate.
        "TOKEN_EXCHANGE_ENABLED": True,
    }

    from django_pyoidc_keycloak.admin_api.client import reset_admin_client

    reset_admin_client()
    yield settings
    reset_admin_client()


@pytest.fixture
def admin_client_real(keycloak_settings):
    from django_pyoidc_keycloak.admin_api.client import KeycloakAdminClient

    with KeycloakAdminClient() as client:
        yield client


class KeycloakAdminOps:
    """The few write operations the tests need, which the library itself does not do."""

    def __init__(self, client) -> None:
        self.client = client

    def create_user(self, username: str, **extra) -> str:
        payload = {"username": username, "enabled": True, **extra}
        response = self.client.request("POST", "/users", json=payload)
        return response.headers["Location"].rsplit("/", 1)[-1]

    def update_user(self, keycloak_id: str, **changes) -> None:
        current = self.client.get_user(keycloak_id)
        self.client.request("PUT", f"/users/{keycloak_id}", json={**current, **changes})

    def delete_user(self, keycloak_id: str) -> None:
        self.client.request("DELETE", f"/users/{keycloak_id}")

    def add_to_group(self, keycloak_id: str, group_id: str) -> None:
        self.client.request("PUT", f"/users/{keycloak_id}/groups/{group_id}")

    def remove_from_group(self, keycloak_id: str, group_id: str) -> None:
        self.client.request("DELETE", f"/users/{keycloak_id}/groups/{group_id}")

    def add_client_role(self, keycloak_id: str, role_name: str) -> None:
        client = self.client.find_client(CLIENT_ID)
        role = next(r for r in self.client.list_client_roles(client["id"]) if r["name"] == role_name)
        self.client.request(
            "POST",
            f"/users/{keycloak_id}/role-mappings/clients/{client['id']}",
            json=[{"id": role["id"], "name": role["name"]}],
        )

    def remove_client_role(self, keycloak_id: str, role_name: str) -> None:
        client = self.client.find_client(CLIENT_ID)
        role = next(r for r in self.client.list_client_roles(client["id"]) if r["name"] == role_name)
        self.client.request(
            "DELETE",
            f"/users/{keycloak_id}/role-mappings/clients/{client['id']}",
            json=[{"id": role["id"], "name": role["name"]}],
        )

    def group_id(self, path: str) -> str:
        for group in self.client.list_groups():
            found = self._find(group, path)
            if found:
                return found
        msg = f"No group at {path!r}"
        raise LookupError(msg)

    def _find(self, node: dict, path: str) -> str | None:
        if node.get("path") == path:
            return node["id"]
        # Current Keycloak serves children from a separate endpoint rather than inlining them.
        children = node.get("subGroups") or (
            self.client.get_group_children(node["id"]) if node.get("subGroupCount") else []
        )
        for child in children:
            found = self._find(child, path)
            if found:
                return found
        return None

    def password_grant(self, username: str, password: str) -> dict:
        response = httpx.post(
            self.client.connection.token_endpoint,
            data={
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "username": username,
                "password": password,
                "scope": "openid",
            },
        )
        response.raise_for_status()
        return response.json()


@pytest.fixture
def ops(admin_client_real) -> KeycloakAdminOps:
    return KeycloakAdminOps(admin_client_real)
