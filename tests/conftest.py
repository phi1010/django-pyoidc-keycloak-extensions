"""Shared fixtures.

The unit suite runs its cache against a throwaway Redis started with testcontainers. The
token-refresh mutex is django-redis's ``cache.client.lock()`` -- a redis-py ``Lock`` whose
release is a token-checked Lua script -- and no other cache backend offers that, so the
tests exercise the real thing (see SECURITY_REVIEW.md, finding 3).

The container is started at import time, before pytest-django configures Django, so that
``tests.testproject.settings`` can point ``CACHES`` at it. Like the Keycloak integration
tests this speaks the Podman socket; see ``tests/integration/conftest.py`` for the
rootless-Podman details. When Podman is not available the cache falls back to locmem and
every test marked ``redis`` is skipped instead of failing confusingly.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from django.core.cache import cache

from django_pyoidc_keycloak.admin_api.client import reset_admin_client
from django_pyoidc_keycloak.admin_api.provider import KeycloakConnection
from tests.testproject.backend import StubPolicyBackend


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


def _start_redis() -> Any | None:
    """A throwaway Redis container, or None when no container runtime is available."""
    socket_url = _podman_socket()
    if socket_url is None:
        return None

    os.environ["DOCKER_HOST"] = socket_url
    # Ryuk cannot reap under rootless Podman; atexit below does the cleanup.
    os.environ["TESTCONTAINERS_RYUK_DISABLED"] = "true"

    from testcontainers.community.redis import RedisContainer

    try:
        container = RedisContainer("docker.io/library/redis:7-alpine")
        container.start()
    except Exception:  # pragma: no cover - image pull or runtime failure
        return None
    return container


def _redis_url(container: Any) -> str | None:
    """The container's redis:// URL, once it accepts connections."""
    try:
        host, port = container.get_container_host_ip(), int(container.get_exposed_port(6379))
    except Exception:  # pragma: no cover - container died between start and read
        return None
    for _ in range(50):
        try:
            with socket.create_connection((host, port), timeout=1):
                return f"redis://{host}:{port}"
        except OSError:
            time.sleep(0.2)
    return None  # pragma: no cover - redis not answering in 10s


_container = _start_redis()
_redis_url = _redis_url(_container) if _container is not None else None

if _container is not None:
    import atexit

    atexit.register(lambda: _container.stop())  # pragma: no cover - process teardown

# pytest-django has already loaded tests.testproject.settings by the time this conftest is
# imported (it touches settings in pytest_load_initial_conftests), so patching the module
# would be silently ignored and the suite would hit the default redis://127.0.0.1:6379.
# Patch the live settings object instead; the cache handler reads CACHES lazily on first use.
from django.conf import settings as django_settings  # noqa: E402

if _redis_url:
    django_settings.CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": _redis_url,
        }
    }
else:
    django_settings.CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    }


def pytest_collection_modifyitems(config: pytest.Config, items: list) -> None:
    """Without a container runtime the real-lock tests cannot run; skip them loudly."""
    if _redis_url is not None:
        return
    skip = pytest.mark.skip(reason="Podman is not available; these tests need a real Redis lock.")
    for item in items:
        if "redis" in item.keywords:
            item.add_marker(skip)


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
