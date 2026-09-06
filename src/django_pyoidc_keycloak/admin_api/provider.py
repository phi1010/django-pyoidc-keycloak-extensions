"""Bridge to django-pyoidc's provider configuration.

The library deliberately does not ask for its own Keycloak credentials: the client that
users log in through is the same client used for Admin API calls and token exchange.  This
module extracts the base URI, realm and client credentials from django-pyoidc's settings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured

from django_pyoidc_keycloak.conf import app_settings

_REALM_RE = re.compile(r"/realms/(?P<realm>[^/]+)")


@dataclass(frozen=True)
class KeycloakConnection:
    """Everything needed to talk to a Keycloak realm."""

    server_url: str
    realm: str
    client_id: str
    client_secret: str
    op_name: str | None = None

    @property
    def token_endpoint(self) -> str:
        return f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/token"

    @property
    def admin_base(self) -> str:
        return f"{self.server_url}/admin/realms/{self.realm}"

    def __repr__(self) -> str:  # never render the secret
        return f"KeycloakConnection(server_url={self.server_url!r}, realm={self.realm!r}, client_id={self.client_id!r})"


def _resolve_op_name() -> str:
    configured = app_settings.get("OP_NAME")
    if configured:
        return str(configured)
    providers = getattr(django_settings, "DJANGO_PYOIDC", None) or {}
    if len(providers) == 1:
        return next(iter(providers))
    if not providers:
        msg = "DJANGO_PYOIDC is not configured; cannot derive Keycloak connection settings."
        raise ImproperlyConfigured(msg)
    msg = (
        "Several providers are configured in DJANGO_PYOIDC; set KEYCLOAK['OP_NAME'] to say "
        "which one this library should synchronise against."
    )
    raise ImproperlyConfigured(msg)


def _split_discovery_uri(uri: str) -> tuple[str, str]:
    """Turn ``https://sso/realms/demo`` into ``("https://sso", "demo")``."""
    match = _REALM_RE.search(uri)
    if not match:
        msg = f"Cannot extract a Keycloak realm from provider_discovery_uri {uri!r}."
        raise ImproperlyConfigured(msg)
    parsed = urlparse(uri)
    server_url = f"{parsed.scheme}://{parsed.netloc}"
    prefix = parsed.path[: match.start()].rstrip("/")
    if prefix:
        server_url = f"{server_url}{prefix}"
    return server_url, match.group("realm")


def get_connection() -> KeycloakConnection:
    """Build the connection, preferring explicit KEYCLOAK settings over django-pyoidc's."""
    op_name = None
    op_settings: dict[str, object] = {}
    try:
        op_name = _resolve_op_name()
        providers = getattr(django_settings, "DJANGO_PYOIDC", None) or {}
        op_settings = {k.lower(): v for k, v in providers.get(op_name, {}).items()}
    except ImproperlyConfigured:
        # Fine as long as everything is spelled out under KEYCLOAK.
        if not all(app_settings.get(name) for name in ("SERVER_URL", "REALM", "ADMIN_CLIENT_ID")):
            raise

    server_url = app_settings.get("SERVER_URL")
    realm = app_settings.get("REALM")
    if not (server_url and realm):
        base = op_settings.get("keycloak_base_uri")
        kc_realm = op_settings.get("keycloak_realm")
        if base and kc_realm:
            server_url = server_url or str(base).rstrip("/")
            realm = realm or str(kc_realm)
        else:
            discovery = op_settings.get("provider_discovery_uri")
            if not discovery:
                msg = (
                    "Cannot determine the Keycloak server URL and realm. Configure "
                    "keycloak_base_uri/keycloak_realm (or provider_discovery_uri) in DJANGO_PYOIDC, "
                    "or set KEYCLOAK['SERVER_URL'] and KEYCLOAK['REALM']."
                )
                raise ImproperlyConfigured(msg)
            derived_url, derived_realm = _split_discovery_uri(str(discovery))
            server_url = server_url or derived_url
            realm = realm or derived_realm

    client_id = app_settings.get("ADMIN_CLIENT_ID") or op_settings.get("client_id")
    client_secret = app_settings.get("ADMIN_CLIENT_SECRET") or op_settings.get("client_secret")
    if not client_id:
        msg = "No client_id available: set it in DJANGO_PYOIDC or as KEYCLOAK['ADMIN_CLIENT_ID']."
        raise ImproperlyConfigured(msg)
    if not client_secret:
        msg = (
            "No client_secret available. The Admin API needs a confidential client with service "
            "accounts enabled; set client_secret in DJANGO_PYOIDC or KEYCLOAK['ADMIN_CLIENT_SECRET']."
        )
        raise ImproperlyConfigured(msg)

    return KeycloakConnection(
        server_url=str(server_url).rstrip("/"),
        realm=str(realm),
        client_id=str(client_id),
        client_secret=str(client_secret),
        op_name=op_name,
    )
