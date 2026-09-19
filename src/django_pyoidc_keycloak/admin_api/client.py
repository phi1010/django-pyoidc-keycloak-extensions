"""Keycloak Admin API client.

Authentication uses the ``client_credentials`` grant with django-pyoidc's own client, so a
project configures one Keycloak client and no separate service account.

The service-account access token is held **in memory on the client instance only**.  It is
never written to the Django cache: that backend is typically Redis or memcached, where a
token would sit in cleartext, outside the database, as a bearer credential for the whole
realm's user directory.
"""

from __future__ import annotations

import asyncio
import logging
import re
import threading
import time
from collections.abc import Iterator
from typing import Any

import httpx
from urllib3.util import parse_url

from django_pyoidc_keycloak.admin_api.exceptions import (
    KeycloakAPIError,
    KeycloakAuthenticationError,
    KeycloakNotFound,
    KeycloakPermissionError,
    KeycloakUserNotFound,
)
from django_pyoidc_keycloak.admin_api.provider import KeycloakConnection, get_connection
from django_pyoidc_keycloak.conf import app_settings
from django_pyoidc_keycloak.scrub import scrub_text

logger = logging.getLogger(__name__)

#: Refresh the service-account token this many seconds before it actually expires.
TOKEN_EXPIRY_LEEWAY = 30

#: Exactly ``/users/<uuid>`` -- the only path whose 404 means "this user was deleted".
_USER_RESOURCE = re.compile(r"/users/[0-9a-fA-F-]{36}")


class KeycloakAdminClient:
    """Synchronous Admin API client. Safe to share between threads."""

    def __init__(self, connection: KeycloakConnection | None = None) -> None:
        self.connection = connection or get_connection()
        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._lock = threading.Lock()
        self._alock: asyncio.Lock | None = None
        self._client: httpx.Client | None = None

    # -- representation -------------------------------------------------
    # The token must never leak through a repr, a pickled object or a traceback.

    def __repr__(self) -> str:
        return f"<KeycloakAdminClient realm={self.connection.realm!r} client_id={self.connection.client_id!r}>"

    __str__ = __repr__

    def __getstate__(self) -> dict[str, Any]:
        state = self.__dict__.copy()
        state["_token"] = None
        state["_token_expires_at"] = 0.0
        state["_lock"] = None
        state["_alock"] = None
        state["_client"] = None
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._lock = threading.Lock()

    # -- plumbing -------------------------------------------------------

    @property
    def http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=app_settings.REQUEST_TIMEOUT)
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> KeycloakAdminClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- authentication -------------------------------------------------

    def _token_is_fresh(self) -> bool:
        return self._token is not None and time.monotonic() < self._token_expires_at - TOKEN_EXPIRY_LEEWAY

    def get_access_token(self) -> str:
        """Return a valid service-account access token, fetching one if needed."""
        if self._token_is_fresh():
            return self._token  # type: ignore[return-value]
        with self._lock:
            # Another thread may have refreshed while we waited for the lock.
            if self._token_is_fresh():
                return self._token  # type: ignore[return-value]
            self._fetch_token()
            return self._token  # type: ignore[return-value]

    def _fetch_token(self) -> None:
        logger.debug(
            "Fetching a service-account token for client %r on realm %r",
            self.connection.client_id,
            self.connection.realm,
        )
        response = self.http.post(
            self.connection.token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": self.connection.client_id,
                "client_secret": self.connection.client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if response.status_code == 401:
            msg = "Keycloak rejected the client credentials for the Admin API."
            raise KeycloakAuthenticationError(msg)
        if response.status_code >= 400:
            msg = f"Could not obtain a service-account token ({response.status_code}): {scrub_text(response.text)}"
            raise KeycloakAPIError(msg, status_code=response.status_code)
        payload = response.json()
        token = payload.get("access_token")
        if not token:
            msg = "Keycloak returned no access_token for the client_credentials grant."
            raise KeycloakAuthenticationError(msg)
        self._token = token
        self._token_expires_at = time.monotonic() + float(payload.get("expires_in", 60))
        # The lifetime, never the token.
        logger.debug("Service-account token obtained; it expires in %ss", payload.get("expires_in", 60))

    # -- requests -------------------------------------------------------

    def _url_for(self, path: str) -> str:
        """Join a realm-relative Admin API path onto this realm's admin base.

        Every request carries the service-account bearer token, which is a credential for the
        whole realm's user directory, so the resulting URL must be proven to stay inside
        ``/admin/realms/<realm>``.  Paths are built by interpolating ids that arrive from
        Keycloak responses and from the local database, so this is not merely a matter of
        caller discipline.

        The check is made on the *parsed and normalised* URL rather than on the path string:
        ``..`` segments are resolved during parsing, and it is the resolved form that decides
        where the request actually goes.  ``/users/../../../master`` reads as a path under
        ``/users``, but resolves to ``/admin/master`` -- a different realm.
        """
        # Only the path portion decides this: a URL-valued query parameter is legitimate.
        probe = path.split("?", 1)[0].split("#", 1)[0]
        if "://" in probe or probe.startswith("//"):
            msg = f"Refusing an absolute Admin API URL: {path!r}. Pass a path relative to the realm."
            raise ValueError(msg)

        # Exactly one separator, whatever the two halves bring with them. The leading slash
        # matters before parsing: without it, parse_url reads "users/count" as a *host*.
        base = parse_url(self.connection.admin_base.rstrip("/"))
        url = parse_url(f"{base}/{path.lstrip('/')}")

        if (url.scheme, url.host, url.port) != (base.scheme, base.host, base.port):
            msg = f"Refusing an Admin API path that redirects the request to another host: {path!r}."
            raise ValueError(msg)
        base_path = base.path or "/"
        if url.path != base_path and not (url.path or "/").startswith(f"{base_path}/"):
            msg = f"Refusing an Admin API path that climbs out of the realm: {path!r} resolves to {url.path!r}."
            raise ValueError(msg)
        return str(url)

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Perform an Admin API request, retrying transient failures."""
        url = self._url_for(path)
        # Compare and report on the normalised form, so a path that only differs in its
        # leading slash still counts as the user resource below.
        path = f"/{path.lstrip('/')}"
        attempts = max(1, int(app_settings.MAX_RETRIES))
        last_error: Exception | None = None

        for attempt in range(attempts):
            headers = {"Authorization": f"Bearer {self.get_access_token()}", **kwargs.pop("headers", {})}
            try:
                response = self.http.request(method, url, headers=headers, **kwargs)
            except httpx.HTTPError as exc:
                # The class alone: an httpx message can echo back what was sent.
                logger.debug(
                    "%s %s failed on attempt %d/%d with %s; retrying",
                    method,
                    url,
                    attempt + 1,
                    attempts,
                    type(exc).__name__,
                )
                last_error = exc
                self._sleep_for_attempt(attempt)
                continue

            logger.debug("%s %s -> %d (attempt %d/%d)", method, url, response.status_code, attempt + 1, attempts)

            if response.status_code == 401:
                # The token expired earlier than advertised; drop it and try once more.
                logger.debug("The service-account token was rejected; discarding it and retrying")
                self._token = None
                if attempt + 1 < attempts:
                    continue
                msg = "Keycloak kept rejecting the service-account token."
                raise KeycloakAuthenticationError(msg)
            if response.status_code == 403:
                msg = (
                    f"The service account lacks permission for {method} {path}. Check the "
                    f"realm-management roles (view-users, query-users, query-groups, view-events, view-realm)."
                )
                raise KeycloakPermissionError(msg)
            if response.status_code == 404:
                # Only a 404 on a specific user means that user is gone. Every other 404 is a
                # configuration or gateway problem, and must not reach the deletion path.
                msg = f"Not found in Keycloak: {path}"
                if _USER_RESOURCE.fullmatch(path):
                    raise KeycloakUserNotFound(msg)
                raise KeycloakNotFound(msg)
            if response.status_code == 429 or response.status_code >= 500:
                logger.debug("Keycloak returned %d; backing off before retrying", response.status_code)
                last_error = KeycloakAPIError(
                    f"Keycloak returned {response.status_code} for {method} {path}",
                    status_code=response.status_code,
                )
                self._sleep_for_attempt(attempt)
                continue
            if response.status_code >= 400:
                msg = f"Keycloak returned {response.status_code} for {method} {path}: {scrub_text(response.text)}"
                raise KeycloakAPIError(msg, status_code=response.status_code)
            return response

        assert last_error is not None
        raise KeycloakAPIError(f"Keycloak request failed after {attempts} attempts: {last_error}")

    @staticmethod
    def _sleep_for_attempt(attempt: int) -> None:
        time.sleep(min(2**attempt * 0.5, 8.0))

    def get_json(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs).json()

    # -- users ----------------------------------------------------------

    def get_user(self, keycloak_id: str) -> dict[str, Any]:
        """Fetch one user. Raises KeycloakUserNotFound when it is gone."""
        return self.get_json(f"/users/{keycloak_id}")

    def count_users(self) -> int:
        return int(self.get_json("/users/count"))

    def iter_users(self, page_size: int | None = None) -> Iterator[dict[str, Any]]:
        """Yield every user in the realm, paging as it goes."""
        size = page_size or int(app_settings.USER_PAGE_SIZE)
        first = 0
        while True:
            page = self.get_json("/users", params={"first": first, "max": size})
            if not page:
                return
            yield from page
            if len(page) < size:
                return
            first += size

    def get_user_groups(self, keycloak_id: str) -> list[dict[str, Any]]:
        return list(self.get_json(f"/users/{keycloak_id}/groups"))

    def get_user_realm_roles(self, keycloak_id: str) -> list[dict[str, Any]]:
        """Effective realm roles, with composites expanded -- what a token would carry."""
        return list(self.get_json(f"/users/{keycloak_id}/role-mappings/realm/composite"))

    def get_user_client_roles(self, keycloak_id: str, client_uuid: str) -> list[dict[str, Any]]:
        """Effective roles on one client. ``client_uuid`` is Keycloak's id, not the clientId."""
        return list(self.get_json(f"/users/{keycloak_id}/role-mappings/clients/{client_uuid}/composite"))

    # -- roles and clients ----------------------------------------------

    def list_realm_roles(self) -> list[dict[str, Any]]:
        return list(self.get_json("/roles", params={"briefRepresentation": False}))

    def get_role_by_id(self, role_id: str) -> dict[str, Any]:
        """One role by its UUID, realm or client alike. Raises KeycloakNotFound when gone.

        ``/roles-by-id`` is the only endpoint that finds a role without already knowing which
        container it belongs to.
        """
        return self.get_json(f"/roles-by-id/{role_id}")

    def find_client(self, client_id: str) -> dict[str, Any] | None:
        """The client representation for a ``clientId``, or None. Needs ``view-clients``."""
        matches = list(self.get_json("/clients", params={"clientId": client_id}))
        for match in matches:
            if match.get("clientId") == client_id:
                return match
        return None

    def list_client_roles(self, client_uuid: str) -> list[dict[str, Any]]:
        return list(self.get_json(f"/clients/{client_uuid}/roles", params={"briefRepresentation": False}))

    # -- groups ---------------------------------------------------------

    def list_groups(self) -> list[dict[str, Any]]:
        """Return the realm's top-level groups.

        Modern Keycloak does not inline the hierarchy: it returns ``subGroups: []`` plus a
        ``subGroupCount``, and serves children from ``/groups/{id}/children``.  Use
        :meth:`get_group_children` to walk down.
        """
        return list(self.get_json("/groups", params={"briefRepresentation": False}))

    def get_group_children(self, group_id: str) -> list[dict[str, Any]]:
        """Direct children of a group. Empty on Keycloak versions without the endpoint."""
        try:
            return list(self.get_json(f"/groups/{group_id}/children", params={"briefRepresentation": False}))
        except KeycloakNotFound:
            # Older servers have no /children endpoint; they inline subGroups instead.
            return []

    def get_group(self, group_id: str) -> dict[str, Any]:
        return self.get_json(f"/groups/{group_id}")

    def get_group_members(self, group_id: str) -> list[dict[str, Any]]:
        return list(self.get_json(f"/groups/{group_id}/members"))

    # -- events ---------------------------------------------------------

    def get_admin_events(self, *, date_from: str | None = None, first: int = 0, maximum: int = 100) -> list[dict]:
        params: dict[str, Any] = {"first": first, "max": maximum}
        if date_from:
            params["dateFrom"] = date_from
        return list(self.get_json("/admin-events", params=params))

    def get_user_events(
        self,
        *,
        date_from: str | None = None,
        types: list[str] | None = None,
        first: int = 0,
        maximum: int = 100,
    ) -> list[dict]:
        params: dict[str, Any] = {"first": first, "max": maximum}
        if date_from:
            params["dateFrom"] = date_from
        if types:
            params["type"] = types
        return list(self.get_json("/events", params=params))


_default_client: KeycloakAdminClient | None = None
_default_client_lock = threading.Lock()


def get_admin_client() -> KeycloakAdminClient:
    """Return the process-wide client, creating it on first use."""
    global _default_client
    if _default_client is None:
        with _default_client_lock:
            if _default_client is None:
                _default_client = KeycloakAdminClient()
    return _default_client


def reset_admin_client() -> None:
    """Drop the cached client. Used by tests and after a settings change."""
    global _default_client
    with _default_client_lock:
        if _default_client is not None:
            _default_client.close()
        _default_client = None
