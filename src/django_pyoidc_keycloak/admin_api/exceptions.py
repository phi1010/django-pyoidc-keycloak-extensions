"""Typed errors for Keycloak Admin API access."""

from __future__ import annotations


class KeycloakError(Exception):
    """Base class for every error raised by this library's Keycloak client."""


class KeycloakConfigurationError(KeycloakError):
    """The Keycloak side is not set up as this library requires."""


class KeycloakAuthenticationError(KeycloakError):
    """The client credentials were rejected."""


class KeycloakPermissionError(KeycloakError):
    """The service account lacks a required realm-management role."""


class KeycloakUserNotFound(KeycloakError):  # noqa: N818 - reads better than ...NotFoundError
    """A user no longer exists in Keycloak. This is what drives deletion."""


class KeycloakAPIError(KeycloakError):
    """An unexpected Admin API response."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class TokensUnavailable(KeycloakError):  # noqa: N818 - reads better than TokensUnavailableError
    """No usable token could be produced for this user or session."""
