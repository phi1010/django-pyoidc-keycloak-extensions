"""A stand-in for the project's own policy backend (Open Policy Agent in production).

It exists to prove the delegation contract: nothing is read from the database, and the
library never answers a permission question itself.  Note what is absent: no ``get_user``.
Resolving a session to a user is KeycloakSessionBackend's job, not a policy engine's.
"""

from __future__ import annotations

from typing import Any

from django_pyoidc_keycloak.backends import KeycloakSessionBackend


class StubPolicyBackend:
    """Records what it was asked, and answers from an in-memory policy."""

    #: perm -> set of usernames, filled in by tests.
    policy: dict[str, set[str]] = {}
    #: Every (method, username, argument) triple this backend was asked about.
    calls: list[tuple[str, str, Any]] = []

    def authenticate(self, request: Any, **credentials: Any) -> None:
        # Logging in happens through OIDC, never through this backend.
        return None

    def has_perm(self, user_obj: Any, perm: str, obj: Any = None) -> bool:
        type(self).calls.append(("has_perm", getattr(user_obj, "username", ""), perm))
        return getattr(user_obj, "username", None) in type(self).policy.get(perm, set())

    def has_module_perms(self, user_obj: Any, app_label: str) -> bool:
        type(self).calls.append(("has_module_perms", getattr(user_obj, "username", ""), app_label))
        return any(
            perm.startswith(f"{app_label}.") and getattr(user_obj, "username", None) in users
            for perm, users in type(self).policy.items()
        )

    def get_all_permissions(self, user_obj: Any, obj: Any = None) -> set[str]:
        username = getattr(user_obj, "username", None)
        return {perm for perm, users in type(self).policy.items() if username in users}

    @classmethod
    def reset(cls) -> None:
        cls.policy = {}
        cls.calls = []


class SubclassedSessionBackend(KeycloakSessionBackend):
    """Proves the session backend is discovered by type, not by dotted path."""
