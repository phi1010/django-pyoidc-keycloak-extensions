"""A stand-in for the project's own policy backend (Open Policy Agent in production).

It exists to prove the delegation contract: nothing is read from the database, and the
library never answers a permission question itself.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model


class StubPolicyBackend:
    """Records what it was asked, and answers from an in-memory policy."""

    #: perm -> set of usernames, filled in by tests.
    policy: dict[str, set[str]] = {}
    #: Every (method, username, argument) triple this backend was asked about.
    calls: list[tuple[str, str, Any]] = []

    def authenticate(self, request: Any, **credentials: Any) -> None:
        # Logging in happens through OIDC, never through this backend.
        return None

    def get_user(self, user_id: Any) -> Any:
        user_model = get_user_model()
        try:
            return user_model.objects.get(pk=user_id)
        except user_model.DoesNotExist:
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
