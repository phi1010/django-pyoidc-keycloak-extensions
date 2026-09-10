"""The session-resolution backend.

Django's session authentication does not store a user, only its primary key and the dotted
path of the backend that logged it in (``_auth_user_backend``).  On every later request
``django.contrib.auth.get_user()`` loads that backend and calls ``get_user(user_id)`` on it
to turn the key back into a model instance.

That is a *user-handling* job, not an authorization one, so this library provides it rather
than pushing it onto the project's policy backend: a policy engine should only ever be asked
``has_perm``.  Permission delegation does not depend on which backend the session records --
``KeycloakAuthorizationMixin`` asks every backend in ``AUTHENTICATION_BACKENDS`` in turn --
so the two roles are cleanly separable.

Add it alongside your own authorization backend::

    AUTHENTICATION_BACKENDS = [
        "django_pyoidc_keycloak.backends.KeycloakSessionBackend",
        "myproject.authz.OPABackend",
    ]
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string


class KeycloakSessionBackend:
    """Resolves the logged-in user from the session, and answers nothing else.

    Deliberately not a ``ModelBackend`` subclass: this must not be able to answer
    ``has_perm`` from ``auth_permission`` rows.  It stores and reads no permission data.
    """

    def authenticate(self, request: Any, **credentials: Any) -> None:
        """Never authenticates: logging in happens through OIDC, not through a backend."""
        return None

    def get_user(self, user_id: Any) -> Any:
        """Load the user by primary key, or ``None`` if it may no longer hold a session."""
        user_model = get_user_model()
        try:
            # is_active covers anonymised tombstones too, since anonymize() clears the flag:
            # a user disabled in Keycloak loses their session on the next request.
            return user_model.objects.get(pk=user_id, is_active=True)
        except user_model.DoesNotExist:
            return None


def resolve_session_backend_path() -> str:
    """The dotted path to record on ``user.backend`` before ``auth.login()``.

    Discovered from ``AUTHENTICATION_BACKENDS`` rather than hardcoded, so that a project may
    subclass the backend, and so that the recorded string is byte-for-byte one of the
    configured entries -- ``auth.get_user()`` compares it against that list and silently
    falls back to ``AnonymousUser`` when it does not match.
    """
    for path in getattr(settings, "AUTHENTICATION_BACKENDS", []):
        # issubclass, not isinstance: no need to instantiate a project's own backends here.
        if issubclass(import_string(path), KeycloakSessionBackend):
            return str(path)
    msg = (
        "No KeycloakSessionBackend in AUTHENTICATION_BACKENDS, so the logged-in user could "
        "not be resolved on later requests. Add "
        "'django_pyoidc_keycloak.backends.KeycloakSessionBackend' to AUTHENTICATION_BACKENDS."
    )
    raise ImproperlyConfigured(msg)
