"""Resolving a session to a user is the library's job, not the policy backend's.

Django's session stores only a primary key and the dotted path of the backend that logged
the user in; ``auth.get_user()`` calls ``get_user()`` on that backend to get the instance
back.  These tests pin that the library supplies it, so a project's authorization backend
only ever has to answer ``has_perm``.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import SESSION_KEY, get_user, get_user_model, login
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory

from django_pyoidc_keycloak.backends import KeycloakSessionBackend, resolve_session_backend_path
from django_pyoidc_keycloak.hooks import get_user as hook_get_user
from tests.testproject.backend import StubPolicyBackend

pytestmark = pytest.mark.django_db

SESSION_BACKEND_PATH = "django_pyoidc_keycloak.backends.KeycloakSessionBackend"


@pytest.fixture
def alice():
    return get_user_model().objects.create_user(username="alice")


def _request_with_session():
    request = RequestFactory().get("/")
    from django.contrib.sessions.middleware import SessionMiddleware

    SessionMiddleware(lambda r: None).process_request(request)
    return request


# -- get_user -----------------------------------------------------------


def test_the_user_is_resolved_by_primary_key(alice):
    """auth.login() stores the pk, so that -- not keycloak_id -- is the lookup key."""
    assert KeycloakSessionBackend().get_user(alice.pk) == alice


def test_an_unknown_key_resolves_to_nothing():
    assert KeycloakSessionBackend().get_user(99999) is None


def test_an_inactive_user_cannot_hold_a_session(alice):
    """Matches KeycloakAuthorizationMixin.has_perm: disabling in Keycloak revokes access."""
    alice.is_active = False
    alice.save()

    assert KeycloakSessionBackend().get_user(alice.pk) is None


def test_an_anonymised_tombstone_cannot_hold_a_session(alice):
    from django_pyoidc_keycloak.sync.users import anonymize

    anonymize(alice)

    assert KeycloakSessionBackend().get_user(alice.pk) is None


def test_the_backend_answers_no_permission_question():
    """It must not be a ModelBackend: that would read auth_permission rows."""
    backend = KeycloakSessionBackend()

    assert not hasattr(backend, "has_perm")
    assert not hasattr(backend, "get_all_permissions")
    assert backend.authenticate(None, username="alice", password="x") is None


# -- path discovery -----------------------------------------------------


def test_the_configured_path_is_discovered():
    assert resolve_session_backend_path() == SESSION_BACKEND_PATH


def test_a_subclass_is_discovered_under_its_own_path(settings):
    """A project may subclass it; the path recorded must be the one Django will compare."""
    settings.AUTHENTICATION_BACKENDS = ["tests.testproject.backend.SubclassedSessionBackend"]

    assert resolve_session_backend_path() == "tests.testproject.backend.SubclassedSessionBackend"


def test_a_missing_session_backend_is_a_configuration_error(settings):
    settings.AUTHENTICATION_BACKENDS = ["tests.testproject.backend.StubPolicyBackend"]

    with pytest.raises(ImproperlyConfigured, match="KeycloakSessionBackend"):
        resolve_session_backend_path()


# -- end to end ---------------------------------------------------------


def test_a_logged_in_user_survives_to_the_next_request(alice):
    """The test the original design lacked: log in, then resolve the user from the session.

    With the policy backend stamped instead, this returns AnonymousUser -- silently, because
    auth.get_user() swallows a backend that cannot resolve the key.
    """
    request = _request_with_session()
    alice.backend = resolve_session_backend_path()
    login(request, alice)

    assert request.session[SESSION_KEY] == str(alice.pk)

    later = _request_with_session()
    later.session = request.session

    assert get_user(later) == alice
    assert StubPolicyBackend.calls == [], "the policy backend must not be asked to resolve a user"


def test_a_user_deactivated_between_requests_becomes_anonymous(alice):
    request = _request_with_session()
    alice.backend = resolve_session_backend_path()
    login(request, alice)

    get_user_model().objects.filter(pk=alice.pk).update(is_active=False)

    later = _request_with_session()
    later.session = request.session

    assert isinstance(get_user(later), AnonymousUser)


def test_the_hook_stamps_a_backend_that_can_actually_resolve_the_user():
    """Ties hooks.get_user to the session machinery, not merely to a string."""
    from tests.test_hooks import _Client, tokens_for

    user = hook_get_user(_Client(), tokens_for())
    request = _request_with_session()
    login(request, user)

    later = _request_with_session()
    later.session = request.session

    assert get_user(later) == user
