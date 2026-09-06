"""Username derivation, including the collision case that motivates it."""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from django_pyoidc_keycloak.sync.usernames import MAX_LENGTH, derive_username, sanitize
from tests.conftest import kc_user

pytestmark = pytest.mark.django_db


def test_prefers_preferred_username():
    assert derive_username({"preferred_username": "alice", "email": "other@example.org"}) == "alice"


def test_falls_back_to_email_local_part():
    assert derive_username({"email": "bob@example.org"}) == "bob"


def test_falls_back_to_the_keycloak_id():
    assert derive_username({"id": "abc-123"}) == "abc-123"


def test_rejects_a_representation_with_nothing_usable():
    with pytest.raises(ValueError, match="Cannot derive a username"):
        derive_username({})


def test_strips_characters_django_does_not_allow():
    assert sanitize("al ice!") == "alice"


def test_suffixes_on_collision():
    """A local row may hold a name Keycloak has since reassigned."""
    user_model = get_user_model()
    user_model.objects.create_user(username="alice")

    assert derive_username(kc_user(preferred_username="alice")) == "alice-2"


def test_keeps_counting_past_the_first_suffix():
    user_model = get_user_model()
    user_model.objects.create_user(username="alice")
    user_model.objects.create_user(username="alice-2")

    assert derive_username({"preferred_username": "alice"}) == "alice-3"


def test_a_user_does_not_collide_with_itself():
    user_model = get_user_model()
    user = user_model.objects.create_user(username="alice")

    assert derive_username({"preferred_username": "alice"}, exclude_pk=user.pk) == "alice"


def test_suffix_fits_inside_the_column():
    user_model = get_user_model()
    long_name = "a" * MAX_LENGTH
    user_model.objects.create_user(username=long_name)

    result = derive_username({"preferred_username": long_name})

    assert len(result) <= MAX_LENGTH
    assert result.endswith("-2")
