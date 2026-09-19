"""A project's own user model, for the swapped-AUTH_USER_MODEL regression test.

This is what the README tells a project to write when it wants to add fields to the user
later. It is exercised by tests/test_swapped_user_model.py through a separate settings
module, because AUTH_USER_MODEL cannot be changed within a running Django instance.
"""

from __future__ import annotations

from django.db import models

from django_pyoidc_keycloak.models import AbstractKeycloakUser


class User(AbstractKeycloakUser):
    """A concrete user in the project's own app, with an extra field."""

    department = models.CharField(max_length=100, blank=True)

    class Meta(AbstractKeycloakUser.Meta):
        abstract = False
        swappable = "AUTH_USER_MODEL"
