"""Ready-to-use models.

Set ``AUTH_USER_MODEL = "keycloak.KeycloakUser"`` **before** the project's first migrate.
Projects that need extra fields should subclass the abstract bases instead and point
``AUTH_USER_MODEL``, ``KEYCLOAK_GROUP_MODEL`` and ``KEYCLOAK_MEMBERSHIP_MODEL`` at their own.
"""

from __future__ import annotations

from django_pyoidc_keycloak.models.base import (
    AbstractGroupMembership,
    AbstractKeycloakGroup,
    AbstractKeycloakUser,
)


class KeycloakUser(AbstractKeycloakUser):
    class Meta(AbstractKeycloakUser.Meta):
        abstract = False
        db_table = "keycloak_user"
        swappable = "AUTH_USER_MODEL"


class KeycloakGroup(AbstractKeycloakGroup):
    class Meta(AbstractKeycloakGroup.Meta):
        abstract = False
        db_table = "keycloak_group"


class GroupMembership(AbstractGroupMembership):
    class Meta(AbstractGroupMembership.Meta):
        abstract = False
        db_table = "keycloak_group_membership"
