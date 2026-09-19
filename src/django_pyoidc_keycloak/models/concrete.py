"""Ready-to-use models.

Set ``AUTH_USER_MODEL = "keycloak.KeycloakUser"`` **before** the project's first migrate.
Projects that need extra fields should subclass the abstract bases instead and point
``AUTH_USER_MODEL``, ``KEYCLOAK_GROUP_MODEL``, ``KEYCLOAK_MEMBERSHIP_MODEL``,
``KEYCLOAK_ROLE_MODEL`` and ``KEYCLOAK_ROLE_ASSIGNMENT_MODEL`` at their own.
"""

from __future__ import annotations

from django_pyoidc_keycloak.models.base import (
    AbstractGroupMembership,
    AbstractKeycloakGroup,
    AbstractKeycloakRole,
    AbstractKeycloakUser,
    AbstractRoleAssignment,
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


class KeycloakRole(AbstractKeycloakRole):
    class Meta(AbstractKeycloakRole.Meta):
        abstract = False
        db_table = "keycloak_role"


class RoleAssignment(AbstractRoleAssignment):
    class Meta(AbstractRoleAssignment.Meta):
        abstract = False
        db_table = "keycloak_role_assignment"
