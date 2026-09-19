"""Remove token sets that nothing can use any more."""

from __future__ import annotations

import logging
from typing import Any

from django.core.management.base import BaseCommand

from django_pyoidc_keycloak.sync.groups import sweep_expired_memberships
from django_pyoidc_keycloak.sync.roles import sweep_expired_role_assignments
from django_pyoidc_keycloak.tokens.store import purge_orphans

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Delete expired token sets and expired manual group memberships and role assignments."

    def handle(self, *args: Any, **options: Any) -> None:
        logger.debug("Purging expired token sets and expired manual memberships and role assignments")
        tokens = purge_orphans()
        memberships = sweep_expired_memberships()
        assignments = sweep_expired_role_assignments()
        self.stdout.write(
            f"Removed {tokens} expired token sets, {memberships} expired manual memberships "
            f"and {assignments} expired manual role assignments."
        )
