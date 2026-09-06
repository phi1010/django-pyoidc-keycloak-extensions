"""Remove token sets that nothing can use any more."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from django_pyoidc_keycloak.sync.groups import sweep_expired_memberships
from django_pyoidc_keycloak.tokens.store import purge_orphans


class Command(BaseCommand):
    help = "Delete expired token sets and expired manual group memberships."

    def handle(self, *args: Any, **options: Any) -> None:
        tokens = purge_orphans()
        memberships = sweep_expired_memberships()
        self.stdout.write(f"Removed {tokens} expired token sets and {memberships} expired manual memberships.")
