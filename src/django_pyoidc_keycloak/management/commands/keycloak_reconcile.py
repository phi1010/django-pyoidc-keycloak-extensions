"""Full reconciliation. Run this on a slower schedule (hourly or nightly).

Event polling misses LDAP-federated changes and expires, so this is the pass that guarantees
the local database eventually matches the realm.
"""

from __future__ import annotations

import logging
from typing import Any

from django.core.management.base import BaseCommand

from django_pyoidc_keycloak.sync.reconcile import full_reconcile

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Compare every Keycloak user and group against the local database and converge."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--dry-run", action="store_true", help="Report what would change, change nothing.")
        parser.add_argument(
            "--import-all",
            action="store_true",
            help="Create local users for Keycloak accounts that have never logged in.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        # The pass itself logs its own progress; this records how it was invoked.
        logger.debug(
            "keycloak_reconcile invoked with --dry-run=%s --import-all=%s",
            options["dry_run"],
            options["import_all"],
        )
        stats = full_reconcile(
            import_all=True if options["import_all"] else None,
            dry_run=options["dry_run"],
        )
        prefix = "Would apply" if options["dry_run"] else "Applied"
        self.stdout.write(
            f"{prefix}: {stats['created']} created, {stats['updated']} updated, "
            f"{stats['deleted']} deleted, {stats['anonymized']} anonymised, "
            f"{stats['skipped']} skipped, {stats['groups']} groups."
        )
