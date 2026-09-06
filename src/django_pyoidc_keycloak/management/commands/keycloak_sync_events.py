"""Incremental synchronisation. Run this often (a minute or two) from cron or Celery beat."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from django_pyoidc_keycloak.sync.events import poll_admin_events, poll_user_events


class Command(BaseCommand):
    help = "Poll Keycloak's event streams and apply the changes locally."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--admin-only", action="store_true", help="Skip the account-console event stream.")
        parser.add_argument("--user-only", action="store_true", help="Only poll the account-console event stream.")

    def handle(self, *args: Any, **options: Any) -> None:
        if not options["user_only"]:
            counts = poll_admin_events()
            self.stdout.write(f"Admin events: {counts['processed']} processed, {counts['skipped']} already seen.")
        if not options["admin_only"]:
            counts = poll_user_events()
            self.stdout.write(f"User events: {counts['processed']} processed, {counts['skipped']} already seen.")
