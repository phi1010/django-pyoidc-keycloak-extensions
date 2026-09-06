"""Refresh one user, by Keycloak id or local username."""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from django_pyoidc_keycloak.admin_api.exceptions import KeycloakUserNotFound
from django_pyoidc_keycloak.sync.users import handle_missing_user, sync_user


class Command(BaseCommand):
    help = "Synchronise a single user from Keycloak."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("identifier", help="A Keycloak UUID or a local username.")

    def handle(self, *args: Any, **options: Any) -> None:
        identifier = options["identifier"]
        user_model = get_user_model()

        keycloak_id = identifier
        local_user = user_model.objects.filter(username=identifier).first()
        if local_user is not None:
            if local_user.keycloak_id is None:
                msg = f"{identifier!r} is a local-only account with no Keycloak id."
                raise CommandError(msg)
            keycloak_id = str(local_user.keycloak_id)

        try:
            user = sync_user(keycloak_id=keycloak_id, create=True)
        except KeycloakUserNotFound:
            if local_user is None:
                msg = f"No Keycloak user with id {keycloak_id!r}."
                raise CommandError(msg) from None
            outcome = handle_missing_user(local_user)
            self.stdout.write(f"{identifier} no longer exists in Keycloak: {outcome}.")
            return

        self.stdout.write(f"Synchronised {user.username} ({user.keycloak_id}).")
