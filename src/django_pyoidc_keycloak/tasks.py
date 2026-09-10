"""Optional Celery tasks.

Importing this module without Celery installed is harmless: the decorators become no-ops and
``CELERY_AVAILABLE`` stays False, which is what the admin checks before offering to enqueue
a bulk synchronisation.
"""

from __future__ import annotations

import logging
from typing import Any

try:  # pragma: no cover - exercised by whichever environment the project has
    from celery import shared_task

    CELERY_AVAILABLE = True
except ImportError:  # pragma: no cover
    CELERY_AVAILABLE = False

    def shared_task(*args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
        """Stand-in so the module imports without Celery."""

        def decorator(func: Any) -> Any:
            return func

        if args and callable(args[0]):
            return args[0]
        return decorator


logger = logging.getLogger(__name__)


@shared_task(name="keycloak.sync_events")
def sync_events_task() -> dict[str, int]:
    from django_pyoidc_keycloak.sync.events import poll_events

    logger.debug("Celery task keycloak.sync_events starting")
    return poll_events()


@shared_task(name="keycloak.reconcile")
def reconcile_task(import_all: bool | None = None) -> dict[str, int]:
    from django_pyoidc_keycloak.sync.reconcile import full_reconcile

    logger.debug("Celery task keycloak.reconcile starting (import_all=%s)", import_all)
    return full_reconcile(import_all=import_all)


@shared_task(name="keycloak.sync_user")
def sync_user_task(keycloak_id: str) -> str | None:
    from django_pyoidc_keycloak.sync.users import sync_user

    logger.debug("Celery task keycloak.sync_user starting for %s", keycloak_id)
    user = sync_user(keycloak_id=keycloak_id, create=True)
    return str(user.pk) if user else None


@shared_task(name="keycloak.sync_users")
def sync_users_task(user_pks: list[str]) -> dict[str, int]:
    """Bulk refresh, used by the admin so a large selection does not block the request."""
    from django.contrib.auth import get_user_model

    from django_pyoidc_keycloak.sync.reconcile import sync_users

    logger.debug("Celery task keycloak.sync_users starting for %d user(s)", len(user_pks))
    user_model = get_user_model()
    return sync_users(user_model.objects.filter(pk__in=user_pks))


@shared_task(name="keycloak.purge_tokens")
def purge_tokens_task() -> dict[str, int]:
    from django_pyoidc_keycloak.sync.groups import sweep_expired_memberships
    from django_pyoidc_keycloak.tokens.store import purge_orphans

    logger.debug("Celery task keycloak.purge_tokens starting")
    return {"tokens": purge_orphans(), "memberships": sweep_expired_memberships()}
