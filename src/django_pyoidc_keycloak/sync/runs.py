"""Helper that records every synchronisation pass as an auditable row."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator

from django.utils import timezone

from django_pyoidc_keycloak.admin_api.provider import get_connection
from django_pyoidc_keycloak.models.sync import SyncKind, SyncRun, SyncStatus
from django_pyoidc_keycloak.scrub import scrub_exception, scrub_text
from django_pyoidc_keycloak.signals import sync_run_finished

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def sync_run(kind: str, realm: str | None = None) -> Iterator[SyncRun]:
    """Open a SyncRun, close it on the way out, and record failures without leaking secrets."""
    if realm is None:
        try:
            realm = get_connection().realm
        except Exception:  # pragma: no cover - configuration errors surface elsewhere
            realm = "?"

    run = SyncRun.objects.create(kind=kind, realm=realm)
    logger.debug("Opened %s synchronisation run %s for realm %s", kind, run.pk, realm)
    try:
        yield run
    except Exception as exc:
        logger.debug("Synchronisation run %s failed: %s", run.pk, scrub_exception(exc))
        run.status = SyncStatus.FAILED
        run.errors += 1
        run.error_detail = scrub_exception(exc)
        run.finished_at = timezone.now()
        run.save()
        sync_run_finished.send(sender=SyncRun, sync_run=run)
        raise
    else:
        run.status = SyncStatus.FAILED if run.errors else SyncStatus.SUCCESS
        run.finished_at = timezone.now()
        run.save()
        logger.info(
            "%s run %s on realm %s finished as %s: %d created, %d updated, %d deleted, "
            "%d anonymised, %d skipped, %d error(s)",
            kind,
            run.pk,
            realm,
            run.status,
            run.created,
            run.updated,
            run.deleted,
            run.anonymized,
            run.skipped,
            run.errors,
        )
        sync_run_finished.send(sender=SyncRun, sync_run=run)


def record_error(run: SyncRun, message: str) -> None:
    """Append a scrubbed error line to the run."""
    run.errors += 1
    safe = scrub_text(message)
    run.error_detail = f"{run.error_detail}\n{safe}".strip()[:20000]
    logger.warning("Synchronisation error: %s", safe)


__all__ = ["SyncKind", "record_error", "sync_run"]
