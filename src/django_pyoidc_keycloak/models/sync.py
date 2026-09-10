"""Bookkeeping for synchronisation: what ran, and where event polling got to."""

from __future__ import annotations

import uuid

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class SyncKind(models.TextChoices):
    EVENTS = "events", _("Event poll")
    RECONCILE = "reconcile", _("Full reconciliation")
    MANUAL = "manual", _("Manual")
    LOGIN = "login", _("Login")


class SyncStatus(models.TextChoices):
    RUNNING = "running", _("Running")
    SUCCESS = "success", _("Success")
    FAILED = "failed", _("Failed")


class SyncRun(models.Model):
    """One synchronisation pass. The audit trail for 'why did this user change?'."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(_("kind"), max_length=16, choices=SyncKind.choices)
    realm = models.CharField(_("realm"), max_length=255)
    status = models.CharField(_("status"), max_length=16, choices=SyncStatus.choices, default=SyncStatus.RUNNING)
    started_at = models.DateTimeField(_("started at"), default=timezone.now)
    finished_at = models.DateTimeField(_("finished at"), null=True, blank=True)

    created = models.PositiveIntegerField(_("created"), default=0)
    updated = models.PositiveIntegerField(_("updated"), default=0)
    deleted = models.PositiveIntegerField(_("deleted"), default=0)
    anonymized = models.PositiveIntegerField(_("anonymised"), default=0)
    skipped = models.PositiveIntegerField(_("skipped"), default=0)
    errors = models.PositiveIntegerField(_("errors"), default=0)

    #: Scrubbed before it is written -- see django_pyoidc_keycloak.scrub.
    error_detail = models.TextField(_("error detail"), blank=True)

    class Meta:
        ordering = ["-started_at"]
        verbose_name = _("synchronisation run")
        verbose_name_plural = _("synchronisation runs")

    def __str__(self) -> str:
        # TODO reference to missing method, to be fixed.
        return f"{self.get_kind_display()} on {self.realm} at {self.started_at:%Y-%m-%d %H:%M:%S}"

    @property
    def duration(self):
        if self.finished_at is None:
            return None
        return self.finished_at - self.started_at


class SyncCursor(models.Model):
    """How far event polling has processed, per realm and stream.

    Keycloak's ``dateFrom`` filter is day-granular, so a poll always re-reads a window and
    relies on ``seen_event_ids`` plus idempotent processing to avoid doing work twice.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    realm = models.CharField(_("realm"), max_length=255)
    stream = models.CharField(_("stream"), max_length=32)
    last_event_time = models.DateTimeField(_("last event time"), null=True, blank=True)
    seen_event_ids = models.JSONField(_("recently seen events"), default=list, blank=True)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)

    #: How many event fingerprints to remember for de-duplication.
    SEEN_LIMIT = 2000

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["realm", "stream"], name="keycloak_synccursor_unique_stream"),
        ]
        verbose_name = _("synchronisation cursor")
        verbose_name_plural = _("synchronisation cursors")

    def __str__(self) -> str:
        return f"{self.realm}/{self.stream}"

    def remember(self, fingerprints: list[str]) -> None:
        """Record processed events, keeping only the most recent ones."""
        combined = [*self.seen_event_ids, *fingerprints]
        self.seen_event_ids = combined[-self.SEEN_LIMIT :]

    def has_seen(self, fingerprint: str) -> bool:
        return fingerprint in self.seen_event_ids
