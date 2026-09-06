"""Models that exist only to exercise the delete-or-anonymise branch."""

from __future__ import annotations

from django.conf import settings
from django.db import models


class ProtectedDocument(models.Model):
    """A host-application model that refuses to let its owner be deleted."""

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="documents")
    title = models.CharField(max_length=100)

    def __str__(self) -> str:
        return self.title


class CascadingNote(models.Model):
    """A host-application model that is happy to go with its owner."""

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notes")
    body = models.TextField(blank=True)

    def __str__(self) -> str:
        return self.body[:50]
