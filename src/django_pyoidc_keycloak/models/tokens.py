"""Encrypted, session-scoped storage for the raw OIDC tokens.

This is the *only* place a token is at rest.  Never the Django cache, never the session,
never a log line, never an admin page.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from django_pyoidc_keycloak.tokens.fields import EncryptedTokenField


class OIDCTokenSet(models.Model):
    """The tokens issued for one login, tied to django-pyoidc's session row.

    Deleting the session deletes these, which is what makes logout purge them.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.OneToOneField(
        "django_pyoidc.OIDCSession",
        on_delete=models.CASCADE,
        related_name="token_set",
        verbose_name=_("OIDC session"),
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="token_sets",
        verbose_name=_("user"),
    )

    access_token = EncryptedTokenField(_("access token"), blank=True, null=True)
    id_token = EncryptedTokenField(_("ID token"), blank=True, null=True)
    refresh_token = EncryptedTokenField(_("refresh token"), blank=True, null=True)

    access_token_expires_at = models.DateTimeField(_("access token expires at"), null=True, blank=True)
    refresh_token_expires_at = models.DateTimeField(_("refresh token expires at"), null=True, blank=True)
    is_offline = models.BooleanField(
        _("offline session"),
        default=False,
        help_text=_("Set when offline_access was requested, so the token outlives the SSO session."),
    )
    scope = models.CharField(_("scope"), max_length=500, blank=True)
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)

    class Meta:
        verbose_name = _("OIDC token set")
        verbose_name_plural = _("OIDC token sets")

    def __str__(self) -> str:
        # Deliberately identifies the row without revealing anything about the tokens.
        return f"Tokens for {self.user_id}"

    def __repr__(self) -> str:
        return f"<OIDCTokenSet id={self.id} user={self.user_id}>"

    @property
    def access_token_expired(self) -> bool:
        if self.access_token_expires_at is None:
            return self.access_token is None
        return self.access_token_expires_at <= timezone.now()

    @property
    def refresh_token_expired(self) -> bool:
        if self.refresh_token is None:
            return True
        if self.refresh_token_expires_at is None:
            # Offline tokens have no fixed expiry; non-offline ones follow the SSO session.
            return False
        return self.refresh_token_expires_at <= timezone.now()

    def expires_within(self, seconds: int) -> bool:
        """Whether the access token is gone or about to be."""
        if self.access_token is None:
            return True
        if self.access_token_expires_at is None:
            return True
        return self.access_token_expires_at <= timezone.now() + timedelta(seconds=seconds)
