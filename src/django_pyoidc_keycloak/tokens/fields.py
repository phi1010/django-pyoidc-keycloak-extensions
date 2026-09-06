"""Encrypted storage for raw tokens.

Built on ``django-fernet-encrypted-fields``, which derives its Fernet key with PBKDF2 from
``SECRET_KEY`` and ``SALT_KEY``.  Two consequences worth knowing:

* ``SALT_KEY`` must be set, or the field raises at first use.  A system check enforces this.
* Rotating ``SECRET_KEY`` without listing the old value in ``SECRET_KEY_FALLBACKS`` makes
  existing ciphertext unreadable.  Tokens are session-scoped and disposable, so rather than
  raising a 500 on every read we return ``None`` and let the caller re-authenticate.
"""

from __future__ import annotations

import logging
from typing import Any

from cryptography.fernet import InvalidToken
from encrypted_fields.fields import EncryptedTextField as _EncryptedTextField

logger = logging.getLogger(__name__)


class EncryptedTokenField(_EncryptedTextField):
    """An encrypted text column that survives a key rotation without breaking the site."""

    def from_db_value(self, value: Any, expression: Any, connection: Any) -> Any:
        try:
            return super().from_db_value(value, expression, connection)
        except InvalidToken, ValueError:
            # Almost always a rotated SECRET_KEY. The stored token is unusable either way;
            # callers treat None as "no token" and send the user through login again.
            logger.warning(
                "Could not decrypt %s.%s -- the encryption key has probably changed. "
                "Add the previous SECRET_KEY to SECRET_KEY_FALLBACKS to keep stored tokens readable.",
                self.model._meta.label if hasattr(self, "model") else "?",
                self.name,
            )
            return None
