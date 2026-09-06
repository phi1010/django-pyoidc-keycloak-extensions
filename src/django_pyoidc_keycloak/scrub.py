"""Keep secrets out of logs, tracebacks and audit rows.

Raw tokens live in exactly one place: the encrypted columns of ``OIDCTokenSet``.  Every
other path -- log records, exception messages, ``SyncRun.error_detail`` -- goes through
here first.
"""

from __future__ import annotations

import re
from typing import Any

SECRET_KEYS = frozenset(
    {
        "access_token",
        "refresh_token",
        "id_token",
        "id_token_hint",
        "code",
        "client_secret",
        "subject_token",
        "password",
        "authorization",
    }
)

REDACTED = "[redacted]"

#: Matches a compact JWS/JWT, which always starts with a base64url-encoded ``{"`` header.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def scrub_text(text: str) -> str:
    """Replace anything that looks like a JWT in free-form text."""
    return _JWT_RE.sub(REDACTED, text)


def scrub(value: Any) -> Any:
    """Recursively redact secret-bearing keys and any embedded JWT."""
    if isinstance(value, dict):
        return {key: (REDACTED if str(key).lower() in SECRET_KEYS else scrub(val)) for key, val in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(scrub(item) for item in value)
    if isinstance(value, str):
        return scrub_text(value)
    return value


def scrub_exception(exc: BaseException) -> str:
    """Render an exception safely for a log line or an audit row."""
    return scrub_text(f"{type(exc).__name__}: {exc}")
