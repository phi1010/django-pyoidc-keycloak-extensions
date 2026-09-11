"""The standing rule: the only place a token is at rest is an encrypted column.

Never the cache, never a log line, never an audit row.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django_pyoidc.models import OIDCSession

from django_pyoidc_keycloak.models import SyncRun
from django_pyoidc_keycloak.scrub import REDACTED, scrub, scrub_exception, scrub_text
from django_pyoidc_keycloak.sync.runs import record_error, sync_run
from django_pyoidc_keycloak.tokens.extract import RawTokens
from django_pyoidc_keycloak.tokens.refresh import get_valid_access_token
from django_pyoidc_keycloak.tokens.store import store_tokens

pytestmark = pytest.mark.django_db

TOKEN_URL = "https://sso.example.org/realms/demo/protocol/openid-connect/token"
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"


def test_scrub_replaces_a_jwt_anywhere_in_a_string():
    assert JWT not in scrub_text(f"Keycloak said no to {JWT} today")
    assert REDACTED in scrub_text(f"token={JWT}")


def test_scrub_redacts_secret_bearing_keys():
    result = scrub({"access_token": JWT, "client_secret": "s3cr3t", "username": "alice"})

    assert result == {"access_token": REDACTED, "client_secret": REDACTED, "username": "alice"}


def test_scrub_reaches_into_nested_structures():
    result = scrub({"outer": [{"refresh_token": "r"}]})

    assert result["outer"][0]["refresh_token"] == REDACTED


def test_scrub_exception_hides_an_embedded_token():
    message = scrub_exception(ValueError(f"bad token {JWT}"))

    assert JWT not in message
    assert "ValueError" in message


def test_an_audit_row_never_records_a_token():
    with sync_run("manual", realm="demo") as run:
        record_error(run, f"Refresh failed for {JWT}")

    assert JWT not in SyncRun.objects.get().error_detail


def test_a_failing_run_records_a_scrubbed_message():
    with pytest.raises(RuntimeError):
        with sync_run("manual", realm="demo"):
            raise RuntimeError(f"exploded with {JWT}")

    run = SyncRun.objects.get()
    assert run.status == "failed"
    assert JWT not in run.error_detail


@respx.mock
def test_no_cached_value_holds_a_token_after_a_full_cycle(caplog):
    """Login, store, refresh and exchange -- then inspect every Redis write.

    The refresh lock writes through redis-py's own ``SET`` (django-redis's ``lock()``
    hands out a redis-py ``Lock``), so the spy hooks the underlying client rather than
    the Django cache API.
    """
    import redis

    written: dict[bytes | str, bytes | str] = {}
    redis_client = cache.client.get_client(write=True)
    original_set = redis_client.set

    def spy_set(key, value, **kwargs):
        written[key] = value
        return original_set(key, value, **kwargs)

    redis_client.set = spy_set
    try:
        user = get_user_model().objects.create_user(username="alice")
        session = OIDCSession.objects.create(state="s", sub="1", cache_session_key="k", session_state="ss")
        token_set = store_tokens(
            session=session,
            user=user,
            raw=RawTokens(
                access_token=JWT,
                id_token=JWT,
                refresh_token="refresh-token",
                access_token_expires_at=datetime.now(tz=UTC) - timedelta(seconds=1),
            ),
        )

        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": JWT, "expires_in": 300}))
        with caplog.at_level(logging.DEBUG):
            get_valid_access_token(token_set)

            from django_pyoidc_keycloak.tokens.exchange import exchange_access_token

            respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": JWT}))
            with override_settings(KEYCLOAK={**settings.KEYCLOAK, "TOKEN_EXCHANGE_ENABLED": True}):
                exchange_access_token(JWT, audience="reports")
    finally:
        redis_client.set = original_set

    assert written, "nothing was cached at all -- the test is not exercising the path"
    for key, value in written.items():
        assert "eyJ" not in str(value), f"a JWT reached Redis under {key!r}"
        assert "refresh-token" not in str(value), f"a refresh token reached Redis under {key!r}"

    for record in caplog.records:
        assert "eyJ" not in record.getMessage()
        assert "refresh-token" not in record.getMessage()

    assert isinstance(redis_client, redis.Redis)  # the spy really was on the redis client
