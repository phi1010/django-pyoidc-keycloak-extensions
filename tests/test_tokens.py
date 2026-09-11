"""Token storage, lazy refresh and exchange."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from django.contrib.auth import get_user_model
from django.db import connection as db_connection
from django.utils import timezone
from django_pyoidc.models import OIDCSession

from django_pyoidc_keycloak.admin_api.exceptions import TokensUnavailable
from django_pyoidc_keycloak.models import OIDCTokenSet
from django_pyoidc_keycloak.tokens.exchange import exchange_access_token
from django_pyoidc_keycloak.tokens.extract import RawTokens, extract_raw_tokens
from django_pyoidc_keycloak.tokens.refresh import get_valid_access_token
from django_pyoidc_keycloak.tokens.store import purge_for_session, purge_orphans, store_tokens

pytestmark = pytest.mark.django_db

TOKEN_URL = "https://sso.example.org/realms/demo/protocol/openid-connect/token"
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.signature"


@pytest.fixture
def user():
    return get_user_model().objects.create_user(username="alice")


@pytest.fixture
def session():
    return OIDCSession.objects.create(state="s", sub="1", cache_session_key="k", session_state="ss")


@pytest.fixture
def token_set(user, session):
    return store_tokens(
        session=session,
        user=user,
        raw=RawTokens(
            access_token=JWT,
            id_token="id." + JWT,
            refresh_token="refresh-token",
            access_token_expires_at=datetime.now(tz=UTC) + timedelta(hours=1),
            scope="openid profile",
        ),
    )


# -- storage ------------------------------------------------------------


def test_tokens_round_trip_through_the_encrypted_columns(token_set):
    stored = OIDCTokenSet.objects.get(pk=token_set.pk)

    assert stored.access_token == JWT
    assert stored.refresh_token == "refresh-token"


def test_the_columns_are_ciphertext_at_rest(token_set):
    """Read past the ORM to prove the database itself holds no readable token."""
    with db_connection.cursor() as cursor:
        cursor.execute("SELECT access_token, refresh_token FROM keycloak_oidctokenset")
        raw = " ".join(str(value) for value in cursor.fetchone())

    assert JWT not in raw
    assert "refresh-token" not in raw


def test_nothing_is_stored_when_there_are_no_tokens(user, session):
    assert store_tokens(session=session, user=user, raw=RawTokens()) is None


def test_logging_out_purges_the_tokens(token_set, session):
    purge_for_session(session)

    assert OIDCTokenSet.objects.count() == 0


def test_deleting_the_session_cascades(token_set, session):
    session.delete()

    assert OIDCTokenSet.objects.count() == 0


def test_expired_sets_are_purged(user, session):
    store_tokens(
        session=session,
        user=user,
        raw=RawTokens(access_token=JWT, refresh_token="r"),
    )
    OIDCTokenSet.objects.update(refresh_token_expires_at=timezone.now() - timedelta(days=1))

    assert purge_orphans() == 1


def test_the_string_form_reveals_nothing(token_set):
    assert JWT not in str(token_set)
    assert JWT not in repr(token_set)


# -- extraction ---------------------------------------------------------


class _Token:
    """Stands in for a pyoidc Token object."""

    def __init__(self):
        self.access_token = JWT
        self.refresh_token = "refresh-token"
        self.id_token_jwt = "id." + JWT
        self.token_expiration_time = int(datetime.now(tz=UTC).timestamp()) + 300
        self.scope = ["openid", "profile"]


class _Grant:
    def __init__(self):
        self.tokens = [_Token()]


class _Consumer:
    def __init__(self):
        self.grant = {"state": _Grant()}


class _Client:
    def __init__(self):
        self.consumer = _Consumer()


def test_extracts_what_django_pyoidc_does_not_pass_on():
    """The raw ID token and refresh token exist only on the pyoidc consumer."""
    raw = extract_raw_tokens(_Client(), {"access_token_jwt": JWT})

    assert raw.access_token == JWT
    assert raw.refresh_token == "refresh-token"
    assert raw.id_token == "id." + JWT
    assert raw.scope == "openid profile"


def test_extraction_never_raises_on_an_unexpected_client():
    raw = extract_raw_tokens(object(), {"access_token_jwt": JWT})

    assert raw.access_token == JWT
    assert raw.refresh_token is None


def test_the_raw_token_repr_lists_names_not_values():
    raw = extract_raw_tokens(_Client(), {"access_token_jwt": JWT})

    assert JWT not in repr(raw)
    assert "access_token" in repr(raw)


# -- refresh ------------------------------------------------------------


def test_a_fresh_token_is_returned_without_any_http(token_set):
    with respx.mock:
        route = respx.post(TOKEN_URL)
        assert get_valid_access_token(token_set) == JWT
        assert route.call_count == 0


@respx.mock
def test_an_expiring_token_is_refreshed(token_set):
    token_set.access_token_expires_at = timezone.now() + timedelta(seconds=5)
    token_set.save()
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "new-token", "expires_in": 300}))

    assert get_valid_access_token(token_set) == "new-token"


@respx.mock
def test_a_rotated_refresh_token_is_stored(token_set):
    token_set.access_token_expires_at = timezone.now() - timedelta(seconds=1)
    token_set.save()
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "new", "expires_in": 300, "refresh_token": "rotated", "refresh_expires_in": 1800},
        )
    )

    get_valid_access_token(token_set)

    token_set.refresh_from_db()
    assert token_set.refresh_token == "rotated"


@respx.mock
def test_a_rejected_refresh_token_drops_the_row(token_set):
    token_set.access_token_expires_at = timezone.now() - timedelta(seconds=1)
    token_set.save()
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(400, json={"error": "invalid_grant"}))

    with pytest.raises(TokensUnavailable, match="log in again"):
        get_valid_access_token(token_set)

    assert OIDCTokenSet.objects.count() == 0


def test_without_a_refresh_token_the_caller_is_told(user, session):
    token_set = store_tokens(
        session=session,
        user=user,
        raw=RawTokens(access_token=JWT, access_token_expires_at=datetime.now(tz=UTC) - timedelta(seconds=1)),
    )

    with pytest.raises(TokensUnavailable, match="no refresh token"):
        get_valid_access_token(token_set)


def test_a_held_lock_stops_a_second_caller_from_refreshing(token_set):
    """The mutex is what keeps two workers from both hitting Keycloak."""
    from django_pyoidc_keycloak.tokens.refresh import _get_lock, _lock_key

    token_set.access_token_expires_at = timezone.now() - timedelta(seconds=1)
    token_set.save()

    # Pretend another worker got there first and is mid-refresh.
    others_lock = _get_lock(_lock_key(token_set))
    assert others_lock.acquire() is True

    # That worker finishes and writes the new token.
    OIDCTokenSet.objects.filter(pk=token_set.pk).update(
        access_token="new-token",
        access_token_expires_at=timezone.now() + timedelta(minutes=5),
    )

    with respx.mock:
        route = respx.post(TOKEN_URL)
        assert get_valid_access_token(token_set) == "new-token"
        assert route.call_count == 0, "the loser of the race must not refresh as well"

    others_lock.release()


def test_waiting_for_another_worker_eventually_gives_up(token_set, monkeypatch):
    """A worker that crashed mid-refresh must not hang the request forever."""
    from django_pyoidc_keycloak.tokens import refresh as refresh_module
    from django_pyoidc_keycloak.tokens.refresh import _get_lock, _lock_key

    monkeypatch.setattr(refresh_module, "LOCK_WAIT_TOTAL", 0.3)
    monkeypatch.setattr(refresh_module, "LOCK_POLL_INTERVAL", 0.05)
    token_set.access_token_expires_at = timezone.now() - timedelta(seconds=1)
    token_set.save()

    others_lock = _get_lock(_lock_key(token_set))
    assert others_lock.acquire() is True

    try:
        with pytest.raises(TokensUnavailable, match="Timed out"):
            get_valid_access_token(token_set)
    finally:
        others_lock.release()


@respx.mock
def test_the_lock_is_released_once_the_refresh_is_done(token_set):
    from django.core.cache import cache

    from django_pyoidc_keycloak.tokens.refresh import _lock_key

    token_set.access_token_expires_at = timezone.now() - timedelta(seconds=1)
    token_set.save()
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "new-token", "expires_in": 300}))

    get_valid_access_token(token_set)

    assert cache.get(_lock_key(token_set)) is None


@respx.mock
def test_a_caller_never_releases_someone_elses_lock(token_set):
    """redis-py's release only deletes the key when it still carries our own token, so a
    slow worker whose lock expired cannot unlock the next one's refresh."""
    from django.core.cache import cache

    from django_pyoidc_keycloak.tokens.refresh import _lock_key

    token_set.access_token_expires_at = timezone.now() - timedelta(seconds=1)
    token_set.save()

    def steal_the_lock(request):
        # The refresh outlived LOCK_TIMEOUT: the key expired and another worker took it.
        cache.set(_lock_key(token_set), "a-newer-token", None)
        return httpx.Response(200, json={"access_token": "new-token", "expires_in": 300})

    respx.post(TOKEN_URL).mock(side_effect=steal_the_lock)

    get_valid_access_token(token_set)

    assert cache.get(_lock_key(token_set)) == "a-newer-token"


def _raw_lock_value(key: str) -> str | None:
    """The lock's stored token, read past django-redis's serializer.

    redis-py stores a plain hex string, not a pickled value, so it can only be read
    through the raw client -- under the prefixed key django-redis itself would use.
    """
    from django.core.cache import cache

    raw = cache.client.get_client(write=True).get(cache.client.make_key(key))
    return raw.decode() if isinstance(raw, bytes) else raw


def test_the_mutex_stores_a_nonce_and_never_a_token(token_set):
    """Whatever ends up in Redis under the lock key must not be a credential.

    redis-py's lock stores a random UUID token; the test reads the stored value while
    the lock is held, to prove no JWT or refresh token snuck in.
    """
    from django_pyoidc_keycloak.tokens.refresh import _get_lock, _lock_key

    token_set.access_token_expires_at = timezone.now() - timedelta(seconds=1)
    token_set.save()

    lock = _get_lock(_lock_key(token_set))
    assert lock.acquire() is True
    try:
        value = _raw_lock_value(_lock_key(token_set))
    finally:
        lock.release()

    assert value, "the lock was never taken"
    assert value not in {JWT, "refresh-token", "new-token", str(token_set.pk), str(token_set.id)}
    assert "eyJ" not in value


@pytest.mark.redis
def test_lock_release_is_atomic_across_expiry(token_set):
    """Finding 3's regression test, against the real Redis.

    When the first worker's lock has expired and a second worker holds the lock, the
    first worker's release must be a no-op -- the Lua script compares tokens -- rather
    than deleting the second worker's lock.
    """
    import redis.exceptions
    from django.core.cache import cache

    from django_pyoidc_keycloak.tokens.refresh import _get_lock, _lock_key

    token_set.access_token_expires_at = timezone.now() - timedelta(seconds=1)
    token_set.save()

    first = _get_lock(_lock_key(token_set))
    assert first.acquire() is True

    # Simulate expiry: drop the key, then let a second worker in.
    cache.delete(_lock_key(token_set))

    second = _get_lock(_lock_key(token_set))
    assert second.acquire() is True

    # The first worker finishes and releases: it must not free the second worker's lock.
    with pytest.raises(redis.exceptions.LockNotOwnedError):
        first.release()

    assert _raw_lock_value(_lock_key(token_set)) is not None, "the second worker's lock was deleted"

    second.release()
    assert _raw_lock_value(_lock_key(token_set)) is None


# -- exchange -----------------------------------------------------------

# The runtime gate (SECURITY_REVIEW.md, finding 7) is on for these tests individually.


@pytest.fixture
def exchange_enabled(settings):
    settings.KEYCLOAK = {**settings.KEYCLOAK, "TOKEN_EXCHANGE_ENABLED": True}


def test_exchange_is_refused_when_the_feature_is_disabled():
    """The system check is not a gate; the call itself must refuse."""
    with respx.mock:
        route = respx.post(TOKEN_URL)

        with pytest.raises(TokensUnavailable, match="Token exchange is disabled"):
            exchange_access_token(JWT, audience="reports")

        assert route.call_count == 0, "a disabled exchange must never reach Keycloak"


@respx.mock
def test_exchange_uses_the_login_client_and_the_right_grant(exchange_enabled):
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "downstream"}))

    assert exchange_access_token(JWT, audience="reports") == "downstream"

    sent = respx.calls[0].request.content.decode()
    assert "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" in sent
    assert "audience=reports" in sent
    assert "client_id=django-app" in sent


@respx.mock
def test_a_refused_exchange_explains_the_keycloak_requirements(exchange_enabled):
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(403, text="not allowed"))

    with pytest.raises(TokensUnavailable, match="Standard token exchange"):
        exchange_access_token(JWT, audience="reports")


@respx.mock
def test_exchanged_tokens_are_never_cached(exchange_enabled):
    from django.core.cache import cache

    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "downstream"}))

    exchange_access_token(JWT, audience="reports")
    exchange_access_token(JWT, audience="reports")

    assert respx.calls.call_count == 2, "a cached exchange would have skipped the second call"
    assert cache.get("keycloak:exchange:reports") is None


def test_offline_is_derived_from_the_granted_scope(user, session):
    """Asking for offline_access does not mean Keycloak issued an offline token."""
    token_set = store_tokens(
        session=session,
        user=user,
        raw=RawTokens(access_token=JWT, refresh_token="r", scope="openid profile"),
    )

    assert token_set.is_offline is False


def test_a_granted_offline_scope_marks_the_set_offline(user, session):
    token_set = store_tokens(
        session=session,
        user=user,
        raw=RawTokens(access_token=JWT, refresh_token="r", scope="openid offline_access"),
    )

    assert token_set.is_offline is True


def test_offline_detection_matches_a_whole_scope_token(user, session):
    """Finding 6: "notoffline_access" must not read as "offline_access"."""
    token_set = store_tokens(
        session=session,
        user=user,
        raw=RawTokens(access_token=JWT, refresh_token="r", scope="openid notoffline_access"),
    )

    assert token_set.is_offline is False
