"""Extraction exercised against real pyoidc objects, not hand-written stand-ins.

The raw ID token and refresh token are not passed to ``hook_get_user``; they exist only on
the pyoidc consumer's grant.  That makes this the library's riskiest coupling, so the test
uses pyoidc's own ``AccessTokenResponse``, ``Grant`` and ``Token`` classes -- if their
storage semantics change, this fails rather than the stubs silently agreeing with a stale
reading of the source.
"""

from __future__ import annotations

from oic.oauth2.grant import Grant
from oic.oic.message import AccessTokenResponse

from django_pyoidc_keycloak.tokens.extract import extract_raw_tokens

ACCESS = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.access-signature"
ID_TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.id-signature"
REFRESH = "eyJhbGciOiJIUzUxMiJ9.eyJ0eXAiOiJSZWZyZXNoIn0.refresh-signature"


def real_grant() -> Grant:
    """A Grant holding a Token built the way pyoidc builds it after a code exchange."""
    response = AccessTokenResponse(
        access_token=ACCESS,
        token_type="Bearer",
        refresh_token=REFRESH,
        expires_in=300,
        scope=["openid", "profile"],
    )
    # AccessTokenResponse.verify() stashes the raw JWT here before replacing "id_token"
    # with a decoded IdToken instance (oic/oic/message.py).
    response["id_token_jwt"] = ID_TOKEN

    grant = Grant()
    grant.add_token(response)
    return grant


class RealConsumer:
    def __init__(self) -> None:
        self.grant = {"some-state": real_grant()}


class RealClient:
    def __init__(self) -> None:
        self.consumer = RealConsumer()


def test_pyoidc_really_does_carry_the_raw_id_and_refresh_tokens():
    """Guards the assumption the whole token feature rests on."""
    token = real_grant().tokens[0]

    assert token.access_token == ACCESS
    assert token.refresh_token == REFRESH
    assert token.id_token_jwt == ID_TOKEN


def test_extracts_all_three_tokens_from_a_real_grant():
    raw = extract_raw_tokens(RealClient(), {"access_token_jwt": ACCESS})

    assert raw.access_token == ACCESS
    assert raw.id_token == ID_TOKEN
    assert raw.refresh_token == REFRESH
    assert raw.scope == "openid profile"


def test_the_expiry_comes_across():
    raw = extract_raw_tokens(RealClient(), {"access_token_jwt": ACCESS})

    assert raw.access_token_expires_at is not None


def test_extraction_works_without_the_hook_dict():
    """django-pyoidc may omit access_token_jwt; the grant still has everything."""
    raw = extract_raw_tokens(RealClient(), {})

    assert raw.access_token == ACCESS
    assert raw.refresh_token == REFRESH


def test_a_grant_without_a_refresh_token_is_reported_not_invented():
    class NoRefreshClient:
        def __init__(self) -> None:
            response = AccessTokenResponse(access_token=ACCESS, token_type="Bearer", expires_in=300)
            grant = Grant()
            grant.add_token(response)
            self.consumer = type("C", (), {"grant": {"s": grant}})()

    raw = extract_raw_tokens(NoRefreshClient(), {"access_token_jwt": ACCESS})

    assert raw.access_token == ACCESS
    assert raw.refresh_token is None


def test_a_consumer_with_several_grants_picks_the_matching_token():
    """Only the grant for this login should be read."""
    other = AccessTokenResponse(access_token="other.token.value", token_type="Bearer", expires_in=300)
    other["id_token_jwt"] = "other.id.token"
    stale = Grant()
    stale.add_token(other)

    class TwoGrantClient:
        def __init__(self) -> None:
            self.consumer = type("C", (), {"grant": {"stale": stale, "current": real_grant()}})()

    raw = extract_raw_tokens(TwoGrantClient(), {"access_token_jwt": ACCESS})

    assert raw.access_token == ACCESS
    assert raw.id_token == ID_TOKEN
    assert raw.refresh_token == REFRESH
