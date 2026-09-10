"""Debug logging is on the record, and it is not a leak.

Two obligations, one per test kind:

* Something is actually logged, at the ``django_pyoidc_keycloak`` namespace, for each
  subsystem -- otherwise an absence assertion below would pass vacuously.
* No secret and no personal data reaches a log record, at any level.  DEBUG is where this
  is most easily lost, because that is where the interesting values live.

The sentinels are deliberately distinctive so that a substring search over ``caplog.text``
cannot pass by accident.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from django_pyoidc.models import OIDCSession

from django_pyoidc_keycloak.sync.events import poll_admin_events
from django_pyoidc_keycloak.sync.groups import apply_group_paths, sync_groups
from django_pyoidc_keycloak.sync.reconcile import full_reconcile, sync_users
from django_pyoidc_keycloak.sync.usernames import derive_username
from django_pyoidc_keycloak.sync.users import anonymize, sync_user
from django_pyoidc_keycloak.tokens.extract import RawTokens
from django_pyoidc_keycloak.tokens.store import find_session, get_token_set, store_tokens
from tests.conftest import kc_user

pytestmark = pytest.mark.django_db

LOGGER = "django_pyoidc_keycloak"

#: Anything that must never be rendered into a log record.
UNAME = "sentinel-username-zz"
EMAIL = "sentinel-email@example.invalid"
FIRST = "SentinelGiven"
LAST = "SentinelFamily"
ATTR = "SENTINEL-ATTRIBUTE-VALUE"
ACCESS = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJTRU5USU5FTC1BQ0NFU1MifQ.SENTINELACCESSSIG"
REFRESH = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJTRU5USU5FTC1SRUZSRVNIIn0.SENTINELREFRESHSIG"
IDTOK = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJTRU5USU5FTC1JRCJ9.SENTINELIDSIG"

SECRETS = (ACCESS, REFRESH, IDTOK)
PERSONAL = (UNAME, EMAIL, FIRST, LAST, ATTR)


@pytest.fixture
def debug_logs(caplog):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    return caplog


def _now_ms() -> int:
    """Event timestamps must fall inside the poll window, which starts a day back."""
    return int(timezone.now().timestamp() * 1000)


def sentinel_user(**overrides):
    """A Keycloak representation whose every human-readable field is a sentinel."""
    return kc_user(
        username=UNAME,
        email=EMAIL,
        firstName=FIRST,
        lastName=LAST,
        attributes={"department": [ATTR]},
        **overrides,
    )


def assert_clean(caplog, *, expect_records_from: str) -> None:
    """No sentinel leaked, and something was logged so the check is not vacuous."""
    text = caplog.text
    for secret in SECRETS:
        assert secret not in text, f"a token reached the log: {secret[:24]}..."
    for personal in PERSONAL:
        assert personal not in text, f"personal data reached the log: {personal}"
    assert any(record.name.startswith(expect_records_from) for record in caplog.records), (
        f"nothing was logged under {expect_records_from}; the assertions above prove nothing"
    )


# -- users --------------------------------------------------------------


def test_syncing_a_user_logs_without_leaking_the_account(debug_logs, connection):
    stub = mock.Mock()
    stub.connection = connection
    stub.get_user_groups.return_value = []
    stub.get_user_realm_roles.return_value = []

    user = sync_user(sentinel_user(), client=stub, create=True, sync_groups=False)

    assert user.email == EMAIL, "the data must still be stored -- only the log is redacted"
    assert_clean(debug_logs, expect_records_from="django_pyoidc_keycloak.sync.users")


def test_the_changed_field_names_are_logged_but_not_their_values(debug_logs, connection):
    stub = mock.Mock()
    stub.connection = connection
    stub.get_user_groups.return_value = []
    stub.get_user_realm_roles.return_value = []
    representation = sentinel_user()

    sync_user(representation, client=stub, create=True, sync_groups=False)

    assert "email" in debug_logs.text, "the field name is the useful part"
    assert_clean(debug_logs, expect_records_from="django_pyoidc_keycloak.sync.users")


def test_anonymising_logs_the_ids_only(debug_logs):
    user = get_user_model().objects.create_user(username=UNAME, email=EMAIL, first_name=FIRST, keycloak_id=uuid.uuid4())

    anonymize(user)

    assert_clean(debug_logs, expect_records_from="django_pyoidc_keycloak.sync.users")


def test_deriving_a_username_never_logs_the_username(debug_logs):
    get_user_model().objects.create_user(username=UNAME)

    derived = derive_username(sentinel_user())

    assert derived.startswith(UNAME), "the derived name still comes from the representation"
    assert_clean(debug_logs, expect_records_from="django_pyoidc_keycloak.sync.usernames")


# -- groups -------------------------------------------------------------


def test_group_synchronisation_logs_paths_and_counts(debug_logs, connection):
    stub = mock.Mock()
    stub.connection = connection
    stub.list_groups.return_value = [{"id": str(uuid.uuid4()), "name": "staff", "path": "/staff"}]

    sync_groups(client=stub)

    assert "/staff" in debug_logs.text, "group paths are not personal data and are worth logging"
    assert_clean(debug_logs, expect_records_from="django_pyoidc_keycloak.sync.groups")


def test_membership_reconciliation_logs_without_the_user(debug_logs):
    user = get_user_model().objects.create_user(username=UNAME, email=EMAIL, keycloak_id=uuid.uuid4())

    apply_group_paths(user, ["/staff"])

    assert_clean(debug_logs, expect_records_from="django_pyoidc_keycloak.sync.groups")


# -- reconcile and events -----------------------------------------------


def test_a_full_reconcile_logs_progress_without_leaking(debug_logs, connection):
    stub = mock.Mock()
    stub.connection = connection
    stub.list_groups.return_value = []
    stub.get_user_groups.return_value = []
    stub.get_user_realm_roles.return_value = []
    stub.iter_users.return_value = iter([sentinel_user()])

    full_reconcile(client=stub, import_all=True)

    assert_clean(debug_logs, expect_records_from="django_pyoidc_keycloak.sync")


def test_polling_admin_events_logs_the_window_and_counts(debug_logs, connection):
    stub = mock.Mock()
    stub.connection = connection
    stub.get_admin_events.return_value = []

    poll_admin_events(client=stub)

    assert_clean(debug_logs, expect_records_from="django_pyoidc_keycloak.sync.events")


def test_an_unparseable_resource_path_is_reported(debug_logs, connection):
    """The TODO this replaced: a silent return was indistinguishable from a no-op."""
    stub = mock.Mock()
    stub.connection = connection
    stub.get_admin_events.return_value = [
        {"time": _now_ms(), "operationType": "UPDATE", "resourceType": "USER", "resourcePath": "nonsense"}
    ]

    poll_admin_events(client=stub)

    assert "no user id in its resourcePath" in debug_logs.text


def test_a_deletion_for_an_unknown_user_is_reported(debug_logs, connection):
    """The other TODO: normal when the account was never imported, but worth saying."""
    stub = mock.Mock()
    stub.connection = connection
    unknown = uuid.uuid4()
    stub.get_admin_events.return_value = [
        {
            "time": _now_ms(),
            "operationType": "DELETE",
            "resourceType": "USER",
            "resourcePath": f"users/{unknown}",
        }
    ]

    poll_admin_events(client=stub)

    assert "has no local row" in debug_logs.text


def test_syncing_a_named_set_of_users_logs_ids_only(debug_logs, connection):
    stub = mock.Mock()
    stub.connection = connection
    stub.get_user_groups.return_value = []
    stub.get_user_realm_roles.return_value = []
    stub.get_user.return_value = sentinel_user()
    user = get_user_model().objects.create_user(username=UNAME, email=EMAIL, keycloak_id=uuid.uuid4())

    sync_users([user], client=stub)

    assert_clean(debug_logs, expect_records_from="django_pyoidc_keycloak.sync")


# -- tokens -------------------------------------------------------------


def test_storing_tokens_logs_their_presence_not_their_value(debug_logs):
    user = get_user_model().objects.create_user(username=UNAME, keycloak_id=uuid.uuid4())
    session = OIDCSession.objects.create(
        state="s", sub=str(user.keycloak_id), cache_session_key="k", session_state="ss"
    )
    raw = RawTokens(
        access_token=ACCESS,
        refresh_token=REFRESH,
        id_token=IDTOK,
        access_token_expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
        scope="openid profile",
    )

    token_set = store_tokens(session=session, user=user, raw=raw, is_offline=False)

    assert token_set.access_token == ACCESS, "the token must still be stored, encrypted"
    assert_clean(debug_logs, expect_records_from="django_pyoidc_keycloak.tokens.store")


def test_looking_up_a_token_set_logs_the_pk_only(debug_logs):
    user = get_user_model().objects.create_user(username=UNAME, keycloak_id=uuid.uuid4())

    get_token_set(user)

    assert_clean(debug_logs, expect_records_from="django_pyoidc_keycloak.tokens.store")


def test_a_request_without_a_session_key_says_so(debug_logs):
    """Failing closed used to be silent, which reads exactly like a bug."""
    assert find_session(mock.Mock(session=None)) is None
    assert "no session key" in debug_logs.text


# -- the admin API client -----------------------------------------------


def test_the_admin_client_logs_the_request_but_not_the_bearer_token(debug_logs, connection):
    import httpx
    import respx

    from django_pyoidc_keycloak.admin_api.client import KeycloakAdminClient

    with respx.mock:
        respx.post(connection.token_endpoint).mock(
            return_value=httpx.Response(200, json={"access_token": ACCESS, "expires_in": 60})
        )
        respx.get(f"{connection.admin_base}/users/count").mock(return_value=httpx.Response(200, json=3))

        KeycloakAdminClient(connection).count_users()

    assert "/users/count -> 200" in debug_logs.text, "the URL and status are the useful part"
    assert_clean(debug_logs, expect_records_from="django_pyoidc_keycloak.admin_api")


def test_the_connection_is_logged_without_the_client_secret(debug_logs, settings):
    from django_pyoidc_keycloak.admin_api.provider import get_connection

    settings.KEYCLOAK = {**settings.KEYCLOAK, "ADMIN_CLIENT_SECRET": "SENTINEL-CLIENT-SECRET"}

    get_connection()

    assert "SENTINEL-CLIENT-SECRET" not in debug_logs.text
    assert "django-app" in debug_logs.text, "the client id is safe and identifies the config"
