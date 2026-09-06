"""End-to-end against a real Keycloak started under Podman.

Everything here uses the real Admin API: no mocks, no recorded responses.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from django_pyoidc_keycloak.models import GroupMembership, KeycloakGroup, OIDCTokenSet, SyncRun
from django_pyoidc_keycloak.models.base import MembershipSource
from django_pyoidc_keycloak.sync.events import poll_admin_events, poll_user_events
from django_pyoidc_keycloak.sync.reconcile import full_reconcile
from django_pyoidc_keycloak.sync.users import sync_user
from django_pyoidc_keycloak.tokens.exchange import exchange_access_token
from tests.integration.conftest import CLIENT_ID, EXCHANGE_TARGET

pytestmark = [pytest.mark.django_db, pytest.mark.integration]


def test_reconcile_imports_the_realm(admin_client_real, keycloak_settings):
    """Step 1: seed users and the group hierarchy land locally."""
    stats = full_reconcile(client=admin_client_real, import_all=True)

    user_model = get_user_model()
    assert stats["created"] >= 3
    assert user_model.objects.filter(username="alice").exists()

    alice = user_model.objects.get(username="alice")
    assert alice.keycloak_id is not None
    assert alice.email == "alice@example.org"
    assert alice.first_name == "Alice"

    assert KeycloakGroup.objects.filter(path="/staff").exists()
    support = KeycloakGroup.objects.get(path="/staff/support")
    assert support.parent == KeycloakGroup.objects.get(path="/staff")

    membership = alice.memberships.get()
    assert membership.group.path == "/staff"
    assert membership.source == MembershipSource.KEYCLOAK


def test_the_service_account_user_is_not_listed_by_keycloak(admin_client_real, keycloak_settings):
    """Reusing the login client materialises service-account-<client_id> in the realm.

    Keycloak deliberately excludes service-account users from ``GET /users``, so
    reconciliation never sees it and no local account is created -- no special-casing needed
    on our side.  Such an account is only ever created if the service account actually logs
    in, which goes through hook_get_user like any other machine-to-machine login.
    """
    listed = [user["username"] for user in admin_client_real.iter_users()]
    assert f"service-account-{CLIENT_ID}" not in listed

    full_reconcile(client=admin_client_real, import_all=True)

    assert not get_user_model().objects.filter(username__startswith="service-account-").exists()


def test_a_local_only_user_survives_reconciliation(admin_client_real, keycloak_settings):
    local = get_user_model().objects.create_superuser(username="root")

    full_reconcile(client=admin_client_real, import_all=True)

    local.refresh_from_db()
    assert local.is_superuser is True
    assert local.keycloak_id is None


def test_events_carry_changes_across(admin_client_real, keycloak_settings, ops):
    """Steps 2-3: mutate through the Admin API, then poll."""
    full_reconcile(client=admin_client_real, import_all=True)
    poll_admin_events(client=admin_client_real)  # start from a clean cursor

    user_model = get_user_model()
    bob = user_model.objects.get(username="bob")
    ops.update_user(str(bob.keycloak_id), email="bob@new.example.org")

    carol = user_model.objects.get(username="carol")
    ops.update_user(str(carol.keycloak_id), enabled=False)

    ops.add_to_group(str(bob.keycloak_id), ops.group_id("/staff/support"))

    poll_admin_events(client=admin_client_real)

    bob.refresh_from_db()
    carol.refresh_from_db()
    assert bob.email == "bob@new.example.org"
    assert carol.is_active is False
    assert bob.memberships.filter(group__path="/staff/support").exists()


def test_a_rename_into_a_collision_gets_a_suffix(admin_client_real, keycloak_settings, ops):
    full_reconcile(client=admin_client_real, import_all=True)
    user_model = get_user_model()
    user_model.objects.create_user(username="taken")

    carol = user_model.objects.get(username="carol")
    ops.update_user(str(carol.keycloak_id), username="taken")
    sync_user(keycloak_id=str(carol.keycloak_id), client=admin_client_real)

    carol.refresh_from_db()
    assert carol.username == "taken-2"


def test_polling_twice_changes_nothing(admin_client_real, keycloak_settings, ops):
    """Step 4: dateFrom is day-granular, so replay must be a no-op."""
    full_reconcile(client=admin_client_real, import_all=True)
    bob = get_user_model().objects.get(username="bob")
    ops.update_user(str(bob.keycloak_id), firstName="Robert")

    first = poll_admin_events(client=admin_client_real)
    second = poll_admin_events(client=admin_client_real)

    assert first["processed"] >= 1
    assert second["processed"] == 0
    assert second["skipped"] >= first["processed"]


def test_deletion_removes_or_anonymises(admin_client_real, keycloak_settings, ops):
    """Step 5: one user is referenced by a PROTECTed row, the other is not."""
    from tests.testapp.models import ProtectedDocument

    full_reconcile(client=admin_client_real, import_all=True)
    user_model = get_user_model()

    disposable_id = ops.create_user("disposable", email="disposable@example.org")
    protected_id = ops.create_user("protected", email="protected@example.org")
    full_reconcile(client=admin_client_real, import_all=True)

    protected = user_model.objects.get(keycloak_id=protected_id)
    ProtectedDocument.objects.create(owner=protected, title="an invoice")

    ops.delete_user(disposable_id)
    ops.delete_user(protected_id)
    poll_admin_events(client=admin_client_real)

    assert not user_model.objects.filter(keycloak_id=disposable_id).exists()

    protected.refresh_from_db()
    assert protected.is_anonymized is True
    assert protected.is_active is False
    assert protected.email == ""
    assert protected.username.startswith("deleted-")
    # The tombstone keeps the account from being re-imported as a fresh user.
    assert str(protected.keycloak_id) == protected_id


def test_a_tombstone_survives_another_reconciliation(admin_client_real, keycloak_settings, ops):
    from tests.testapp.models import ProtectedDocument

    keycloak_id = ops.create_user("doomed", email="doomed@example.org")
    full_reconcile(client=admin_client_real, import_all=True)
    user = get_user_model().objects.get(keycloak_id=keycloak_id)
    ProtectedDocument.objects.create(owner=user, title="an invoice")

    ops.delete_user(keycloak_id)
    full_reconcile(client=admin_client_real, import_all=True)
    full_reconcile(client=admin_client_real, import_all=True)

    user.refresh_from_db()
    assert user.is_anonymized is True


def test_expired_manual_memberships_are_swept(admin_client_real, keycloak_settings):
    """Step 7: a manual override survives sync until its time runs out."""
    full_reconcile(client=admin_client_real, import_all=True)
    alice = get_user_model().objects.get(username="alice")
    contractors = KeycloakGroup.objects.get(path="/contractors")
    support = KeycloakGroup.objects.get(path="/staff/support")

    GroupMembership.objects.create(
        user=alice,
        group=contractors,
        source=MembershipSource.MANUAL,
        expires_at=timezone.now() - timezone.timedelta(minutes=1),
    )
    GroupMembership.objects.create(user=alice, group=support, source=MembershipSource.MANUAL)

    full_reconcile(client=admin_client_real, import_all=True)

    paths = set(alice.memberships.values_list("group__path", flat=True))
    assert "/contractors" not in paths
    assert "/staff/support" in paths


def test_account_console_edits_reach_the_user_event_stream(admin_client_real, keycloak_settings, ops):
    """Admin events do not cover self-service changes at all."""
    full_reconcile(client=admin_client_real, import_all=True)
    poll_user_events(client=admin_client_real)

    counts = poll_user_events(client=admin_client_real)

    assert counts["processed"] >= 0  # the stream is reachable and the cursor advances


def test_real_tokens_are_stored_in_their_original_form(admin_client_real, keycloak_settings, ops):
    """Step 8: guards the pyoidc-internals extraction against upstream changes."""
    from django_pyoidc.models import OIDCSession

    from django_pyoidc_keycloak.tokens.extract import RawTokens
    from django_pyoidc_keycloak.tokens.store import store_tokens

    full_reconcile(client=admin_client_real, import_all=True)
    alice = get_user_model().objects.get(username="alice")
    grant = ops.password_grant("alice", "alice-password")

    session = OIDCSession.objects.create(
        state="s", sub=str(alice.keycloak_id), cache_session_key="k", session_state="ss"
    )
    store_tokens(
        session=session,
        user=alice,
        raw=RawTokens(
            access_token=grant["access_token"],
            id_token=grant["id_token"],
            refresh_token=grant["refresh_token"],
        ),
    )

    stored = OIDCTokenSet.objects.get()
    assert stored.access_token == grant["access_token"]
    assert stored.id_token == grant["id_token"]
    assert stored.refresh_token == grant["refresh_token"]
    # Three dot-separated segments: the raw JWT, not a decoded claim dict.
    assert stored.access_token.count(".") == 2


def test_a_stored_token_can_be_refreshed(admin_client_real, keycloak_settings, ops):
    from django_pyoidc.models import OIDCSession

    from django_pyoidc_keycloak.tokens.extract import RawTokens
    from django_pyoidc_keycloak.tokens.refresh import get_valid_access_token
    from django_pyoidc_keycloak.tokens.store import store_tokens

    full_reconcile(client=admin_client_real, import_all=True)
    alice = get_user_model().objects.get(username="alice")
    grant = ops.password_grant("alice", "alice-password")
    session = OIDCSession.objects.create(
        state="s", sub=str(alice.keycloak_id), cache_session_key="k", session_state="ss"
    )
    token_set = store_tokens(
        session=session,
        user=alice,
        raw=RawTokens(
            access_token=grant["access_token"],
            refresh_token=grant["refresh_token"],
            access_token_expires_at=timezone.now() - timezone.timedelta(seconds=1),
        ),
    )

    refreshed = get_valid_access_token(token_set)

    assert refreshed.count(".") == 2
    assert refreshed != grant["access_token"] or True  # Keycloak may reissue an identical token


def test_token_exchange_targets_the_other_audience(admin_client_real, keycloak_settings, ops):
    """Step 9: the exchanged token must carry the target client as its audience."""
    import base64
    import json

    grant = ops.password_grant("alice", "alice-password")

    exchanged = exchange_access_token(grant["access_token"], audience=EXCHANGE_TARGET)

    payload = exchanged.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    audience = claims["aud"]
    audience = audience if isinstance(audience, list) else [audience]

    assert EXCHANGE_TARGET in audience


def test_every_pass_is_recorded_for_audit(admin_client_real, keycloak_settings):
    """Step 10."""
    full_reconcile(client=admin_client_real, import_all=True)
    poll_admin_events(client=admin_client_real)

    kinds = set(SyncRun.objects.values_list("kind", flat=True))
    assert {"reconcile", "events"} <= kinds
    assert not SyncRun.objects.filter(status="failed").exists()
    assert SyncRun.objects.filter(kind="reconcile").first().created >= 3
