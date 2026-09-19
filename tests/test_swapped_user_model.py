"""A project that swaps AUTH_USER_MODEL must be able to migrate.

Regression test. Two things used to make this impossible:

* The library's migrations create GroupMembership, RoleAssignment and OIDCTokenSet with
  foreign keys to AUTH_USER_MODEL but declared no ``swappable_dependency``, so nothing
  ordered them after the project's own user. ``migrate`` died with
  "Related model 'testapp_swapped.user' cannot be resolved".
* Once that dependency existed, the user's ``groups`` / ``roles`` ManyToManyFields pointed
  back at those same through models, which is a genuine cycle:
  CircularDependencyError. They are properties now.

AUTH_USER_MODEL is read once at start-up, so this runs Django in a subprocess against
tests.testproject.settings_swapped rather than through override_settings.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def run_management_command(*args: str) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "DJANGO_SETTINGS_MODULE": "tests.testproject.settings_swapped",
        "PYTHONPATH": str(REPO_ROOT),
    }
    return subprocess.run(
        [sys.executable, "-m", "django", *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture(scope="module")
def generated_migrations() -> subprocess.CompletedProcess:
    """`makemigrations` for the swapping app, written into the real migrations package."""
    migrations_dir = REPO_ROOT / "tests" / "testapp_swapped" / "migrations"
    for path in migrations_dir.glob("0*.py"):
        path.unlink()
    try:
        yield run_management_command("makemigrations", "testapp_swapped")
    finally:
        for path in migrations_dir.glob("0*.py"):
            path.unlink()


def test_makemigrations_produces_a_single_migration(generated_migrations):
    """No hand-splitting: the whole user model fits in one initial migration."""
    assert generated_migrations.returncode == 0, generated_migrations.stderr
    written = sorted(p.name for p in (REPO_ROOT / "tests" / "testapp_swapped" / "migrations").glob("0*.py"))

    assert written == ["0001_initial.py"], generated_migrations.stdout


def test_migrate_applies_cleanly(generated_migrations):
    """The whole graph, library included, runs against an empty database."""
    assert generated_migrations.returncode == 0, generated_migrations.stderr

    result = run_management_command("migrate", "--no-input")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "cannot be resolved" not in result.stderr
    assert "CircularDependencyError" not in result.stderr


def test_the_admin_routes_follow_the_swapped_model(generated_migrations):
    """Regression test: the admin used to hard-code ``admin:keycloak_keycloakuser_*``.

    Under a swapped user model those routes are ``admin:testapp_swapped_user_*``, so the
    "Sync now" button and every redirect after it raised NoReverseMatch. The change_form
    template was looked up by app and model too, so it was never found either.
    """
    assert generated_migrations.returncode == 0, generated_migrations.stderr
    probe = (
        "from django.contrib import admin;"
        "from django.contrib.auth import get_user_model;"
        "from django.urls import reverse;"
        "a=admin.site._registry[get_user_model()];"
        "print('SYNC', reverse(a.admin_url_name('sync'), args=['1']));"
        "print('SYNCALL', a.admin_url('sync_all'));"
        "print('LIST', a.admin_url('changelist'));"
        "print('TPL', a.change_form_template, a.change_list_template)"
    )

    result = run_management_command("shell", "-c", probe)

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "SYNC /admin/testapp_swapped/user/1/sync/" in output, output
    assert "SYNCALL /admin/testapp_swapped/user/sync-all/" in output, output
    assert "LIST /admin/testapp_swapped/user/" in output, output
    # A fixed path, not admin/<app>/<model>/..., or it stops resolving when swapped.
    assert "TPL django_pyoidc_keycloak/change_form.html django_pyoidc_keycloak/change_list.html" in output, output
