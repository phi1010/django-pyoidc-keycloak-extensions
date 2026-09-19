"""Removes the user's password column and the groups/roles many-to-many fields.

``password``
    Keycloak is the only authenticator. Every code path already stored an unusable hash, so
    nothing is lost -- a column that is never read is still one to migrate, dump and back up.
    Projects with a local bootstrap superuser lose nothing either: it never had a usable
    password, and it gets a session through ``manage.py shell`` or ``force_login``.

``groups`` / ``roles``
    State-only. A ManyToManyField with an explicit ``through`` has no table of its own, so
    dropping the field touches nothing in the database; GroupMembership and RoleAssignment,
    which hold the data, are untouched. They are gone because they made this app's user model
    depend on models that point back at AUTH_USER_MODEL, which is a circular migration
    dependency for any project that swaps in its own user. Reads still work: both are now
    properties returning the same queryset (see KeycloakAuthorizationMixin).
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("keycloak", "0003_roles_and_model_base"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="keycloakuser",
            name="password",
        ),
        migrations.RemoveField(
            model_name="keycloakuser",
            name="groups",
        ),
        migrations.RemoveField(
            model_name="keycloakuser",
            name="roles",
        ),
    ]
