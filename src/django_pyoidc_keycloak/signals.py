"""Extension points for the host application.

Every signal is sent with ``sender`` set to the model class involved.
"""

from __future__ import annotations

import django.dispatch

#: A local user was created from a Keycloak account. kwargs: user, representation
user_created = django.dispatch.Signal()

#: A local user was refreshed from Keycloak. kwargs: user, representation, changed_fields
user_synced = django.dispatch.Signal()

#: A user vanished from Keycloak and was removed locally. kwargs: keycloak_id, username
user_deleted = django.dispatch.Signal()

#: A user vanished from Keycloak but local data prevented deletion. kwargs: user
user_anonymized = django.dispatch.Signal()

#: A group was created or refreshed from Keycloak. kwargs: group, representation
group_synced = django.dispatch.Signal()

#: Group membership changed. kwargs: user, group, action ("added"/"removed"), source
membership_changed = django.dispatch.Signal()

#: A role was created or refreshed from Keycloak. kwargs: role, representation
role_synced = django.dispatch.Signal()

#: Role assignment changed. kwargs: user, role, action ("added"/"removed"), source
role_assignment_changed = django.dispatch.Signal()

#: A synchronisation pass ended, successfully or not. kwargs: sync_run
sync_run_finished = django.dispatch.Signal()
