# django-pyoidc-keycloak-extensions

Keycloak user, group and role synchronisation, encrypted token storage and RFC 8693 token exchange
for Django projects that authenticate through
[django-pyoidc](https://pypi.org/project/django-pyoidc/).

django-pyoidc handles the OIDC login flow and stops there. This library adds what a project
needs when Keycloak is the system of record:

* **Identity is the Keycloak UUID**, not an email address. Emails change and get reused.
* **There is no password column.** Keycloak is the only authenticator, so the field is
  removed rather than filled with a hash nothing ever reads.
* **Users stay in step with Keycloak** — renames, disables and deletions arrive through
  event polling, with full reconciliation as the correctness backstop.
* **Deleted accounts are removed, or anonymised** when local data still references them.
* **Groups and roles mirror Keycloak**, with temporary manual overrides an admin can grant.
  Realm roles and the OIDC client's roles are stored locally; `is_staff` and `is_superuser`
  are derived from client roles.
* **Login applies the ID token immediately**, unless a reconcile has produced newer data.
* **Permissions are never stored locally.** Every `has_perm` goes to your own authorization
  backend (Open Policy Agent, or whatever you use).
* **Raw tokens are stored encrypted**, refreshed lazily, and exchangeable for another audience.

## Requirements

* Python 3.14+, Django 5.2+, django-pyoidc 1.0.13+
* Keycloak 26.2+ for token exchange
* **A Redis server** as Django's default cache. The token-refresh lock needs it (see
  [Using the tokens](#using-the-tokens)), and no other cache backend will do.
  django-redis and redis-py are installed as dependencies; you run the Redis server yourself.
* **Celery 5.4+ (optional)**, installed through the `celery` extra. Without it, sync runs
  from cron and the admin's bulk actions run inline (see [Scheduling](#scheduling)).

## Installation

```bash
uv pip install django-pyoidc-keycloak-extensions            # core, needs Redis
uv pip install "django-pyoidc-keycloak-extensions[celery]"  # also installs Celery tasks
```

## Keycloak setup

This library reuses the client you already configured for django-pyoidc — there is no
separate service account to create. On that client:

1. **Client authentication: on** (it must be confidential).
2. **Service accounts roles: on.**
3. On the service-account user, assign these `realm-management` roles:
   `view-users`, `query-users`, `query-groups`, `view-events`, `view-realm`, `view-clients`.
4. In *Realm settings → Sessions/Events*, enable **admin events** and **user events** — event
   polling reads both, and neither is on by default.
5. For token exchange: switch on **Standard token exchange** on the client, and make sure the
   user holds a role on the target client so that audience is within your client's scope.
6. Create the client roles `app-staff` and `app-superuser` on the client (or change
   `STAFF_ROLES` / `SUPERUSER_ROLES`), plus whatever roles your policy reads.
7. Add three protocol mappers to the client so login can read membership and roles from the
   ID token without an Admin API call. Keycloak's default `roles` scope only puts roles in the
   access token; these copy them into the ID token and userinfo as well:

   | Mapper type | Claim | Setting |
   | --- | --- | --- |
   | Group Membership | `groups` | Full group path: on |
   | User Client Role | `resource_access.${client_id}.roles` | Multivalued: on |
   | User Realm Role | `realm_access.roles` | Multivalued: on |

   Enable *Add to ID token*, *Add to access token* and *Add to userinfo* on each. The exact
   JSON is in `tests/integration/realm-export.json`.

> This grants the browser-facing login client read access to the realm's user directory. A
> leaked client secret therefore exposes more than it would with a separate admin client — an
> accepted trade-off for a single set of credentials. Split them with
> `KEYCLOAK["ADMIN_CLIENT_ID"]` / `["ADMIN_CLIENT_SECRET"]` if you would rather not.

## Django setup

`AUTH_USER_MODEL` must be set **before the project's first migrate**. Changing it later means
a manual migration.

```python
INSTALLED_APPS = [
    ...,
    "django_pyoidc",
    "django_pyoidc_keycloak",
]

AUTH_USER_MODEL = "keycloak.KeycloakUser"

# The first backend resolves the logged-in user from the session on every request; the
# second decides every permission. ModelBackend must NOT be here: a system check rejects
# it, because it would answer has_perm() from the database.
AUTHENTICATION_BACKENDS = [
    "django_pyoidc_keycloak.backends.KeycloakSessionBackend",
    "myproject.authz.OPABackend",
]

SALT_KEY = env("SALT_KEY")  # token encryption; see "Token encryption" below

# Must be django-redis: token refresh locks through it (system check keycloak.E008).
# Use a trusted, access-controlled Redis; see "Security notes".
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": env("REDIS_URL"),  # e.g. "redis://redis:6379/0"
    }
}

DJANGO_PYOIDC = {
    "sso": {
        "client_id": "django-app",
        "client_secret": env("OIDC_CLIENT_SECRET"),
        "provider_class": "KeycloakProvider",
        "keycloak_base_uri": "https://sso.example.org",
        "keycloak_realm": "myrealm",
        "hook_get_user": "django_pyoidc_keycloak.hooks.get_user",
        "hook_user_login": "django_pyoidc_keycloak.hooks.user_login",
        "hook_user_logout": "django_pyoidc_keycloak.hooks.user_logout",
        "hook_session_logout": "django_pyoidc_keycloak.hooks.session_logout",
    }
}

KEYCLOAK = {
    "OP_NAME": "sso",
}
```

### Your authorization backend

Permissions only -- nothing about users:

```python
class OPABackend:
    def has_perm(self, user_obj, perm, obj=None): ...
    def has_module_perms(self, user_obj, app_label): ...
    def get_all_permissions(self, user_obj, obj=None):  # optional; the admin index uses it
        ...
```

Every configured backend is asked in turn, so your backend does not have to be the one the
session records.  In particular it needs no `get_user`: Django resolves the logged-in user
by calling `get_user()` on the backend stored in the session, and
`KeycloakSessionBackend` -- shipped with this library -- is what serves that request.  It
does the primary-key lookup and nothing else, so a deactivated or anonymised account stops
resolving to a session immediately, and no permission ever comes out of the database.

`is_superuser` short-circuits to `True` before your backend is consulted, and `is_staff`
gates admin access.

`KeycloakSessionBackend` must appear in `AUTHENTICATION_BACKENDS` (system check
`keycloak.E004`): `django.contrib.auth` ignores a session backend that is not listed there
and silently falls back to `AnonymousUser` on every request.  You may subclass it; the
library discovers it by type.

### Permissions your policy will be asked about

All of the form `<app_label>.<verb>_<model_name>`, so a swapped model changes both halves:

| Verb | Example | Meaning |
| --- | --- | --- |
| `view` / `add` / `change` / `delete` | `keycloak.change_keycloakuser` | Django's four, unchanged. |
| `sync` | `keycloak.sync_keycloakuser` | Pull this record from Keycloak now. |

`sync` is this library's own verb, and it is **independent of `change`** in both directions.
It is asked for per model, so `sync_keycloakuser`, `sync_keycloakgroup` and
`sync_keycloakrole` are separate grants.
Synchronising is neither reading nor editing: it pulls the record from the realm and, when
the account has gone, deletes or anonymises it locally.  So a policy can grant `sync`
without `change` -- an operator who may repair drift but not hand-edit fields -- or `change`
without `sync`, for someone who administers local-only accounts but must not trigger Admin
API traffic.  Without the verb neither the buttons nor the actions are rendered.

### What the admin offers

Users, groups and roles each have the same two, on top of the user page's "Sync now":

| Where | What |
| --- | --- |
| Changelist button | Synchronise **everything** of that kind, pruning what the realm no longer has. |
| Changelist button | **Full reconcile** of the realm — the same work as `manage.py keycloak_reconcile`. |
| Changelist action | Synchronise the **selected** rows only, leaving the rest alone. |

The reconcile button is realm-wide, so it appears on all three changelists and does more
than "synchronise everything": it also *imports* accounts that have never logged in (when
`IMPORT_ALL_USERS` is on), deletes or anonymises accounts Keycloak no longer has, sweeps
expired overrides, and records a `SyncRun`. Because it rewrites users, groups and roles
alike, it needs the `sync` verb on **all three** models — otherwise holding only
`sync_keycloakgroup` would start a pass that deletes user accounts.

Both buttons enqueue through Celery when it is configured, and run inline otherwise.

**Changed in 0.3.2:** "synchronise everything" is a button rather than a dropdown action.
Django's actions only run against a selection, so as an action it required ticking a row it
then ignored. Groups and roles gained both; before, they could only be synchronised by a
full `keycloak_reconcile`.

No `Permission` row is created for `sync` (none is created for anything -- see
`CREATE_DJANGO_PERMISSIONS`); the string is simply what your backend is asked about.

## Logging

Every module logs under its own name below `django_pyoidc_keycloak`, so the whole library
can be turned up at once:

```python
LOGGING = {
    "version": 1,
    "loggers": {
        "django_pyoidc_keycloak": {"level": "DEBUG", "handlers": ["console"]},
    },
}
```

| Level | What you get |
| --- | --- |
| `INFO` | Synchronisation runs and their counts, users deleted or anonymised, event cursors advancing, token sets dropped or purged. |
| `DEBUG` | Every decision behind those: the poll window, why an event was skipped, which fields a representation changed, each Admin API request and status, refresh-lock contention. |
| `WARNING` | Something was survivable but did not happen -- a role read that failed, tokens that could not be stored. |

**Nothing logged is a secret or personal data, at any level.** Tokens, client secrets and
passwords never reach a log record: HTTP response bodies are passed through `scrub()` before
they are rendered, and request payloads are never logged at all. Accounts are identified by
`keycloak_id` and local primary key, never by username, email or name; a Keycloak
representation is logged as its list of *keys*, and a change as its list of *field names*.
Group paths and role names are logged, since they are realm configuration rather than user data.

`tests/test_logging.py` enforces this with sentinel values, so it stays true.

## Scheduling

```cron
*/2 *  * * *  manage.py keycloak_sync_events    # incremental
17  *  * * *  manage.py keycloak_reconcile      # the correctness backstop
30  3  * * *  manage.py keycloak_purge_tokens   # expired tokens, memberships and role assignments
```

Both are needed. Admin events only cover changes made through the Admin API or console;
self-service edits land in the user event stream, LDAP-federated changes produce no events at
all, and events expire. `keycloak_reconcile` is what guarantees convergence.

With Celery installed, `django_pyoidc_keycloak.tasks` offers the same operations as tasks, and
the admin's bulk actions enqueue instead of blocking the request.

## Token encryption

Tokens are stored in Fernet-encrypted columns via `django-fernet-encrypted-fields`, which
derives its key from `SECRET_KEY` **and** `SALT_KEY`. Set `SALT_KEY` to a long random value
kept out of version control. Rotating `SECRET_KEY` without listing the old value in
`SECRET_KEY_FALLBACKS` makes existing tokens unreadable — they are session-scoped and
disposable, so the library logs a warning and treats them as absent rather than erroring.

Tokens are at rest in exactly one place: those columns. Never the cache, the session, a log
line, or an admin page.

## Using the tokens

```python
from django_pyoidc_keycloak.tokens.refresh import get_access_token_for_user
from django_pyoidc_keycloak.tokens.exchange import exchange_token

token = get_access_token_for_user(request.user)          # refreshed if near expiry
downstream = exchange_token(request.user, audience="reports-api")
```

Refresh is lazy and on demand, never scheduled: refreshing on a timer resets Keycloak's SSO
Session Idle clock (defeating idle timeout), is still capped by SSO Session Max, and races
the user's own browser refresh, which trips reuse detection when rotation is on. For work while
the user is away, set `KEYCLOAK["REQUEST_OFFLINE_ACCESS"] = True` to obtain an offline token,
which is exempt from SSO Session Max.

Concurrent refreshes are serialised by a distributed lock served through
[django-redis](https://github.com/jazzband/django-redis) — redis-py's `Lock`, acquired with
`SET NX PX` and released by a token-checked Lua script, so a worker whose lock expired can
never release the next worker's. This is why django-redis is a mandatory dependency and
`CACHES["default"]` must point at `django_redis.cache.RedisCache`; a system check
(`keycloak.E008`) enforces it at start-up.

## Groups and roles

Keycloak's group tree, its realm roles and the roles of your OIDC client are mirrored into
`KeycloakGroup` and `KeycloakRole`, and a user's membership and assignments into the
`GroupMembership` and `RoleAssignment` through models. Both through models carry a `source`:
`keycloak` rows are added and removed by synchronisation to match the realm exactly, `manual`
rows are an admin override that survives synchronisation until `expires_at` passes.

```python
request.user.active_groups()                       # unexpired memberships
request.user.active_roles()                        # unexpired assignments
request.user.has_role("feature1-editor", "django-app")
request.user.has_role("app-admin")                 # client_id="" is a realm role

request.user.groups                                # every group, expiry included
request.user.roles                                 # every role, expiry included
group.users                                        # and back the other way
```

**Changed in 0.3.1:** `user.groups` and `user.roles` (and `group.users` / `role.users`) are
read-only properties returning a queryset, not ManyToManyFields. Every read works as before;
`.add()` and `.set()` are gone, but a `through` model with extra columns never allowed them
anyway. They became properties so that the user model does not depend on the very models that
point back at it — see *Your own user model*.

Roles are stored *effective*: composites are expanded, both when read from the Admin API and
in tokens, so the two paths agree. Other clients' roles are ignored unless you list them in
`KEYCLOAK["ROLE_CLIENTS"]`; Keycloak's built-in `realm-management`, `account` and `broker`
roles never reach the local table by default.

`is_staff` and `is_superuser` are derived from role references in `STAFF_ROLES` and
`SUPERUSER_ROLES`. A bare name is a role on the OIDC client, `realm:name` a realm role, and
`other-client:name` a role on a client that is also in `ROLE_CLIENTS`. The defaults are the
client roles `app-staff` and `app-superuser`. An empty list leaves that flag for you to manage
by hand.

### Login versus reconcile

At login the `groups`, `realm_access` and `resource_access` claims are applied immediately,
so a user sees a change in Keycloak on their next sign-in without waiting for a sync. But a
token is only as fresh as its `iat`, and a reconcile or event poll may have run since. The user
row records `authorization_synced_at`: Admin API synchronisation stamps it with the read time,
a login stamps it with the token's `iat`, and a login whose token predates the stamp leaves
groups, roles and the staff flags alone. A claim that is missing altogether falls back to the
Admin API for that kind of data; a present-but-empty claim means "no roles".

### Your own user model

`AUTH_USER_MODEL = "keycloak.KeycloakUser"` is the shortcut. A project that expects to add
fields to the user should subclass the abstract model instead, from the start — Django cannot
change `AUTH_USER_MODEL` after the first migrate without a hand-written migration:

```python
# accounts/models.py
from django_pyoidc_keycloak.models import AbstractKeycloakUser


class User(AbstractKeycloakUser):
    department = models.CharField(max_length=100, blank=True)

    class Meta(AbstractKeycloakUser.Meta):
        abstract = False
        swappable = "AUTH_USER_MODEL"
```

```python
AUTH_USER_MODEL = "accounts.User"
```

`manage.py makemigrations` then writes one ordinary initial migration and `migrate` applies
it; nothing else is needed, and the admin follows the swapped model by itself. Only the user
is swapped here — the group, role, membership and role-assignment models stay this library's,
because swapping one means owning its migrations too.

**Changed in 0.3.1.** Before that release this did not work at all: the library's migrations
referenced `AUTH_USER_MODEL` without declaring a `swappable_dependency` (so `migrate` failed
with *Related model 'accounts.user' cannot be resolved*), the user's `groups` / `roles`
many-to-many fields made the dependency circular once that was fixed, and the admin
registration was silently dropped for a swapped-out model (`admin.E039` on the inlines).

### Your own model base

Every domain model (user, group, membership, role, assignment) inherits from the abstract
model named by `KEYCLOAK_MODEL_BASE`, which supplies the UUID primary key and `created_at` /
`updated_at`. Point it at your own abstract model to add soft deletion, history or a manager
to all of them at once. If your base adds *fields*, you must also subclass the abstract models
in your own app, point `AUTH_USER_MODEL` and the `KEYCLOAK_*_MODEL` settings at them and own
their migrations; system check `keycloak.E009` refuses to start otherwise, because the
library's migrations know nothing about your columns.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `OP_NAME` | auto | Which `DJANGO_PYOIDC` provider to use; required if several are configured. |
| `SERVER_URL` / `REALM` | from django-pyoidc | Override the derived Keycloak location. |
| `ADMIN_CLIENT_ID` / `ADMIN_CLIENT_SECRET` | from django-pyoidc | Use a separate admin client. |
| `IMPORT_ALL_USERS` | `False` | Create local users for accounts that never logged in. |
| `SYNC_ON_LOGIN` | `True` | Refresh the user from claims at each login. |
| `SYNC_GROUPS` | `True` | Mirror group membership. |
| `SYNC_ROLES` | `True` | Mirror realm and client roles and their assignments. |
| `ROLE_CLIENTS` | the OIDC client | Which clients' roles are mirrored, by `clientId`. Realm roles always are. |
| `USERNAME_STRATEGY` | built-in | Dotted path to your own username derivation. |
| `STAFF_ROLES` / `SUPERUSER_ROLES` | `["app-staff"]` / `["app-superuser"]` | Role references that map to `is_staff` / `is_superuser`: a bare name is a client role on the OIDC client, `realm:name` a realm role. **Changed in 0.3:** realm roles now need the `realm:` prefix. |
| `CREATE_DJANGO_PERMISSIONS` | `False` | Let Django populate `auth_permission` again. |
| `STORE_TOKENS` | `True` | Store raw tokens at login. |
| `REQUEST_OFFLINE_ACCESS` | `False` | Request `offline_access` scope. |
| `TOKEN_EXCHANGE_ENABLED` | `False` | Enables token exchange; the call refuses while off. |
| `ADMIN_BULK_INLINE_LIMIT` | `50` | Cap on synchronising inline from the admin without Celery. |
| `EVENT_OVERLAP_SECONDS` | `300` | How far back each event poll re-reads. |

Top-level Django settings, not under `KEYCLOAK`:

| Setting | Default | Meaning |
| --- | --- | --- |
| `KEYCLOAK_GROUP_MODEL` / `KEYCLOAK_MEMBERSHIP_MODEL` | `keycloak.KeycloakGroup` / `keycloak.GroupMembership` | Swap in your own concrete models. |
| `KEYCLOAK_ROLE_MODEL` / `KEYCLOAK_ROLE_ASSIGNMENT_MODEL` | `keycloak.KeycloakRole` / `keycloak.RoleAssignment` | Likewise for roles. |
| `KEYCLOAK_MODEL_BASE` | `django_pyoidc_keycloak.models.base.KeycloakModelBase` | Abstract base of every domain model (see above). |

## Security notes

**The Django cache must be trusted storage.** django-pyoidc stores its pyoidc state in the
cache and reads it back with `jsonpickle.decode` (upstream marks this `noqa: S301`), so
anyone who can write to that cache can execute code in your process on the next decode. Do
not point `CACHES["default"]` at a Redis or memcached instance shared with less-trusted
components, and keep it authenticated and network-isolated.

**Group and role mappers must derive from actual membership and role mappings.** At login,
membership and roles are read from the `groups`, `realm_access` and `resource_access` claims
when present, and `is_staff` / `is_superuser` follow. This library only ever grants groups
and roles Keycloak owns — a locally created group or role can never be reached through a
claim — but if you configure a mapper over a user-editable attribute, a user controls their
own claim content, and with it the staff flags.

**Token encryption uses PBKDF2-SHA256 at 100 000 iterations**, which is what
`django-fernet-encrypted-fields` does and is below OWASP's current 600k guidance. Session
tokens are short-lived, so this is minor; weigh it if you enable `REQUEST_OFFLINE_ACCESS`,
since offline tokens live much longer.

**`django-pyoidc` has no upper version bound.** It holds the actual OIDC request paths, so
pin it in your own project and read its release notes before upgrading.

## Notes on behaviour worth knowing

* **No user has a password.** `AbstractKeycloakUser` removes the `password` column Django's
  `AbstractBaseUser` provides, so there is no local credential to leak, rotate or brute-force,
  and no authentication path that goes around Keycloak. `set_password()` raises,
  `check_password()` is always `False`, and `createsuperuser` neither prompts for nor stores
  one (Django skips the prompt when the field is absent). A bootstrap superuser still works:
  it is unmanaged, and gets a session through `manage.py shell` or `force_login`.
  `get_session_auth_hash()` hashes the account's identity instead of the password, so
  sessions still work; they are ended by Keycloak's backchannel logout and by
  `KeycloakSessionBackend` refusing a deactivated or anonymised account.
  **Changed in 0.3.1:** the column used to exist, holding an unusable hash.
* **Local-only users are never touched.** A user with `keycloak_id = NULL` (your bootstrap
  superuser, for instance) survives every reconciliation.
* **Anonymisation keeps a tombstone.** `keycloak_id` is retained so a deleted Keycloak account
  is never re-imported as a fresh user.
* **Service-account users are not imported.** Keycloak excludes them from `GET /users`, so
  reconciliation never sees them; one is only created if it actually logs in.
* **Inactive users have no permissions.** `has_perm` returns `False` for `is_active=False`
  before any backend is consulted, so disabling an account in Keycloak revokes access as soon
  as sync notices, without waiting for your policy engine.
* **Two empty tables remain.** `django.contrib.auth` cannot be removed from `INSTALLED_APPS`,
  so `auth_permission` and `auth_group` exist. This library never reads or writes them, and
  permission creation is disconnected so they stay empty.

## Development

```bash
uv sync --extra dev --extra celery
uv run pytest                  # unit tests
uv run pytest -m integration   # against a real Keycloak in Podman
```

The integration suite starts `quay.io/keycloak/keycloak:26.4` through Podman's socket, imports
a realm, and drives the full cycle: reconcile, mutate, poll, delete, refresh, exchange. It
skips itself if Podman is not installed.

The unit suite starts its own throwaway `redis:7-alpine` container through the same Podman
socket and points the cache at it. You do not need a Redis running locally. Without Podman
it falls back to a local-memory cache and skips the tests marked `redis`.

## Releasing

Publishing runs on GitHub Actions (`.github/workflows/publish.yml`) using PyPI **Trusted
Publishing**, so there is no API token in repository secrets.

One-time setup:

1. On PyPI, add a *pending publisher* under the project's *Publishing* settings — owner
   `phi1010`, repository `django-pyoidc-keycloak-extensions`, workflow `publish.yml`,
   environment `pypi`. Repeat on TestPyPI with environment `testpypi` if you want a dry run.
2. In the repository settings, create the `pypi` (and optionally `testpypi`) environments.
   Adding required reviewers there puts a manual gate between the release and the upload.

To release:

1. Bump `version` in `pyproject.toml` and commit.
2. Tag and push: `git tag v0.2.0 && git push --tags`.
3. Publish a GitHub Release for that tag.

The workflow re-runs lint, the unit tests and the migration check, refuses to publish if the
tag and `pyproject.toml` disagree on the version, verifies the wheel actually contains the
admin templates and migrations, uploads to PyPI, and attaches the artefacts to the release.

`workflow_dispatch` publishes to TestPyPI by default, for rehearsing a release without
burning a version number — PyPI uploads are immutable and a version can never be reused.
