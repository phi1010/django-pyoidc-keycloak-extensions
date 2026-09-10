# django-pyoidc-keycloak-extensions

## Context

The repository is empty (no commits, only `pyproject.toml` and `.idea/`). We are building a
reusable Django library on top of `django-pyoidc` (verified: v1.0.13, `Requires-Python >=3.10`,
`django>=5.2`, classifiers for Django 5.2/6.0 and Python 3.14 — compatible with this project's
`requires-python = ">=3.14"`).

`django-pyoidc` handles the OIDC login flow but stops there: its default user resolution is
`get_user_by_email(tokens)` (`django_pyoidc/__init__.py`), it stores nothing but an `OIDCSession`
row, and it has no notion of Keycloak as a system of record. The gap this library fills:

1. Keycloak is the source of truth for user data, but Django only ever learns about a user at
   login, and never learns that a user was renamed, disabled, or deleted.
2. Identity should be the Keycloak UUID, not an email address (emails change and are reusable).
3. Django's built-in `auth.Group` is the wrong grouping primitive here — groups should mirror
   Keycloak groups, with a documented escape hatch for temporary manual overrides.
4. Raw OIDC tokens are discarded, so the app cannot act on the user's behalf against other
   services (token exchange).

### Integration seams in django-pyoidc (read from the 1.0.13 wheel)

- `hook_get_user(client, tokens)` — per-provider setting, replaces `get_user_by_email`. This is
  where we resolve/create a user by the `sub` claim. Called from `OIDCEngine.call_get_user_function`
  (`engine.py:33`).
- **What `tokens` actually contains** (built at `views.py:399-407`, verified by reading the source):
  `{"info_token_claims": …, "access_token_jwt": …, "access_token_claims": …, "id_token_claims": …}`.
  So the raw **access token JWT is available**, but the raw **ID token JWT is not** — django-pyoidc
  decodes it to claims and leaves `id_token_jwt` commented out (`views.py:396-398`) — and the
  **refresh token is not passed at all**. Both are reachable from the `client` argument:
  `client.consumer` is a pyoidc `Consumer` (`client.py:42`) whose grant DB holds the full token
  object (`refresh_token`, `id_token_jwt`) for the current `state`. Getting the ID token and
  refresh token in original form therefore means reading them off `client.consumer`, not off
  `tokens`. This is the single riskiest integration point in the library: pin it with a test that
  fails loudly if the consumer's internals move, and keep the extraction isolated in one function.
- **Hook ordering matters for token storage.** `hook_get_user` runs *before* the `OIDCSession` row
  is created (`views.py:420`), so nothing at that point can FK to a session.
  `hook_user_login(request, user)` runs *after* it (`views.py:426`) but receives no tokens.
- `hook_user_login(request, user)` (`views.py:66`), `hook_user_logout(user_request, logout_request_args)`
  (`views.py:79`), `hook_session_logout(session)` (`views.py:288`) — our sync and token-purge triggers.
- Hooks are dotted paths resolved via `import_object` in `OIDCEngine.call_function`.
- `django_pyoidc.models.OIDCSession` (`state`, `session_state`, `sub`, `cache_session_key`) — the
  natural FK target for session-scoped token storage.
- `django_pyoidc.providers.keycloak*.Keycloak18Provider` — provider config we reuse for the
  Keycloak base URL and realm rather than duplicating settings.

### Decisions already made with the user

| Question | Decision |
|---|---|
| Identity | `uuid4` PK + unique nullable `keycloak_id`; users without `keycloak_id` are *unmanaged* and never touched by sync |
| Groups | Own UUID group model mirroring Keycloak groups; `auth.Group` unregistered from admin; manual membership overrides supported and *temporary* |
| Sync triggers | Management commands (cron) + optional Celery extra + on-login refresh via `hook_get_user` |
| Import users who never logged in | Optional, behind a setting (default off) |
| Model shape | Both — abstract bases plus ready-to-use concrete models |
| Token storage | Encrypted via `django-fernet-encrypted-fields` (verified maintained: 0.4.0, 2026-04) |
| Token retention | Session-scoped; purged at logout / backchannel logout / session expiry |
| Background refresh | Lazy, on-demand refresh; `offline_access` requested only when a setting enables it |

### Out of scope

**No Django REST Framework integration.** No DRF extra, no authentication class, no serializers.
django-pyoidc ships its own `django_pyoidc.drf` package for projects that need bearer-token
authentication; this library stays session/admin-oriented and leaves DRF to it. The public API is
plain Python functions (`sync_user`, `get_valid_access_token`, `exchange_token`) that a DRF view can
call if a project wants to, but nothing here imports or depends on `rest_framework`.

### Two facts that shape the design

**Keycloak admin events are not sufficient on their own.** They only capture changes made through
the Admin API/console; self-service account-console edits appear in the separate *user* events
endpoint, and LDAP-federated changes and deletions emit nothing at all. They must be enabled per
realm and they expire. Therefore the design is *event polling for latency* plus *periodic full
reconciliation for correctness*. Events are treated as triggers only — we always re-read
`/users/{id}` rather than trusting the event's `representation` blob, which also makes replay
idempotent (the admin-events `dateFrom` filter is day-granular).

**Background token refresh on a timer is the wrong tool** (discussed with the user): it resets
Keycloak's *SSO Session Idle* timer, defeating idle timeout; it is still hard-capped by *SSO
Session Max*; and with refresh-token rotation enabled it races the user's own browser refresh and
can trip reuse detection, killing the session. Instead: refresh lazily when a token is actually
needed and near expiry, and offer `offline_access` (exempt from SSO Session Max) as the opt-in
mechanism for genuinely away-from-keyboard work.

**Concurrency control is a cache mutex, not `select_for_update`.** Under ASGI a row lock would pin
a DB transaction open across the HTTP round-trip to Keycloak. `cache.add()` is an atomic
test-and-set that works identically in sync and async contexts, and Django 5.2's `cache.aadd()` /
async ORM methods give a genuinely async path.

---

## Package layout

Distribution `django-pyoidc-keycloak-extensions`, importable package `django_pyoidc_keycloak`,
Django app label `keycloak`.

```
src/django_pyoidc_keycloak/
    apps.py                 # KeycloakConfig; checks (system checks for misconfiguration)
    conf.py                 # AppSettings object with defaults + validation
    models/
        base.py             # AbstractKeycloakUser, AbstractKeycloakGroup, AbstractGroupMembership
        concrete.py         # KeycloakUser, KeycloakGroup, GroupMembership
        sync.py             # SyncRun, SyncCursor
        tokens.py           # OIDCTokenSet
    backends.py             # KeycloakSessionBackend (session resolution, no permissions)
    permissions.py          # KeycloakAuthorizationMixin, AuthorizationBackendProtocol
    managers.py             # KeycloakUserManager
    admin_api/
        client.py           # KeycloakAdminClient (client_credentials, django-pyoidc's client)
        exceptions.py
    sync/
        users.py            # sync_user, sync_all_users, delete_or_anonymize
        groups.py           # sync_groups, sync_user_groups
        events.py           # poll_admin_events, poll_user_events
        reconcile.py        # full_reconcile
        usernames.py        # username derivation + collision strategy
    tokens/
        extract.py          # extract_raw_tokens(client, tokens) - the only pyoidc-internals touch
        fields.py           # encrypted field wiring
        store.py            # store_tokens, purge_tokens
        refresh.py          # get_valid_access_token (cache mutex)
        exchange.py         # exchange_token
    hooks.py                # hook_get_user, hook_user_login, hook_user_logout, hook_session_logout
    signals.py
    admin.py
    tasks.py                # Celery tasks, imported only if celery installed
    management/commands/
        keycloak_sync_events.py
        keycloak_reconcile.py
        keycloak_sync_user.py
        keycloak_purge_tokens.py
    migrations/
```

`pyproject.toml`: dependencies `django>=5.2`, `django-pyoidc>=1.0.13`, `httpx`,
`django-fernet-encrypted-fields`. Extras: `celery`, `dev` (pytest, pytest-django,
pytest-asyncio, respx, testcontainers, ruff, mypy, django-stubs). Integration tests run the
Keycloak container under **Podman** — see Verification.

---

## Models

### `AbstractKeycloakUser` (`models/base.py`)

Extends `AbstractBaseUser` + our own `KeycloakAuthorizationMixin` (**not** Django's
`PermissionsMixin`, which would bring both the `auth.Group` M2M and a `user_permissions` M2M into
the database).

- `id = UUIDField(primary_key=True, default=uuid4, editable=False)`
- `keycloak_id = UUIDField(unique=True, null=True, blank=True, db_index=True)` — `None` marks an
  *unmanaged* local account (bootstrap superuser, service accounts); reconciliation must never
  delete or anonymize these.
- `username` (`USERNAME_FIELD`, unique, 150 chars), `email`, `first_name`, `last_name`
- `is_active` ← Keycloak `enabled`; `is_staff`, `is_superuser` (both retained and meaningful —
  `is_staff` gates admin access, `is_superuser` short-circuits `has_perm` to `True`)
- **no** `user_permissions` M2M — permissions are never stored locally
- `email_verified` ← `emailVerified`
- `date_joined` ← `createdTimestamp`
- `keycloak_attributes = JSONField(default=dict, blank=True)` — raw KC custom attributes
- `last_synced_at`, `is_anonymized = BooleanField(default=False)`
- `objects = KeycloakUserManager()`

Concrete `KeycloakUser` in `models/concrete.py`; projects that need extra fields subclass the
abstract base instead. `AUTH_USER_MODEL` must be set before the project's first migrate — document
this prominently.

### Groups

`AbstractKeycloakGroup`: UUID PK, `keycloak_id` (unique, nullable — nullable so admins can create
purely local groups), `name`, `path` (KC group path, unique per realm), `parent` self-FK for the
Keycloak group hierarchy, `last_synced_at`. **No `permissions` M2M** — a group is pure membership
metadata that the authorization backend reads; it grants nothing by itself.

`AbstractGroupMembership` (explicit through model — this is what makes "temporary manual
manipulation" expressible):

- `user` FK, `group` FK
- `source = CharField(choices=["keycloak", "manual"])`
- `expires_at = DateTimeField(null=True, blank=True)` — a manual membership may be time-boxed
- `created_by`, `created_at`, `note`
- `unique_together (user, group)`

Reconciliation rules: KC group membership is authoritative for `source="keycloak"` rows — they are
added and removed to match Keycloak exactly. `source="manual"` rows are preserved by sync and only
removed when `expires_at` passes (swept by the reconcile command and by a Celery beat task).
The `active_groups()` helper excludes expired memberships and is what the authorization backend
should consult.

### Authorization: no stored permissions (`permissions.py`)

Permissions are decided entirely by the project's own Open Policy Agent authorization backend via
`has_perm`. This library stores **no** permission data: no `user_permissions` M2M, no group
`permissions` M2M, no `auth.Group` rows, and no assignment UI.

`KeycloakAuthorizationMixin` provides the fields and API the admin and the project's code need,
without any permission storage:

- Fields: `is_superuser`, plus `groups = M2M(KEYCLOAK_GROUP_MODEL, through=GroupMembership,
  related_name="users")`. (`is_staff` and `is_active` live on the user model itself.)
- Methods mirroring `PermissionsMixin`'s *delegating* half only —
  `has_perm(perm, obj=None)`, `has_perms(perm_list, obj=None)`, `has_module_perms(app_label)`,
  `get_all_permissions(obj=None)` — each looping over `django.contrib.auth.get_backends()` exactly
  as `_user_has_perm` does, so the OPA backend is the sole decision point.
- The superuser short-circuit is preserved: `is_active and is_superuser` ⇒ `has_perm` returns
  `True` without consulting any backend. Same for `has_module_perms`.
- Deliberately **absent**: `get_group_permissions`, `get_user_permissions`, `user_permissions`.

**What the project's OPA backend must implement** (documented contract, with an
`AuthorizationBackendProtocol` typing protocol shipped for reference):
`has_perm(user_obj, perm, obj=None)`, `has_module_perms(user_obj, app_label)`, and optionally
`get_all_permissions(user_obj, obj=None)` (the admin's index page and some third-party apps call
it). Authorization only — a policy engine is never asked to handle users.

`django.contrib.auth.models.ModelBackend` is **not** used and should not appear in
`AUTHENTICATION_BACKENDS`; a system check errors if it does, since its presence would silently
reintroduce database-backed permission lookups.

**Session resolution is a separate backend** (`backends.py`). Django's session stores only the
user's primary key plus the dotted path of the backend that logged it in, and
`django.contrib.auth.get_user()` calls `get_user(user_id)` on *that* backend to rebuild the
instance. Upstream django-pyoidc offloads this to `ModelBackend`, which is exactly what we
forbid — so the library ships `KeycloakSessionBackend`: a primary-key lookup filtered on
`is_active` (which also excludes anonymised tombstones), `authenticate()` returning `None`, and
no permission methods at all. `hook_get_user` stamps its path on `user.backend` before
`auth.login()`, discovering it from `AUTHENTICATION_BACKENDS` by type so that subclasses work and
the recorded string is byte-for-byte a configured entry — `auth.get_user()` compares against that
list and silently returns `AnonymousUser` when the path is not in it. A system check
(`keycloak.E004`) errors when no such backend is configured, since the failure is otherwise
invisible.

### Keeping permission rows out of the database

`django.contrib.auth` cannot be removed from `INSTALLED_APPS` — it provides the auth machinery,
`get_user_model`, the login/session plumbing and admin integration — so its `auth_permission` and
`auth_group` tables are created by its migrations regardless. What we can and do suppress is their
*population and exposure*:

- `apps.py` disconnects `django.contrib.auth.management.create_permissions` from `post_migrate`
  (opt-out via `KEYCLOAK["CREATE_DJANGO_PERMISSIONS"]`, default `False`), so no `Permission` rows
  are ever generated for any model.
- `admin.py` calls `admin.site.unregister(Group)` inside `try/except NotRegistered` at import time,
  so native groups vanish from the admin entirely.
- No admin UI anywhere exposes permission selection.

The admin adds one verb of its own, `sync` (`<app_label>.sync_<model_name>`, derived per model
by `SyncPermissionMixin` so a swapped user model gets the verb on itself). It gates the "Sync
now" button, `sync_single_view`, and both changelist actions, and is deliberately independent
of `change`: synchronisation pulls from the realm and may delete or anonymise the local row, so
a policy has reason to grant either verb without the other. Custom admin actions are *not*
permission-checked by default -- only `delete_selected` is -- so the actions declare
`permissions=["sync"]`, which makes Django withhold them from the dropdown. No `Permission` row
is declared for it: `Meta.permissions` on an abstract model cannot parameterise the codename by
subclass, so a project with a swapped model would get a row naming the wrong one.

The README states plainly that two empty legacy tables remain as an artifact of `contrib.auth`'s
migrations, and that they are never read or written by this library.

### `SyncRun` / `SyncCursor` (`models/sync.py`)

`SyncRun`: `kind` (`events` | `reconcile` | `manual`), `realm`, `started_at`, `finished_at`,
`status`, counters (`created`, `updated`, `deleted`, `anonymized`, `errors`), `error_detail` text.
Read-only in the admin — the audit trail for "why did this user change".

`SyncCursor`: one row per realm+stream, holding the last processed event timestamp and a set of
recently-seen event ids for dedupe (the admin-events `dateFrom` filter is day-granular).

### `OIDCTokenSet` (`models/tokens.py`)

Session-scoped, per the retention decision.

- `session = OneToOneField("django_pyoidc.OIDCSession", on_delete=CASCADE, related_name="token_set")`
- `user = FK(AUTH_USER_MODEL, on_delete=CASCADE, related_name="token_sets")`
- `access_token = EncryptedTextField()`, `id_token = EncryptedTextField()`,
  `refresh_token = EncryptedTextField(null=True)` — from `django-fernet-encrypted-fields`
- `access_token_expires_at`, `refresh_token_expires_at`, `is_offline = BooleanField(default=False)`
- `scope`, `created_at`, `updated_at`

Key material from a dedicated `SALT_KEY` / encryption key setting, **not** `SECRET_KEY` — document
that rotating `SECRET_KEY` must not silently destroy tokens, and that Fernet's `MultiFernet`
supports key rotation.

---

## Keycloak Admin API client (`admin_api/client.py`)

`KeycloakAdminClient` using `httpx` with both sync and async methods:

- Auth: `client_credentials` against `{server_url}/realms/{realm}/protocol/openid-connect/token`
  **reusing django-pyoidc's existing `client_id` / `client_secret`** from the provider settings
  (`OIDCSettings.get("client_id")` / `("client_secret")`, as read in `client.py:28-29`). There is no
  separate admin client: the same confidential client that users log in through also holds the
  service account used for Admin API calls. Optional `ADMIN_CLIENT_ID` / `ADMIN_CLIENT_SECRET`
  overrides exist for deployments that later want to split them, but they are unset by default.

  Keycloak-side prerequisites, to document: the login client must be **confidential** (client
  authentication on) and have **Service accounts roles enabled**; the `realm-management` roles below
  are then assigned to that client's service-account user. Worth stating plainly in the README:
  this grants the browser-facing login client read access to the realm's user directory, so a
  leaked client secret exposes more than it would with a split client — an accepted, documented
  trade-off in exchange for a single set of credentials.
- **The service-account access token is never written to the Django cache.** The cache backend is
  typically Redis or memcached — unauthenticated by default, plaintext on the wire, shared across
  processes, often dumped to disk or a monitoring tool — so a token there is a bearer credential
  for the whole realm's user data sitting in cleartext outside the database. It is held **in
  memory on the client instance only**, in a private attribute, refreshed when within ~30s of
  expiry, guarded by a `threading.Lock` (plus an `asyncio.Lock` for the async client) so
  concurrent callers issue one token request. Cost of not sharing it across processes is one extra
  token request per worker per token lifetime, which is negligible.
- `__repr__`/`__str__` never include the token, and the token attribute is excluded from pickling
  so it cannot leak into a serialized traceback or a cached object.
- Base URL and realm derived from the django-pyoidc provider config where available, overridable
  by explicit settings.
- Methods: `get_user(id)`, `list_users(first, max, brief)` (paginated generator),
  `count_users()`, `get_user_groups(id)`, `list_groups()`, `get_group_members(id)`,
  `get_admin_events(date_from, first, max)`, `get_user_events(...)`.
- Retry with backoff on 5xx/429; raise typed exceptions; `KeycloakUserNotFound` on 404 (the signal
  that drives deletion).

Required roles on `realm-management`, assigned to the login client's service-account user and
documented in the README: `view-users`, `query-users`, `query-groups`, `view-events`, `view-realm`.

One consequence of reusing the login client: Keycloak materialises a `service-account-<client_id>`
user in the realm. **Verified against a real Keycloak 26.4 during implementation: it does not appear
in `GET /users`** -- Keycloak excludes service-account users from the listing entirely -- so
reconciliation never sees it and no local account is created, with or without `IMPORT_ALL_USERS`.
No special-casing is needed, and none would be possible. Such an account is only ever created if the
service account actually logs in, which goes through `hook_get_user` like any other
machine-to-machine login. Covered by an integration test that asserts both halves.

---

## Sync logic

### Username derivation (`sync/usernames.py`)

`derive_username(representation, *, exclude_pk=None) -> str`: takes `preferred_username`
(falling back to `email`, then `sub`), slugifies to the allowed charset, truncates to fit 150
chars including any suffix, and on collision appends `-2`, `-3`, … until free. Pluggable via a
`KEYCLOAK["USERNAME_STRATEGY"]` dotted path. Collisions are real even though KC usernames are
realm-unique, because a stale local row may still hold a name that KC has since reassigned.

### `hook_get_user` (`hooks.py`)

Resolves the user by the `sub` claim against `keycloak_id`, creating the row when absent, then
optionally refreshes fields (`KEYCLOAK["SYNC_ON_LOGIN"]`). Two details `get_user_by_email` shows
are mandatory (`__init__.py:80-81`): it must set
`user.backend` to the `KeycloakSessionBackend` path — with more than one
entry in `AUTHENTICATION_BACKENDS`, `auth.login()` raises without an explicit backend — and it must return a
user for which `is_authenticated` is true, or the callback view treats login as failed
(`views.py:414`).

**Group membership at login** comes from a `groups` claim when the realm has a group-membership
mapper configured (zero extra network calls); it falls back to `GET /users/{id}/groups` only when
the claim is absent, so a login does not necessarily cost an admin-API round trip. Which path was
used is logged at debug level, and a system check hints at adding the mapper.

### `sync_user(representation | keycloak_id) -> KeycloakUser` (`sync/users.py`)

Idempotent upsert keyed on `keycloak_id`. Always re-reads from the Admin API when given only an
id. Updates the mapped fields, renames the username if `preferred_username` changed (via the
collision strategy), syncs `source="keycloak"` group memberships, stamps `last_synced_at`, emits
`user_synced` / `user_created`. Optionally maps configured KC realm/client roles to
`is_staff` / `is_superuser` via a `KEYCLOAK["STAFF_ROLES"]` / `["SUPERUSER_ROLES"]` setting.

### `delete_or_anonymize(user) -> "deleted" | "anonymized"`

```
with transaction.atomic():
    sid = transaction.savepoint()
    try:
        user.delete()
        return "deleted"
    except (ProtectedError, RestrictedError):
        transaction.savepoint_rollback(sid)
        anonymize(user)
        return "anonymized"
```

`anonymize()`: `username = f"deleted-{uuid4().hex[:12]}"`, blank `email`/`first_name`/`last_name`,
`is_active = False`, `set_unusable_password()`, clear `keycloak_attributes`, `is_anonymized = True`,
and **keep `keycloak_id` as a tombstone** so the same KC user is never re-imported as a fresh
account. Emits `user_deleted` / `user_anonymized`.

Django's `Collector` raises both `ProtectedError` and `RestrictedError` during `delete()`, before
any SQL is emitted — but the savepoint is still required because a cascade may have partially
executed for other relations. Also catch `IntegrityError` for host models that use `DO_NOTHING`
with a database-level FK constraint, which surfaces only at the DB.

### `poll_admin_events` (`sync/events.py`)

Reads the cursor, fetches admin events since it (plus a configurable overlap window), filters to
`resourceType in {USER, GROUP, GROUP_MEMBERSHIP, REALM_ROLE_MAPPING}`, extracts the affected
user/group id from `resourcePath`, dedupes against the cursor's seen-ids, then calls `sync_user` /
`sync_group` per affected id. `DELETE` on a user resource triggers `delete_or_anonymize`. Also
polls the *user* events endpoint for `UPDATE_PROFILE` / `UPDATE_EMAIL` so account-console
self-service edits are not missed. Advances the cursor only on success; records a `SyncRun`.

### `full_reconcile` (`sync/reconcile.py`)

Pages `/users`, upserts each (skipping rows already flagged `is_anonymized=True` — otherwise every
pass re-404s the tombstones and re-runs `delete_or_anonymize` on them, which on the second attempt
could hard-delete the row and defeat the tombstone), creating new local users only when
`KEYCLOAK["IMPORT_ALL_USERS"]` is true — default false, per the user's decision), then walks local
users with a non-null `keycloak_id` that were not seen in this pass and confirms each with a
`GET /users/{id}`; a 404 means gone from Keycloak → `delete_or_anonymize`. Never touches users with
`keycloak_id IS NULL`. Also reconciles groups and expires stale manual memberships. This is the
correctness backstop for LDAP-federated and event-expired changes.

---

## Tokens

### Storage (`tokens/store.py`)

Storage is a **two-phase handoff across the two hooks**, forced by the ordering described above:

1. `hook_get_user(client, tokens)` extracts `access_token_jwt` from `tokens`, and the raw
   `id_token_jwt` + `refresh_token` from `client.consumer`'s grant for the current state
   (`tokens/extract.py::extract_raw_tokens(client, tokens)` — the one place that touches pyoidc
   internals). It attaches them to the returned user instance as a transient
   `user._keycloak_pending_tokens`. Nothing is written yet — there is no session row to point at.
2. `hook_user_login(request, user)` receives the *same* user instance, by which time the
   `OIDCSession` row exists. It resolves that row (newest row with
   `cache_session_key=request.session.session_key`) and writes the `OIDCTokenSet`, then clears the
   transient attribute.

If phase 1 could not obtain a refresh token, the token set is still stored with
`refresh_token=NULL` and lazy refresh raises `TokensUnavailable` for that session rather than
failing the login.

`hook_user_logout` and `hook_session_logout` delete the token set. The `keycloak_purge_tokens`
management command sweeps sets whose session no longer exists and whose refresh token has expired.

`KEYCLOAK["REQUEST_OFFLINE_ACCESS"]` (default `False`) appends `offline_access` to the provider's
`scopes` list — the verified django-pyoidc settings key (`settings.py:25,39`, default
`["openid"]`) — and marks the resulting set `is_offline=True`.

### Lazy refresh (`tokens/refresh.py`)

```
get_valid_access_token(token_set, *, leeway=60) -> str
aget_valid_access_token(...)          # async twin
```

If the access token expires more than `leeway` seconds out, return it. Otherwise acquire a cache
mutex — `cache.add(f"kc:refresh:{token_set.pk}", nonce, timeout=30)` — which is an atomic
test-and-set. **The cached value is a random lock nonce, never a token**; the refreshed tokens go
only to the encrypted database columns. The winner performs the `refresh_token` grant, saves the
new set, and releases (comparing the nonce so it cannot release someone else's lock);
losers sleep briefly and re-read the row (the winner has by then written it). No DB transaction is
held across the network call, so this is safe under ASGI. On `invalid_grant` the token set is
deleted and a typed `TokensUnavailable` is raised for the caller to handle.

### Rule: the only place a token is at rest is an encrypted DB column

Stated once so it is not re-litigated per feature: raw tokens live **only** in `OIDCTokenSet`'s
encrypted fields. Never in the Django cache, never in the session, never in a log record, never in
an admin page, never in a `SyncRun.error_detail`. Exception handling scrubs `access_token`,
`refresh_token`, `id_token`, `code` and `client_secret` from any request/response body before it
reaches a log or an exception message.

Note one thing outside our control, to document rather than fix: django-pyoidc's own
`OIDCEngine._call_introspection` caches introspection results in the Django cache under a key
hashed from the access token (`engine.py`). That stores *claims*, not the token itself, but it is
upstream behaviour worth knowing about; introspection can be avoided entirely by using
`hook_validate_access_token` instead.

### Token exchange (`tokens/exchange.py`)

```
exchange_token(user_or_token_set, *, audience, requested_token_type=ACCESS_TOKEN) -> str
```

POSTs to the realm token endpoint with
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token` (obtained via
`get_valid_access_token`), `subject_token_type=urn:ietf:params:oauth:token-type:access_token`,
`audience`, `requested_token_type`. **Exchanged tokens are not cached either** — same reasoning as
the service-account token, and worse, since these are per-user credentials for a downstream
service. Each call performs a fresh exchange and returns the token to the caller, which holds it
for the duration of its own request and nothing more. Never stored in the cache, never persisted to
the database, never logged.

**Which client credentials are used matters.** The subject token must carry the requesting client
as an audience, or be that client's own token — so the exchange is performed with **django-pyoidc's
login client** (`client_id` / `client_secret` from the provider settings). Since the Admin API
client now reuses those same credentials, this is automatically consistent — there is only one
client, and the user's access token was issued to it, so the audience precondition holds without
any extra configuration. (This was a real failure mode under the earlier split-client design, where
exchanging with the admin client's credentials would have 403'd on every call.)

Documented preconditions, verified against the current Keycloak docs:
`token-exchange-standard:v2` is enabled by default; the requesting client **must be confidential**
with "Standard token exchange" switched on; the subject token must already carry the requester
client as an audience; refresh tokens in the response require "Allow refresh token in Standard
Token Exchange"; requested scopes must already be default/optional scopes of the requesting client.
Public clients cannot perform token exchange — a system check warns if the *login* client is
configured without a client secret while token exchange is in use.

---

## Django admin (`admin.py`)

- `admin.site.unregister(Group)` (guarded).
- `KeycloakUserAdmin`: KC-derived fields read-only (one-way sync), `keycloak_id` searchable,
  filters on `is_active` / `is_anonymized` / `last_synced_at`. Memberships as an inline showing
  `source` and `expires_at`, with `source="keycloak"` rows read-only.
- Actions: **Sync selected users**, **Sync all users**, **Delete/anonymize selected**. When Celery
  is installed the bulk actions enqueue and message the user; otherwise they run inline with a
  guard on selection size (configurable cap) so the request cannot hang indefinitely.
- Per-object "Sync now" button on the change form (custom admin URL).
- `SyncRunAdmin`: read-only, no add permission — the audit view.
- `KeycloakGroupAdmin`: KC-derived groups read-only except for local memberships; locally created
  groups fully editable. No permission assignment widget exists anywhere.
- `OIDCTokenSet` is **not** registered in the admin (it holds secret material); a read-only
  presence/expiry indicator appears on the user change form instead.

## Signals (`signals.py`)

`user_created`, `user_synced`, `user_anonymized`, `user_deleted`, `group_synced`,
`membership_changed`, `sync_run_finished` — the host application's extension points.

## Settings (`conf.py`)

A single `KEYCLOAK = {...}` dict with a typed accessor and defaults: `SERVER_URL`, `REALM`,
`ADMIN_CLIENT_ID` / `ADMIN_CLIENT_SECRET` (both unset by default — credentials come from
django-pyoidc's provider config), `IMPORT_ALL_USERS` (False), `REQUEST_OFFLINE_ACCESS`
(False), `SYNC_ON_LOGIN` (True), `USERNAME_STRATEGY`, `STAFF_ROLES`, `SUPERUSER_ROLES`,
`CREATE_DJANGO_PERMISSIONS` (False),
`EVENT_OVERLAP_SECONDS`, `ADMIN_BULK_INLINE_LIMIT`, `TOKEN_ENCRYPTION_KEY`. Django system checks in
`apps.py` validate the combination at startup (missing secret, backend not installed,
`AUTH_USER_MODEL` mismatch, offline access requested without a refresh-capable client).

---

## Implementation order

1. Project scaffolding: `src/` layout, pyproject with deps/extras, ruff + mypy + pytest-django,
   a `tests/testproject/` Django settings module.
2. `conf.py`, `apps.py` + system checks.
3. Models: user, group, membership, `KeycloakAuthorizationMixin`, managers, initial migration.
4. Admin: user/group/membership, `auth.Group` unregistration.
5. `KeycloakAdminClient` + unit tests with `respx`.
6. `sync/usernames.py`, `sync/users.py` (incl. `delete_or_anonymize`), `sync/groups.py`, signals.
7. `hooks.py` — `hook_get_user` resolving by `sub` (setting `user.backend`), plus login sync.
8. `SyncRun`/`SyncCursor`, `sync/events.py`, `sync/reconcile.py`, management commands.
9. Admin sync actions; `tasks.py` behind an optional Celery import.
10. Token storage, lazy refresh, token exchange; purge command and logout hooks.
11. README: setup, enabling service accounts on the existing django-pyoidc client and its
    `realm-management` roles, Keycloak client configuration for token exchange,
    `AUTH_USER_MODEL`-before-first-migrate warning, cron/beat examples.

## Verification

- `uv run pytest` — unit tests with `respx`-mocked Admin API covering: username collisions,
  `delete_or_anonymize` both branches (a `PROTECT` FK fixture forces the anonymize path),
  unmanaged users surviving reconcile, event dedupe/replay idempotence, membership
  source/expiry precedence, and lazy-refresh mutex contention (two concurrent callers ⇒ exactly one
  refresh request).
- Secret-handling tests, using a `LocMemCache` that records every key/value written: after a full
  login → sync → refresh → exchange cycle, assert **no cached value contains a JWT** (regex for
  `eyJ`-prefixed strings), that the refresh mutex value is a nonce, that the DB columns are
  ciphertext at rest (raw SQL read does not contain the token), and that no log record emitted
  during the cycle contains one.
- Authorization tests: `has_perm` delegates to a stub backend and is never answered from the DB;
  `is_superuser` short-circuits without calling the backend; `is_staff=False` is denied admin entry;
  expired memberships are absent from `active_groups()`; and — the regression guard for this
  requirement — `Permission.objects.count() == 0` after `migrate`, and the user and group models
  expose no `user_permissions` / `permissions` fields.
### Integration test: dynamically provisioned Keycloak under Podman

A session-scoped pytest fixture (`tests/integration/conftest.py`) starts a throwaway Keycloak
container via **Podman** — no pre-existing server, no fixed ports, nothing to clean up by hand.

- **Runtime wiring.** `testcontainers` speaks the Docker API, so the fixture points it at Podman's
  socket rather than shelling out: it exports `DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock`
  (rootless; falling back to `/run/podman/podman.sock`) and sets
  `TESTCONTAINERS_RYUK_DISABLED=1`, since the Ryuk reaper needs privileged socket access that
  rootless Podman does not grant — the fixture's own teardown stops the container instead. If the
  socket is absent the fixture runs `podman system service --time=0 unix://…` in the background,
  and if Podman itself is missing the whole integration module is `pytest.skip`ped so the unit
  suite still passes on a machine without it.
- **Container.** `quay.io/keycloak/keycloak:<pinned tag>` with `start-dev`, bootstrap admin
  credentials from env, `--features=token-exchange-standard:v2`, and admin/user **event storage
  enabled** — without that the event-polling half of the library cannot be exercised. Port 8080 is
  published on an ephemeral host port that the fixture reads back, and readiness is a poll of the
  health endpoint with a timeout.
- **Realm bootstrap.** The fixture imports a realm JSON (`tests/integration/realm-export.json`)
  defining: the single confidential client django-pyoidc logs in through — service accounts
  enabled, holding the `realm-management` roles listed above, standard token exchange enabled — a
  second client with a distinct audience purely as the exchange *target*, a group hierarchy, and a
  handful of seed users.
- **Django wiring.** A function-scoped fixture rewrites the `KEYCLOAK` settings dict to the
  container's dynamic URL and flushes the DB between tests, so tests are independent while the
  container is shared across the module.

The scenario the test drives end to end:

1. `keycloak_reconcile` — assert seed users and the group hierarchy land locally, with
   `keycloak_id` populated and memberships marked `source="keycloak"`.
2. Mutate through the Admin API: rename a user's `preferred_username` into a collision with an
   existing local row, change an email, disable one user, add one to a group, remove another.
3. `keycloak_sync_events` — assert each change converged, that the collision produced a suffixed
   username, and that `enabled=false` became `is_active=False`.
4. Run the same events poll a second time — assert nothing changes (idempotence / cursor dedupe).
5. Delete a user in Keycloak that has a `PROTECT`ed related object, and one that has none; poll
   again and assert one was anonymized (with `keycloak_id` retained as a tombstone) and the other
   hard-deleted.
6. Assert a locally created user with `keycloak_id IS NULL` survived every pass untouched, and that
   the `service-account-<client_id>` user is absent from `GET /users` and so is never imported,
   even with `IMPORT_ALL_USERS` enabled.
7. Add a manual membership with an `expires_at` in the past, reconcile, assert it was swept while a
   non-expiring manual membership survived.
8. Drive a real OIDC login through django-pyoidc's callback view against the container and assert
   the stored `OIDCTokenSet` holds the *raw* access token, ID token and refresh token — this is
   the test that guards the `client.consumer` extraction against upstream changes.
9. Obtain a real token set and assert
   `exchange_token(..., audience=<second client>)` returns a token whose `aud` is that client.
10. Assert a `SyncRun` row was recorded for each pass with the expected counters.
- Manual end-to-end against the user's Keycloak: `uv run manage.py keycloak_reconcile --dry-run`,
  then a real run, then the admin "Sync now" button, then log in through django-pyoidc and confirm
  a token set is stored and purged at logout.
- Token exchange verified manually against a second client with a distinct audience, since it
  depends on realm-side client configuration that cannot be asserted from our side.

Note: all Python commands run via `uv run` / `uv pip` (never bare `pip`), per the user's preference.
