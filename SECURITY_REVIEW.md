# Security Review — django-pyoidc-keycloak-extensions

**Date:** 2026-09-06
**Scope:** all source under `src/django_pyoidc_keycloak/`, test project settings, dependencies in `uv.lock`.
**Method:** manual code review (auth flows, token storage, admin integration, sync engine, secrets handling), dependency version check.

## Findings

### 1. HIGH — `find_session()` ignores its `user` argument; tokens can be attached to another user's session

`src/django_pyoidc_keycloak/tokens/store.py:37-45`

```python
def find_session(request: Any, user: Any = None):
    session_key = getattr(getattr(request, "session", None), "session_key", None)
    queryset = OIDCSession.objects.all()
    if session_key:
        queryset = queryset.filter(cache_session_key=session_key)
    return queryset.order_by("-created_at").first()   # <-- user never used
```

If `session_key` is absent (empty session, middleware ordering, unusual session backend), the function returns the **most recent `OIDCSession` row of any user**. `store_tokens()` then runs `update_or_create(session=session, defaults={"user": user, ...})` (`tokens/store.py:53-68`), which *overwrites the `user` field and the token ciphertext* of that row. Two consequences:

- User A's fresh tokens can be written onto user B's session row (token misattribution).
- User B's stored tokens are silently replaced by user A's. B's next `get_token_set()` / `get_access_token_for_user()` — which filters *only by user* — can then return A's tokens to B: a **cross-user credential leak**.

**Fix:** always filter by both keys, and fail closed:

```python
if not session_key:
    return None
return OIDCSession.objects.filter(
    cache_session_key=session_key, sub=str(getattr(user, "keycloak_id", "") or "")
).order_by("-created_at").first()
```

Add a test covering the "no session key" path (it currently prefers to guess).

### 2. HIGH — `sync_single_view` performs a permission-checked-optional, state-changing GET

`src/django_pyoidc_keycloak/admin.py:146-181`

Two distinct problems:

a) **No model-permission check.** Custom URLs added in `get_urls()` and wrapped only in `self.admin_site.admin_view(...)` require *staff login* but **not** `has_change_permission` on the user model. Any staff user (e.g. someone given staff for a read-only admin area) can trigger Keycloak syncs and the follow-up user deletion/anonymisation on a 404 (`handle_missing_user`). Compare: Django's built-in views call `self.has_change_permission(request)` internally.

b) **State change over GET.** The "Sync now" link is a plain `<a href>` (`templates/admin/keycloak/keycloakuser/change_form.html:6`). Django's CSRF middleware does not protect GET, so `<img src=".../admin/keycloak/keycloakuser/<id>/sync/">` on any page a logged-in admin visits triggers a sync — including `delete_or_anonymize()` when the account 404s (e.g. during a transient Keycloak outage, where `KeycloakUserNotFound` is also raised by `request()` for *any* 404 from the Admin API, not just "user gone").

**Fix:** require POST (a small form with `{% csrf_token %}`), and start the view with:

```python
if not self.has_change_permission(request):
    raise PermissionDenied
```

Relatedly, `KeycloakAdminClient.request()` maps **every** 404 to `KeycloakUserNotFound` (`admin_api/client.py:160-162`), so a misconfigured path or transient gateway 404 currently walks the delete/anonymise path in `sync_single_view`, `_handle_admin_event` and `sync_users`. Consider a narrower mapping (404 on `/users/{id}` only) or verifying deletion via a second call.

### 3. MEDIUM — the `groups` claim from login can grant membership in any local group

`src/django_pyoidc_keycloak/hooks.py:121-136` → `src/django_pyoidc_keycloak/sync/groups.py:111-163`

At login, a `groups` claim is applied directly with `apply_group_paths()`, which matches **paths against every local group, including locally created (`keycloak_id IS NULL`) groups** (`groups.py:120`). Membership then feeds `active_groups()` (`permissions.py:107-112`) for the project's policy engine. Two escalation paths:

- If the Keycloak group mapper is (mis)configured over a user-editable attribute, a user controls their own claim content.
- Even with a correct mapper, any path collision with a sensitive *local-only* group (e.g. `/admins` created manually) grants membership that Keycloak never authorised.

**Fix:** in `apply_group_paths`, restrict to managed groups:

```python
wanted = set(
    group_model.objects.filter(path__in=paths, keycloak_id__isnull=False).values_list("pk", flat=True)
)
```

and document that group mappers must derive from the group membership, never from user-editable attributes.

### 4. MEDIUM — `has_perm()` delegates without checking `is_active`

`src/django_pyoidc_keycloak/permissions.py:82-96`

`is_active` is only consulted on the superuser fast path. Django's `ModelBackend.has_perm` returns `False` for inactive users; this mixin asks the project backend regardless. A user disabled in Keycloak (`is_active=False`) keeps whatever permissions the policy backend grants until that backend itself checks activity. Cheap, defence-in-depth fix:

```python
def has_perm(self, perm, obj=None):
    if not self.is_active:
        return False
    ...
```

Apply the same to `has_module_perms()` and `get_all_permissions()`.

### 5. MEDIUM — username derivation has a TOCTOU race and an unbounded loop

`src/django_pyoidc_keycloak/sync/usernames.py:43-66`

`exists()` checks followed by `user.save()` are not atomic; two concurrent logins for different Keycloak accounts claiming the same username end in `IntegrityError` (a 500 at login). The `while True` suffix loop is also unbounded against a hostile/long collision set.

**Fix:** wrap creation in `transaction.atomic()` and retry on `IntegrityError`, or add a deterministic tie-break (e.g. suffix from the Keycloak UUID), and cap the suffix (fall back to the UUID).

### 6. LOW — scrubbing has coverage gaps

`src/django_pyoidc_keycloak/scrub.py:13-35`

- `SECRET_KEYS` misses `refresh_token_url`? — more usefully: `client_assertion`, `session_state`, `device_secret`, `token`, `registration_access_token`, and `secret` as a bare key.
- The JWT regex requires the `eyJ` header prefix and exactly two dots; opaque access tokens (Keycloak can be configured to issue them) pass through unredacted. Errors from `httpx` do not contain bodies, so this is low-impact today, but `record_error()` writes free-form messages into `SyncRun.error_detail`, which staff can read.
- Consider redacting anything matching a high-entropy token pattern, not just JWTs.

### 7. LOW — pickling a `KeycloakAdminClient` still carries the client secret

`src/django_pyoidc_keycloak/admin_api/client.py:58-64`

`__getstate__` clears `_token` but keeps `self.connection`, and `KeycloakConnection` is a picklable dataclass containing `client_secret` (`admin_api/provider.py:22-30`). Exclude it too, or give `KeycloakConnection` a `__reduce__`/`__getstate__` that drops the secret.

### 8. LOW — `_perform_refresh` can store `None` access tokens

`src/django_pyoidc_keycloak/tokens/refresh.py:76-87`

If Keycloak's refresh response lacks `access_token`, the row is saved with `access_token=None` and `get_valid_access_token` returns `None` (typed `str`). Validate the payload like `_fetch_token()` does and raise `TokensUnavailable` instead.

### 9. LOW — inherited / dependency notes

- **django-pyoidc 1.0.13** stores pyoidc state in the Django cache via `jsonpickle.decode` (upstream `session.py:48`, marked `noqa: S301`). Anyone who can write to the cache backend can achieve RCE on next decode. If the deployed cache is Redis/memcached shared with less-trusted components, flag this; at minimum, document that the cache must be treated as trusted storage.
- **django-fernet-encrypted-fields 0.4.0** derives the Fernet key with PBKDF2-SHA256 at **100 000 iterations** (`encrypted_fields/fields.py:39`), below OWASP's current 600k guidance. Tokens are session-scoped and short-lived which mitigates this; no action needed in this repo, but worth knowing if token lifetimes grow (offline tokens).
- Installed versions (Django 6.1.1, httpx 0.28.1, cryptography 50.0.1) are current; no known CVEs apply. `django-pyoidc>=1.0.13` has no upper bound — pin or monitor it, since it holds the actual OIDC request paths.
- PEP 758 multi-except syntax (`except InvalidToken, ValueError:` in `tokens/fields.py:29`, `sync/users.py:209`) is Python 3.14-only. `requires-python = ">=3.14"` protects it, but anyone back-porting will hit a confusing `SyntaxError`.
- Test settings (`tests/testproject/settings.py`) hardcode weak `SECRET_KEY`/`SALT_KEY`/client secret and `login_redirection_requires_https: False` — test-only, acceptable; make sure it never becomes the copy-paste production template.

## What is already done well

- Raw tokens live only in `EncryptedTokenField` columns; never in cache, session, logs or the admin (`OIDCTokenSet` deliberately unregistered; `token_status` shows metadata only).
- Consistent secret hygiene: `scrub_text`/`scrub_exception` on every error path into logs and `SyncRun.error_detail`; guarded `__repr__`/`__str__` on `RawTokens`, `OIDCTokenSet`, `KeycloakAdminClient`, `KeycloakConnection`; `__getstate__` clears the service token; the refresh lock stores a random nonce, not a token.
- Login keys users on `sub` rather than email; events are treated as triggers only (representations re-read); anonymisation keeps a `keycloak_id` tombstone so deleted accounts cannot be resurrected; unmanaged local users are never touched by sync.
- Good start-up validation (`checks.py`: E001–E007, W001–W003), including the `SALT_KEY` requirement and ModelBackend detection.
- httpx defaults used throughout — no `verify=False` anywhere.

## Priority order

1. `find_session()` user filter (finding 1)
2. `sync_single_view`: POST + change-permission check; narrow 404→`KeycloakUserNotFound` mapping (finding 2)
3. Restrict `apply_group_paths` to managed groups (finding 3)
4. `is_active` gate in the permission mixin (finding 4)
5. Username race (finding 5)
6. Remaining low items as touch-ups.
