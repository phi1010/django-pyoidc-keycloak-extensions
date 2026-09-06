# django-pyoidc-keycloak-extensions

Keycloak user and group synchronisation, encrypted token storage and RFC 8693 token exchange
for Django projects that authenticate through
[django-pyoidc](https://pypi.org/project/django-pyoidc/).

django-pyoidc handles the OIDC login flow and stops there. This library adds what a project
needs when Keycloak is the system of record:

* **Identity is the Keycloak UUID**, not an email address. Emails change and get reused.
* **Users stay in step with Keycloak** — renames, disables and deletions arrive through
  event polling, with full reconciliation as the correctness backstop.
* **Deleted accounts are removed, or anonymised** when local data still references them.
* **Groups mirror Keycloak**, with temporary manual overrides an admin can grant.
* **Permissions are never stored locally.** Every `has_perm` goes to your own authorization
  backend (Open Policy Agent, or whatever you use).
* **Raw tokens are stored encrypted**, refreshed lazily, and exchangeable for another audience.

## Requirements

Python 3.14+, Django 5.2+, django-pyoidc 1.0.13+, Keycloak 26.2+ for token exchange.

## Installation

```bash
uv pip install django-pyoidc-keycloak-extensions
```

## Keycloak setup

This library reuses the client you already configured for django-pyoidc — there is no
separate service account to create. On that client:

1. **Client authentication: on** (it must be confidential).
2. **Service accounts roles: on.**
3. On the service-account user, assign these `realm-management` roles:
   `view-users`, `query-users`, `query-groups`, `view-events`, `view-realm`.
4. In *Realm settings → Sessions/Events*, enable **admin events** and **user events** — event
   polling reads both, and neither is on by default.
5. For token exchange: switch on **Standard token exchange** on the client, and make sure the
   user holds a role on the target client so that audience is within your client's scope.

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

# Your policy engine decides every permission. ModelBackend must NOT be here:
# a system check rejects it, because it would answer has_perm() from the database.
AUTHENTICATION_BACKENDS = ["myproject.authz.OPABackend"]

SALT_KEY = env("SALT_KEY")  # token encryption; see "Token encryption" below

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
    "AUTH_BACKEND": "myproject.authz.OPABackend",
}
```

### Your authorization backend

It must provide:

```python
class OPABackend:
    def authenticate(self, request, **credentials):
        return None  # login happens through OIDC

    def get_user(self, user_id):  # required: session auth calls this on every request
        ...

    def has_perm(self, user_obj, perm, obj=None): ...
    def has_module_perms(self, user_obj, app_label): ...
    def get_all_permissions(self, user_obj, obj=None):  # optional; the admin index uses it
        ...
```

`is_superuser` short-circuits to `True` before your backend is consulted, and `is_staff`
gates admin access.

## Scheduling

```cron
*/2 *  * * *  manage.py keycloak_sync_events    # incremental
17  *  * * *  manage.py keycloak_reconcile      # the correctness backstop
30  3  * * *  manage.py keycloak_purge_tokens   # expired tokens and memberships
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
Session Idle clock (defeating idle timeout), is still capped by SSO Session Max, and races the
user's own browser refresh, which trips reuse detection when rotation is on. For work while
the user is away, set `KEYCLOAK["REQUEST_OFFLINE_ACCESS"] = True` to obtain an offline token,
which is exempt from SSO Session Max.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `OP_NAME` | auto | Which `DJANGO_PYOIDC` provider to use; required if several are configured. |
| `SERVER_URL` / `REALM` | from django-pyoidc | Override the derived Keycloak location. |
| `ADMIN_CLIENT_ID` / `ADMIN_CLIENT_SECRET` | from django-pyoidc | Use a separate admin client. |
| `IMPORT_ALL_USERS` | `False` | Create local users for accounts that never logged in. |
| `SYNC_ON_LOGIN` | `True` | Refresh the user from claims at each login. |
| `SYNC_GROUPS` | `True` | Mirror group membership. |
| `USERNAME_STRATEGY` | built-in | Dotted path to your own username derivation. |
| `STAFF_ROLES` / `SUPERUSER_ROLES` | `[]` | Realm roles that map to `is_staff` / `is_superuser`. |
| `AUTH_BACKEND` | auto | Backend recorded on the user at login; required if several. |
| `CREATE_DJANGO_PERMISSIONS` | `False` | Let Django populate `auth_permission` again. |
| `STORE_TOKENS` | `True` | Store raw tokens at login. |
| `REQUEST_OFFLINE_ACCESS` | `False` | Request `offline_access` scope. |
| `TOKEN_EXCHANGE_ENABLED` | `False` | Enables the token-exchange system check. |
| `ADMIN_BULK_INLINE_LIMIT` | `50` | Cap on synchronising inline from the admin without Celery. |
| `EVENT_OVERLAP_SECONDS` | `300` | How far back each event poll re-reads. |

## Notes on behaviour worth knowing

* **Local-only users are never touched.** A user with `keycloak_id = NULL` (your bootstrap
  superuser, for instance) survives every reconciliation.
* **Anonymisation keeps a tombstone.** `keycloak_id` is retained so a deleted Keycloak account
  is never re-imported as a fresh user.
* **Service-account users are not imported.** Keycloak excludes them from `GET /users`, so
  reconciliation never sees them; one is only created if it actually logs in.
* **Two empty tables remain.** `django.contrib.auth` cannot be removed from `INSTALLED_APPS`,
  so `auth_permission` and `auth_group` exist. This library never reads or writes them, and
  permission creation is disconnected so they stay empty.

## Development

```bash
uv pip install -e ".[dev,celery]"
uv run pytest                  # unit tests
uv run pytest -m integration   # against a real Keycloak in Podman
```

The integration suite starts `quay.io/keycloak/keycloak:26.4` through Podman's socket, imports
a realm, and drives the full cycle: reconcile, mutate, poll, delete, refresh, exchange. It
skips itself if Podman is not installed.
