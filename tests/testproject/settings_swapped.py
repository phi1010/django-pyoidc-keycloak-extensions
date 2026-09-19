"""The test project with AUTH_USER_MODEL pointed at an app of its own.

Everything else matches tests.testproject.settings. Used only by
tests/test_swapped_user_model.py, which drives `makemigrations` and `migrate` in a
subprocess: a swapped user model is a start-up-time decision, so it cannot be tested with
override_settings inside the main suite.
"""

from __future__ import annotations

from tests.testproject.settings import *  # noqa: F403

INSTALLED_APPS = [*INSTALLED_APPS, "tests.testapp_swapped"]  # noqa: F405

AUTH_USER_MODEL = "testapp_swapped.User"

# A local-memory cache, so the check that demands django-redis (keycloak.E008) is the only
# thing this module has to care about -- it is not, and migrate does not touch the cache.
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379",
    }
}
