"""Settings for the test project."""

from __future__ import annotations

SECRET_KEY = "test-secret-key-not-for-production"
SALT_KEY = "test-salt-key-not-for-production"
DEBUG = False
USE_TZ = True

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.admin",
    "django_pyoidc",
    "django_pyoidc_keycloak",
    "tests.testapp",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

ROOT_URLCONF = "tests.testproject.urls"

AUTH_USER_MODEL = "keycloak.KeycloakUser"

AUTHENTICATION_BACKENDS = [
    "django_pyoidc_keycloak.backends.KeycloakSessionBackend",
    "tests.testproject.backend.StubPolicyBackend",
]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

DJANGO_PYOIDC = {
    "sso": {
        "client_id": "django-app",
        "client_secret": "s3cr3t",
        "provider_class": "KeycloakProvider",
        "keycloak_base_uri": "https://sso.example.org",
        "keycloak_realm": "demo",
        "hook_get_user": "django_pyoidc_keycloak.hooks.get_user",
        "hook_user_login": "django_pyoidc_keycloak.hooks.user_login",
        "hook_user_logout": "django_pyoidc_keycloak.hooks.user_logout",
        "hook_session_logout": "django_pyoidc_keycloak.hooks.session_logout",
        "login_uris_redirect_allowed_hosts": ["testserver"],
        "login_redirection_requires_https": False,
        "post_logout_redirect_uri": "/",
        "post_login_uri_success": "/",
    }
}

KEYCLOAK = {
    "OP_NAME": "sso",
}
