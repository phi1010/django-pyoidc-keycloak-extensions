"""RFC 8693 token exchange: act on a user's behalf against another audience.

Keycloak requirements, which the README repeats:

* ``token-exchange-standard:v2`` is enabled by default on current Keycloak.
* The requesting client must be **confidential** with "Standard token exchange" enabled.
* The subject token must already carry the requesting client as an audience, or be that
  client's own token.  Since this library reuses django-pyoidc's client for everything, that
  holds automatically -- the user's access token was issued to exactly this client.
* Public clients cannot exchange tokens at all.

Exchanged tokens are never cached and never persisted.  They are per-user credentials for a
downstream service; the caller holds one for the duration of its own request and no longer.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from django_pyoidc_keycloak.admin_api.exceptions import TokensUnavailable
from django_pyoidc_keycloak.admin_api.provider import get_connection
from django_pyoidc_keycloak.conf import app_settings
from django_pyoidc_keycloak.scrub import scrub_text

logger = logging.getLogger(__name__)

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
REFRESH_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:refresh_token"


def exchange_access_token(
    subject_token: str,
    *,
    audience: str,
    requested_token_type: str = ACCESS_TOKEN_TYPE,
    scope: str | None = None,
) -> str:
    """Exchange one access token for another aimed at ``audience``."""
    connection = get_connection()
    data = {
        "grant_type": GRANT_TYPE,
        "client_id": connection.client_id,
        "client_secret": connection.client_secret,
        "subject_token": subject_token,
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "audience": audience,
        "requested_token_type": requested_token_type,
    }
    if scope:
        # Only scopes already assigned to the requesting client are accepted.
        data["scope"] = scope

    # The audience and the requested type are safe to log; `data` never is.
    logger.debug(
        "Exchanging a token for audience %r (requested type %s, scope %r)",
        audience,
        requested_token_type,
        scope,
    )

    with httpx.Client(timeout=app_settings.REQUEST_TIMEOUT) as client:
        response = client.post(connection.token_endpoint, data=data)

    if response.status_code >= 400:
        logger.debug("Token exchange for audience %r was refused with %d", audience, response.status_code)
        detail = scrub_text(response.text)
        if response.status_code in (400, 403):
            msg = (
                f"Keycloak refused the token exchange for audience {audience!r} ({response.status_code}). "
                "Check that the client is confidential, has 'Standard token exchange' enabled, and that "
                f"the subject token lists {connection.client_id!r} as an audience. Response: {detail}"
            )
            raise TokensUnavailable(msg)
        msg = f"Token exchange failed ({response.status_code}): {detail}"
        raise TokensUnavailable(msg)

    payload = response.json()
    token = payload.get("access_token")
    if not token:
        msg = "Keycloak returned no access_token for the exchange."
        raise TokensUnavailable(msg)
    logger.debug("Token exchange for audience %r succeeded", audience)
    return str(token)


def exchange_token(
    user_or_token_set: Any,
    *,
    audience: str,
    requested_token_type: str = ACCESS_TOKEN_TYPE,
    scope: str | None = None,
) -> str:
    """Return a token for ``audience`` on behalf of a user.

    Accepts either a user or an ``OIDCTokenSet``.  The subject token is obtained through the
    normal lazy-refresh path, so an expired access token is renewed first.
    """
    from django_pyoidc_keycloak.models.tokens import OIDCTokenSet
    from django_pyoidc_keycloak.tokens.refresh import get_access_token_for_user, get_valid_access_token

    if isinstance(user_or_token_set, OIDCTokenSet):
        logger.debug("Using token set %s as the exchange subject", user_or_token_set.pk)
        subject_token = get_valid_access_token(user_or_token_set)
    else:
        logger.debug("Resolving a subject token for user %s", getattr(user_or_token_set, "pk", None))
        subject_token = get_access_token_for_user(user_or_token_set)

    return exchange_access_token(
        subject_token,
        audience=audience,
        requested_token_type=requested_token_type,
        scope=scope,
    )
