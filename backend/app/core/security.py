"""Minimal access control for state-changing endpoints.

DEMO vs PRODUCTION (see docs/security.md):

* If ``CR360_API_KEY`` is set, every write endpoint requires the ``X-API-Key`` header
  (constant-time comparison). This is a *shared secret* suitable for a local demo or a
  single trusted client. It is NOT user authentication: no identities, roles or rotation.
* If no key is set and ``CR360_APP_ENV=demo``, writes are allowed (offline demo only).
* If no key is set and ``CR360_APP_ENV=production``, writes are refused (fail closed).

``X-Actor`` is a free-text label recorded in the audit trail. It is NOT an authenticated
identity; a production deployment must derive the actor from an identity provider (OIDC).
"""

from __future__ import annotations

import hmac
import re

from fastapi import Header, HTTPException, status

from app.core.config import get_settings

_ACTOR_RE = re.compile(r"[^A-Za-z0-9 ._@-]")
DEFAULT_ACTOR = "anonymous-demo-user"


def require_write_access(x_api_key: str | None = Header(default=None)) -> None:
    settings = get_settings()
    if settings.write_auth_enabled:
        expected = settings.api_key.get_secret_value()  # type: ignore[union-attr]
        if not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or invalid API key")
        return
    if settings.app_env == "production":
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Write operations are disabled: no API key configured in production mode",
        )


def sanitize_actor(raw: str | None) -> str:
    if not raw:
        return DEFAULT_ACTOR
    cleaned = _ACTOR_RE.sub("", raw).strip()[:64]
    return cleaned or DEFAULT_ACTOR


def get_actor(x_actor: str | None = Header(default=None)) -> str:
    """Sanitised, length-limited actor label for the audit trail (not an identity)."""
    return sanitize_actor(x_actor)
