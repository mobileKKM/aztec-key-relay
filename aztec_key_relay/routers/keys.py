"""API endpoints."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status

from ..firebase import FirebaseError, TemplateUnchangedError
from ..keys import InvalidKeyError
from ..service import KeyEnvelope, KeyService, KeyUnavailableError, RefreshRateLimitedError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1")


def get_key_service() -> KeyService:
    from ..main import app_state  # late import: avoids a circular module dep

    service = app_state.key_service
    if service is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "service not ready")
    return service


def _api_token() -> str | None:
    from ..main import app_state

    return app_state.api_token


def require_token(authorization: Annotated[str | None, Header()] = None) -> None:
    """Optional bearer auth: enforced only when RELAY_API_TOKEN is set."""
    expected_token = _api_token()
    if expected_token is None:
        return
    if authorization != f"Bearer {expected_token}":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid bearer token", headers={"WWW-Authenticate": "Bearer"})


def _get_cache_control() -> str:
    """`Cache-Control` for cacheable key responses.

    `private` when bearer auth is enabled (a shared cache must never store
    token-authorized responses), `public` otherwise so an intermediary can
    serve repeat GETs without hitting the relay.
    """
    from ..main import app_state

    visibility = "private" if app_state.api_token else "public"
    return f"{visibility}, max-age={app_state.cache_max_age}"


@router.get("/aztec-key", dependencies=[Depends(require_token)])
async def get_aztec_key(response: Response) -> KeyEnvelope:
    """Serves the cached key. Never triggers an upstream fetch."""
    response.headers["Cache-Control"] = _get_cache_control()
    service = get_key_service()
    try:
        return await service.current()
    except KeyUnavailableError as exc:
        # Don't let a cache store the 503 — it would mask a fast recovery.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), headers={"Cache-Control": "no-store"}) from exc


@router.post("/aztec-key/refresh", dependencies=[Depends(require_token)], status_code=status.HTTP_200_OK)
async def refresh_aztec_key() -> KeyEnvelope:
    """Forces an upstream fetch (e.g. after the app's request failed)."""
    service = get_key_service()
    try:
        return await service.refresh()
    except TemplateUnchangedError:
        # Upstream confirmed the cached key is current — serve it.
        return await service.current()
    except RefreshRateLimitedError as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            str(exc),
            headers={"Retry-After": str(max(1, round(exc.retry_after))), "Cache-Control": "no-store"},
        ) from exc
    except (FirebaseError, InvalidKeyError) as exc:
        # The old key stays cached (marked stale); tell the client to retry later.
        await service.mark_stale()
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"upstream fetch failed: {exc}", headers={"Cache-Control": "no-store"}
        ) from exc
