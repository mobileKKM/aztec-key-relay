"""API endpoints."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status

from ..firebase import FirebaseError
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


@router.get("/aztec-key", dependencies=[Depends(require_token)])
async def get_aztec_key() -> KeyEnvelope:
    """Serves the cached key. Never triggers an upstream fetch."""
    service = get_key_service()
    try:
        return await service.current()
    except KeyUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc


@router.post("/aztec-key/refresh", dependencies=[Depends(require_token)], status_code=status.HTTP_200_OK)
async def refresh_aztec_key() -> KeyEnvelope:
    """Forces an upstream fetch (e.g. after the app's request failed)."""
    service = get_key_service()
    try:
        return await service.refresh()
    except RefreshRateLimitedError as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            str(exc),
            headers={"Retry-After": str(max(1, round(exc.retry_after)))},
        ) from exc
    except (FirebaseError, InvalidKeyError) as exc:
        # The old key stays cached (marked stale); tell the client to retry later.
        await service.mark_stale()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"upstream fetch failed: {exc}") from exc
