"""API endpoints."""

from __future__ import annotations

import logging
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..firebase import FirebaseError
from ..keys import InvalidKeyError
from ..service import KeyEnvelope, KeyService, KeyUnavailableError, RefreshRateLimitedError

logger = logging.getLogger(__name__)

NO_STORE = {"Cache-Control": "no-store"}

bearer_scheme = HTTPBearer(auto_error=False, description="Required only when RELAY_API_TOKEN is set.")

router = APIRouter(tags=["keys"])


def get_key_service() -> KeyService:
    from ..main import app_state  # late import: avoids a circular module dep

    service = app_state.key_service
    if service is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "service not ready", headers=NO_STORE)
    return service


def _api_token() -> str | None:
    from ..main import app_state

    return app_state.api_token


def require_token(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]) -> None:
    """Optional bearer auth: enforced only when RELAY_API_TOKEN is set."""
    expected_token = _api_token()
    if expected_token is None:
        return
    presented = credentials.credentials if credentials else ""
    if not secrets.compare_digest(presented.encode(), expected_token.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid bearer token", headers={"WWW-Authenticate": "Bearer"})


def _etag(envelope: KeyEnvelope) -> str:
    return f'"{envelope.fingerprint_sha256}"'


def _etag_matches(if_none_match: str | None, etag: str) -> bool:
    if not if_none_match:
        return False
    candidates = [tag.strip().removeprefix("W/") for tag in if_none_match.split(",")]
    return "*" in candidates or etag in candidates


@router.get("/aztec-key", dependencies=[Depends(require_token)], response_model=KeyEnvelope)
async def get_aztec_key(
    response: Response,
    if_none_match: Annotated[str | None, Header()] = None,
) -> KeyEnvelope | Response:
    """Serves the cached key. Never triggers an upstream fetch.

    The ETag is the key fingerprint, so `If-None-Match` gets a bodyless 304
    until the key rotates.
    """
    service = get_key_service()
    try:
        envelope = await service.current()
    except KeyUnavailableError as exc:
        # Don't let a cache store the 503 — it would mask a fast recovery.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), headers=NO_STORE) from exc

    headers = {"ETag": _etag(envelope)}
    if _etag_matches(if_none_match, headers["ETag"]):
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    response.headers.update(headers)
    return envelope


@router.post("/aztec-key/refresh", dependencies=[Depends(require_token)], status_code=status.HTTP_200_OK)
async def refresh_aztec_key(response: Response) -> KeyEnvelope:
    """Forces an upstream fetch (e.g. after the app's request failed).

    Inside the rate window this returns the key checked moments ago, or 429
    if that check failed.
    """
    response.headers.update(NO_STORE)
    service = get_key_service()
    try:
        envelope = await service.refresh()
        response.headers["ETag"] = _etag(envelope)
        return envelope
    except RefreshRateLimitedError as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            str(exc),
            headers={"Retry-After": str(max(1, round(exc.retry_after))), **NO_STORE},
        ) from exc
    except KeyUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), headers=NO_STORE) from exc
    except (FirebaseError, InvalidKeyError) as exc:
        # The old key stays cached (marked stale). Details stay in our log:
        # they contain upstream URLs (project id) and Google's error text.
        logger.warning("refresh failed: %s", exc)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "upstream fetch failed", headers=NO_STORE) from exc
