"""aztec-key-relay — FastAPI entrypoint.

Lifespan responsibilities:
1. build the Firebase client (one shared Installation, restored from disk),
2. on startup, fetch **only if** no key is cached yet — a fresh deployment
   must serve a key immediately, a restart with a good key must not hit
   Firebase,
3. run the scheduler: a daily refresh (fixed UTC hour + jitter) that ignores
   the min-interval rate limit, plus retries with backoff while there is no
   usable key (failed startup fetch, or a refresh that left the key stale).

No access log: the relay exists so app users leave no trace upstream, and it
keeps none of its own (uvicorn runs with --no-access-log).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import random
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import __version__
from .config import get_settings
from .firebase import FirebaseClient, FirebaseError
from .keys import InvalidKeyError
from .routers import keys as keys_router
from .service import KeyService
from .store import Store

logger = logging.getLogger("aztec_key_relay")

DAILY_JITTER_SECONDS = 15 * 60
# Retry backoff while there is no usable key: 1 min, doubling, capped at 30 min.
RECOVERY_MIN_SECONDS = 60
RECOVERY_MAX_SECONDS = 30 * 60
# How often the idle scheduler checks whether a refresh left the key stale.
STALE_POLL_SECONDS = 60


@dataclass
class AppState:
    key_service: KeyService | None = None
    store: Store | None = None
    http_client: httpx.AsyncClient | None = None
    api_token: str | None = None
    background: set[asyncio.Task] = field(default_factory=set)
    transport: httpx.AsyncBaseTransport | None = None


app_state = AppState()


def _seconds_until_daily(hour_utc: int) -> float:
    now = dt.datetime.now(dt.UTC)
    target = now.replace(hour=hour_utc, minute=0, second=0, microsecond=0)
    if target <= now:
        target += dt.timedelta(days=1)
    return (target - now).total_seconds() + random.uniform(0, DAILY_JITTER_SECONDS)


async def _refresh_once(service: KeyService, reason: str) -> None:
    try:
        await service.refresh(force=True)
    except (FirebaseError, InvalidKeyError) as exc:
        logger.warning("%s refresh failed (cached key kept, marked stale): %s", reason, exc)
    except Exception:
        # Never let one surprise (e.g. a sqlite error) end the scheduler.
        logger.exception("%s refresh failed unexpectedly", reason)
        service.mark_stale()


async def _refresh_loop(service: KeyService, hour_utc: int) -> None:
    loop = asyncio.get_running_loop()
    backoff = RECOVERY_MIN_SECONDS
    while True:
        if service.needs_recovery:
            delay = backoff * random.uniform(1.0, 1.5)
            backoff = min(backoff * 2, RECOVERY_MAX_SECONDS)
            logger.info("no usable key — retrying upstream in %.0f s", delay)
            await asyncio.sleep(delay)
            await _refresh_once(service, "recovery")
            continue

        backoff = RECOVERY_MIN_SECONDS
        deadline = loop.time() + _seconds_until_daily(hour_utc)
        logger.info("daily refresh scheduled in %.0f s", deadline - loop.time())
        while not service.needs_recovery and (remaining := deadline - loop.time()) > 0:
            await asyncio.sleep(min(remaining, STALE_POLL_SECONDS))
        if not service.needs_recovery:
            await _refresh_once(service, "daily")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    app_state.api_token = settings.relay_api_token
    # No default headers: each FirebaseClient call sets the exact SDK header
    # set (empty UA, `Accept-Encoding: gzip`, `Connection: Keep-Alive`) so we
    # never advertise python-httpx upstream.
    app_state.http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, read=20.0),
        transport=app_state.transport,
    )
    app_state.store = Store(settings.relay_db_path)
    firebase = FirebaseClient(settings, app_state.http_client)
    app_state.key_service = KeyService(settings, firebase, app_state.store)
    app_state.key_service.restore_installation()

    if app_state.store.current_key() is None:
        logger.info("no cached key — fetching on startup")
        try:
            await app_state.key_service.refresh(force=True)
        except (FirebaseError, InvalidKeyError) as exc:
            logger.error("startup fetch failed (will retry on schedule/refresh): %s", exc)
    else:
        logger.info("cached key present — skipping startup fetch")

    scheduler = asyncio.create_task(
        _refresh_loop(app_state.key_service, settings.relay_daily_refresh_hour), name="refresh-scheduler"
    )
    app_state.background.add(scheduler)

    yield

    scheduler.cancel()
    for task in app_state.background:
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:  # shutdown best effort
            logger.exception("background task failed during shutdown")
    app_state.background.clear()
    if app_state.http_client:
        await app_state.http_client.aclose()
    if app_state.store:
        app_state.store.close()
    app_state.key_service = None
    app_state.store = None
    app_state.http_client = None
    app_state.api_token = None
    app_state.transport = None


def create_app(*, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    """Builds the app; [transport] lets tests replace the upstream HTTP layer."""
    app_state.transport = transport

    app = FastAPI(
        title="aztec-key-relay",
        version=__version__,
        description="Relays the mKKM aztecKey RSA public key from Firebase Remote Config.",
        lifespan=lifespan,
    )
    app.include_router(keys_router.router, prefix="/api/v1")

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready", include_in_schema=False)
    async def ready() -> JSONResponse:
        service = app_state.key_service
        if service is None or app_state.store is None or app_state.store.current_key() is None:
            return JSONResponse({"ready": False}, status_code=503)
        return JSONResponse({"ready": True, "stale": service.stale})

    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run("aztec_key_relay.main:app", host="127.0.0.1", port=8000)
