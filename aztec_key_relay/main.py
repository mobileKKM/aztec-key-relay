"""aztec-key-relay — FastAPI entrypoint.

Lifespan responsibilities:
1. build the Firebase client (one shared Installation, restored from disk),
2. on startup, fetch **only if** no key is cached yet — a fresh deployment
   must serve a key immediately, a restart with a good key must not hit
   Firebase,
3. run the daily scheduler (fixed UTC hour + jitter), which force-refreshes
   regardless of the min-interval rate limit.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx
import uvicorn
from fastapi import FastAPI

from . import __version__
from .config import get_settings
from .firebase import FirebaseClient, FirebaseError, TemplateUnchangedError
from .keys import InvalidKeyError
from .routers import keys as keys_router
from .service import KeyService
from .store import Store

logger = logging.getLogger("aztec_key_relay")

DAILY_JITTER_SECONDS = 15 * 60


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
    import datetime as dt

    now = dt.datetime.now(dt.UTC)
    target = now.replace(hour=hour_utc, minute=0, second=0, microsecond=0)
    if target <= now:
        target += dt.timedelta(days=1)
    return (target - now).total_seconds() + random.uniform(0, DAILY_JITTER_SECONDS)


async def _daily_refresh_loop(service: KeyService, hour_utc: int) -> None:
    while True:
        wait = _seconds_until_daily(hour_utc)
        logger.info("daily refresh scheduled in %.0f s", wait)
        await asyncio.sleep(wait)
        try:
            await service.refresh(force=True)
        except TemplateUnchangedError:
            logger.info("daily refresh: key unchanged upstream (HTTP 304)")
        except (FirebaseError, InvalidKeyError) as exc:
            logger.warning("daily refresh failed (cached key kept, marked stale): %s", exc)
            await service.mark_stale()


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
        _daily_refresh_loop(app_state.key_service, settings.relay_daily_refresh_hour), name="daily-refresh"
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
    app.include_router(keys_router.router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    async def ready() -> dict[str, bool | str]:
        service = app_state.key_service
        if service is None or app_state.store is None or app_state.store.current_key() is None:
            return {"ready": False}
        return {"ready": True, "stale": service.stale}

    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run("aztec_key_relay.main:app", host="127.0.0.1", port=8000)
