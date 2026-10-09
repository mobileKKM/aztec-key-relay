"""Key lifecycle service: fetch → validate → persist → serve.

Guarantees:
* a failed fetch **never** evicts the last good key — callers see it with
  ``stale: true`` so the app can warn/retry,
* only one upstream fetch runs at a time (single-flight),
* refreshes are rate-limited to [Settings.relay_min_fetch_interval] seconds
  so a fleet of failing clients can't hammer Firebase,
* the persisted installation (FID) is restored on boot and saved on change.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from .config import Settings
from .firebase import FirebaseClient, TemplateUnchangedError
from .keys import InvalidKeyError, KeyRecord, parse_public_key, validate_aztec_key
from .store import Store

logger = logging.getLogger(__name__)


class KeyUnavailableError(RuntimeError):
    """No key has ever been fetched successfully."""


class RefreshRateLimitedError(RuntimeError):
    """A fetch ran too recently; includes the seconds to wait."""

    def __init__(self, retry_after: float) -> None:
        super().__init__(f"refresh rate limited; retry after {retry_after:.0f}s")
        self.retry_after = retry_after


@dataclass(slots=True)
class KeyEnvelope:
    """The wire shape served by the API."""

    pem: str
    fingerprint_sha256: str
    fetched_at: str
    age_seconds: int
    version: int
    stale: bool
    bits: int

    @classmethod
    def of(cls, record: KeyRecord, *, stale: bool, bits: int) -> KeyEnvelope:
        return cls(
            pem=record.pem,
            fingerprint_sha256=record.fingerprint,
            fetched_at=record.fetched_at.isoformat(),
            age_seconds=record.age_seconds(),
            version=record.version,
            stale=stale,
            bits=bits,
        )


class KeyService:
    def __init__(self, settings: Settings, firebase: FirebaseClient, store: Store) -> None:
        self._settings = settings
        self._firebase = firebase
        self._store = store
        self._lock = asyncio.Lock()
        self._last_fetch_attempt: float | None = None
        self._stale = False

    @property
    def stale(self) -> bool:
        return self._stale

    def restore_installation(self) -> None:
        """Adopts the persisted FID (if any) so we reuse one identity."""
        state = self._store.load_fid_state()
        if state:
            self._firebase.restore_installation(*state)
            logger.info("restored Firebase installation %s…", state[0][:8])

    def _persist_installation(self) -> None:
        """Saves the current installation so it survives restarts."""
        installation = self._firebase.installation
        if installation is None:
            return
        self._store.save_fid_state(
            fid=installation.fid,
            refresh_token=installation.refresh_token,
            auth_token=installation.auth.token if installation.auth else None,
            auth_expires_at=installation.auth.expires_at if installation.auth else None,
        )

    async def refresh(self, *, force: bool = False) -> KeyEnvelope:
        """Fetches, validates and stores the key; single-flight.

        [force] bypasses the min-interval rate limit (used by the daily
        scheduler). Raises [RefreshRateLimitedError] / [FirebaseError] /
        [InvalidKeyError].
        """
        async with self._lock:
            now = time.monotonic()
            if not force and self._last_fetch_attempt is not None:
                elapsed = now - self._last_fetch_attempt
                min_interval = self._settings.relay_min_fetch_interval
                if elapsed < min_interval:
                    raise RefreshRateLimitedError(min_interval - elapsed)
            self._last_fetch_attempt = now

            try:
                raw = await self._firebase.fetch_aztec_key()
            except TemplateUnchangedError:
                # 304: upstream confirmed our cached key is still current.
                current = await self.current()
                self._stale = False
                logger.info("key unchanged upstream (HTTP 304)")
                return current
            key, fingerprint = validate_aztec_key(raw)
            was_stale = self._stale
            record = self._store.save_key(
                pem=raw,
                fingerprint=fingerprint,
                fetched_at=datetime.now(UTC),
                max_history=self._settings.relay_key_history,
            )
            self._persist_installation()
            self._stale = False
            logger.info(
                "key %s (fingerprint %s…, %d bits)",
                "recovered" if was_stale else "ok",
                fingerprint[:12],
                key.key_size,
            )
            return KeyEnvelope.of(record, stale=False, bits=key.key_size)

    async def current(self) -> KeyEnvelope:
        """Serves the cached key; 503-shaped error if none exists yet."""
        record = self._store.current_key()
        if record is None:
            raise KeyUnavailableError("no key fetched yet")
        try:
            bits = parse_public_key(record.pem).key_size
        except InvalidKeyError:
            logger.error("cached key no longer parses — refusing to serve")
            raise KeyUnavailableError("cached key invalid") from None
        return KeyEnvelope.of(record, stale=self._stale, bits=bits)

    async def mark_stale(self) -> None:
        """Flags the cached key as suspect (used after a failed refresh)."""
        self._stale = True
