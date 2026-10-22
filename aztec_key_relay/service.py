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
from .firebase import FirebaseClient, FirebaseError, TemplateUnchangedError
from .keys import InvalidKeyError, KeyRecord, parse_public_key, validate_aztec_key
from .store import Store

logger = logging.getLogger(__name__)


class KeyUnavailableError(RuntimeError):
    """No key has ever been fetched successfully."""


class RefreshRateLimitedError(RuntimeError):
    """A fetch failed too recently; includes the seconds to wait."""

    def __init__(self, retry_after: float) -> None:
        super().__init__(f"refresh rate limited; retry after {retry_after:.0f}s")
        self.retry_after = retry_after


@dataclass(slots=True)
class KeyEnvelope:
    """The wire shape served by the API."""

    pem: str
    fingerprint_sha256: str
    fetched_at: str
    last_checked_at: str
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
            last_checked_at=record.last_checked_at.isoformat(),
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
        self._last_fetch_ok = False
        self._stale = False
        # (fingerprint, bits) of the last cached key that parsed — so GETs
        # don't re-parse the PEM every time.
        self._checked_key: tuple[str, int] | None = None

    @property
    def stale(self) -> bool:
        return self._stale

    @property
    def needs_recovery(self) -> bool:
        """True while there is no usable key or the last refresh failed."""
        return self._stale or self._store.current_key() is None

    def restore_installation(self) -> None:
        """Adopts the persisted FID (and auth token) so we reuse one identity."""
        state = self._store.load_fid_state()
        if state:
            self._firebase.restore_installation(state.fid, state.refresh_token, state.auth_token, state.auth_expires_at)
            logger.info("restored Firebase installation %s…", state.fid[:8])

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

        Inside the min-interval window, a caller gets the just-checked key if
        the last fetch succeeded, or [RefreshRateLimitedError] if it failed.
        [force] skips the window (scheduler). Raises [RefreshRateLimitedError]
        / [FirebaseError] / [InvalidKeyError]; the last two mark the key stale.
        """
        async with self._lock:
            now = time.monotonic()
            if not force and self._last_fetch_attempt is not None:
                elapsed = now - self._last_fetch_attempt
                min_interval = self._settings.relay_min_fetch_interval
                if elapsed < min_interval:
                    if self._last_fetch_ok:
                        return await self.current()
                    raise RefreshRateLimitedError(min_interval - elapsed)
            self._last_fetch_attempt = now
            self._last_fetch_ok = False
            try:
                envelope = await self._fetch_and_store()
            except (FirebaseError, InvalidKeyError):
                self._stale = True
                raise
            self._last_fetch_ok = True
            self._stale = False
            return envelope

    async def _fetch_and_store(self) -> KeyEnvelope:
        try:
            raw = await self._firebase.fetch_aztec_key()
        except TemplateUnchangedError:
            self._persist_installation()
            if self._store.current_key() is None:
                # Nothing to fall back on — drop the ETag so the next fetch
                # returns the full template.
                self._firebase.clear_etag()
                raise FirebaseError("upstream reported no change, but no key is cached") from None
            self._store.touch_current(datetime.now(UTC))
            logger.info("key unchanged upstream (HTTP 304)")
            return await self.current()

        # The upstream exchange worked — keep this installation even if the
        # key turns out to be unusable.
        self._persist_installation()
        key, fingerprint = validate_aztec_key(raw)
        record = self._store.save_key(
            pem=raw,
            fingerprint=fingerprint,
            fetched_at=datetime.now(UTC),
            max_history=self._settings.relay_key_history,
        )
        self._firebase.commit_etag()
        self._checked_key = (fingerprint, key.key_size)
        logger.info(
            "key %s (fingerprint %s…, %d bits, version %d)",
            "recovered" if self._stale else "ok",
            fingerprint[:12],
            key.key_size,
            record.version,
        )
        return KeyEnvelope.of(record, stale=False, bits=key.key_size)

    async def current(self) -> KeyEnvelope:
        """Serves the cached key; 503-shaped error if none exists yet."""
        record = self._store.current_key()
        if record is None:
            raise KeyUnavailableError("no key fetched yet")
        if self._checked_key is None or self._checked_key[0] != record.fingerprint:
            try:
                bits = parse_public_key(record.pem).key_size
            except InvalidKeyError:
                logger.error("cached key no longer parses — refusing to serve")
                raise KeyUnavailableError("cached key invalid") from None
            self._checked_key = (record.fingerprint, bits)
        return KeyEnvelope.of(record, stale=self._stale, bits=self._checked_key[1])

    def mark_stale(self) -> None:
        """Flags the cached key as suspect (after an unexpected refresh error)."""
        self._stale = True
