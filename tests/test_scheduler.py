"""Tests for the refresh scheduler: recovery retries and resilience."""

from __future__ import annotations

import asyncio

from aztec_key_relay import main


class FlakyService:
    """Fails its first refreshes in different ways, then recovers."""

    def __init__(self, failures: list[Exception]) -> None:
        self.failures = failures
        self.calls = 0
        self.stale = True

    @property
    def needs_recovery(self) -> bool:
        return self.stale

    async def refresh(self, *, force: bool = False) -> None:
        assert force
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        self.stale = False

    def mark_stale(self) -> None:
        self.stale = True


async def test_recovery_retries_until_a_key_is_fetched(monkeypatch) -> None:
    monkeypatch.setattr(main, "RECOVERY_MIN_SECONDS", 0.001)
    monkeypatch.setattr(main, "RECOVERY_MAX_SECONDS", 0.004)
    service = FlakyService([main.FirebaseError("upstream down"), RuntimeError("disk on fire")])

    task = asyncio.create_task(main._refresh_loop(service, hour_utc=4))
    try:
        for _ in range(200):
            if not service.needs_recovery:
                break
            await asyncio.sleep(0.005)
        # A FirebaseError and an unexpected error did not end the loop.
        assert service.calls == 3
        assert not task.done()
    finally:
        task.cancel()
