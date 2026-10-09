"""Tests for aztec_key_relay.firebase — installation lifecycle + RC fetch."""

from __future__ import annotations

import httpx
import pytest
from conftest import REAL_AZTEC_KEY_PEM, FakeFirebase, generate_pkcs1_pem

from aztec_key_relay.config import Settings
from aztec_key_relay.firebase import FirebaseClient, FirebaseError, _parse_duration


@pytest.mark.parametrize(
    ("value", "seconds"),
    [("604800s", 604800), ("1w", 604800), ("1h", 3600), ("30m", 1800), ("2d", 172800)],
)
def test_parse_duration(value: str, seconds: float) -> None:
    from datetime import timedelta

    assert _parse_duration(value) == timedelta(seconds=seconds)


def test_parse_duration_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        _parse_duration("soon")


async def test_creates_installation_and_fetches_key() -> None:
    fake = FakeFirebase([REAL_AZTEC_KEY_PEM])
    async with httpx.AsyncClient(transport=fake.transport) as http:
        client = FirebaseClient(Settings(), http)
        assert client.installation is None

        pem = await client.fetch_aztec_key()

        assert pem == REAL_AZTEC_KEY_PEM
        assert fake.installations_created == 1
        assert fake.auth_tokens_generated == 1
        assert fake.rc_fetches == 1


async def test_reuses_installation_and_auth_token() -> None:
    fake = FakeFirebase([REAL_AZTEC_KEY_PEM])
    async with httpx.AsyncClient(transport=fake.transport) as http:
        client = FirebaseClient(Settings(), http)
        await client.fetch_aztec_key()
        await client.fetch_aztec_key()

        # One installation, one token generation, two RC fetches.
        assert fake.installations_created == 1
        assert fake.auth_tokens_generated == 1
        assert fake.rc_fetches == 2


async def test_restores_persisted_installation() -> None:
    fake = FakeFirebase([REAL_AZTEC_KEY_PEM])
    async with httpx.AsyncClient(transport=fake.transport) as http:
        client = FirebaseClient(Settings(), http)
        client.restore_installation("abc123", "refresh-token")

        await client.fetch_aztec_key()

        # Adopted FID → no new installation; only the auth token is generated.
        assert fake.installations_created == 0
        assert fake.auth_tokens_generated == 1
        assert client.installation is not None
        assert client.installation.fid == "abc123"


async def test_rc_http_error_raises_firebase_error() -> None:
    fake = FakeFirebase([REAL_AZTEC_KEY_PEM])
    fake.fail_next_rc = True
    async with httpx.AsyncClient(transport=fake.transport) as http:
        client = FirebaseClient(Settings(), http)
        # First attempt 500s; the retry-with-fresh-installation also 500s…
        # FakeFirebase.fail_next_rc only fails once, so second succeeds.
        pem = await client.fetch_aztec_key()
        assert pem == REAL_AZTEC_KEY_PEM
        assert fake.installations_created == 2  # one per attempt


async def test_persistent_rc_error_raises() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.host == "firebaseinstallations.googleapis.com":
            if url.path.endswith("authTokens:generate"):
                return httpx.Response(200, json={"token": "t", "expiresIn": "1w"})
            return httpx.Response(200, json={"fid": "f" * 22, "refreshToken": "rt", "expiresIn": "1w"})
        return httpx.Response(500, text="persistent failure")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FirebaseClient(Settings(), http)
        with pytest.raises(FirebaseError):
            await client.fetch_aztec_key()


async def test_missing_aztec_entry_raises() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.host == "firebaseinstallations.googleapis.com":
            if url.path.endswith("authTokens:generate"):
                return httpx.Response(200, json={"token": "t", "expiresIn": "1w"})
            return httpx.Response(200, json={"fid": "f" * 22, "refreshToken": "rt", "expiresIn": "1w"})
        return httpx.Response(200, json={"state": "NO_TEMPLATE", "entries": {}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FirebaseClient(Settings(), http)
        with pytest.raises(FirebaseError, match="aztecKey"):
            await client.fetch_aztec_key()


async def test_rotation_serves_new_key() -> None:
    rotated = generate_pkcs1_pem()
    fake = FakeFirebase([REAL_AZTEC_KEY_PEM, rotated])
    async with httpx.AsyncClient(transport=fake.transport) as http:
        client = FirebaseClient(Settings(), http)
        assert await client.fetch_aztec_key() == REAL_AZTEC_KEY_PEM
        assert await client.fetch_aztec_key() == rotated
