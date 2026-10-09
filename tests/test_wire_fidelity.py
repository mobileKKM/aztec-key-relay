"""Wire-fidelity tests: the upstream requests must match the captured
official-client traffic byte-for-byte (headers, body serialization, ETag).

The expectations are derived from the 2026-10-08 mitmproxy capture of the
official app's Remote Config fetch (documented in mobile_kkm's ekp_crypto).
"""

from __future__ import annotations

import json

import httpx
import pytest
from conftest import REAL_AZTEC_KEY_PEM

from aztec_key_relay.config import Settings
from aztec_key_relay.firebase import FirebaseClient, TemplateUnchangedError

# The exact body the official app sent (capture, 2026-10-08), with the
# instance-specific values parameterized — field ORDER matters (JSONObject
# preserves insertion order).
CAPTURED_BODY_FIELDS = [
    "appInstanceId",
    "appVersion",
    "countryCode",
    "analyticsUserProperties",
    "appId",
    "platformVersion",
    "timeZone",
    "sdkVersion",
    "packageName",
    "appInstanceIdToken",
    "languageCode",
    "appBuild",
]


def captured_headers(request: httpx.Request) -> dict[str, str]:
    return {k.decode(): v.decode() for k, v in request.headers.raw}


@pytest.fixture
def rc_requests() -> list[httpx.Request]:
    return []


def make_client(captured: list[httpx.Request], *, etag: str | None = None, status: int = 200) -> httpx.AsyncClient:
    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        if "firebaseremoteconfig" in request.url.host:
            headers = {"ETag": etag} if etag else {}
            return httpx.Response(status, headers=headers, json={"state": "UPDATE", "entries": {"aztecKey": REAL_AZTEC_KEY_PEM}})
        if request.url.path.endswith("authTokens:generate"):
            return httpx.Response(200, json={"token": "auth-token", "expiresIn": "604800s"})
        return httpx.Response(200, json={"fid": "e" + "f" * 21, "refreshToken": "rt", "expiresIn": "1w"})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_rc_headers_match_capture() -> None:
    captured: list[httpx.Request] = []
    async with make_client(captured) as http:
        client = FirebaseClient(Settings(), http)
        await client.fetch_aztec_key()

    rc = next(r for r in captured if "firebaseremoteconfig" in r.url.host)
    headers = captured_headers(rc)
    # The authoritative set from the captured official-app fetch (miss AND hit).
    assert headers["User-Agent"] == ("Dalvik/2.1.0 (Linux; U; Android 14; Android SDK built for arm64 Build/UE1A.230829.036.A1)")
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"
    assert headers["X-Firebase-RC-Fetch-Type"] == "BASE/1"
    assert headers["X-Google-GFE-Can-Retry"] == "yes"
    assert headers["Accept-Encoding"] == "gzip", "httpx default is 'gzip, deflate'"
    assert headers["Connection"] == "Keep-Alive"
    assert headers["X-Goog-Api-Key"] == Settings().firebase_api_key
    assert headers["X-Android-Package"] == "ANDROID_PACKAGE"
    assert headers["X-Android-Cert"] == "ANDROID_CERT"
    assert headers["X-Goog-Firebase-Installations-Auth"] == "auth-token"
    assert "python-httpx" not in headers.get("User-Agent", "")


async def test_cache_miss_sends_no_if_none_match() -> None:
    """First fetch (no cached ETag) must omit If-None-Match — like the captured miss."""
    captured: list[httpx.Request] = []
    async with make_client(captured, etag="etag-PROJECT_ID-firebase-fetch-CAPTURED_ETAG_NUMBER") as http:
        client = FirebaseClient(Settings(), http)
        await client.fetch_aztec_key()
        await client.fetch_aztec_key()

    first, second = [r for r in captured if "firebaseremoteconfig" in r.url.host]
    assert "If-None-Match" not in captured_headers(first), "miss must not revalidate"
    assert captured_headers(second)["If-None-Match"] == "etag-PROJECT_ID-firebase-fetch-CAPTURED_ETAG_NUMBER"


async def test_rc_body_matches_capture_exactly() -> None:
    captured: list[httpx.Request] = []
    async with make_client(captured) as http:
        client = FirebaseClient(Settings(), http)
        await client.fetch_aztec_key()

    rc = next(r for r in captured if "firebaseremoteconfig" in r.url.host)
    body = json.loads(rc.content)
    # Field presence and ORDER must match the captured official-app body.
    assert list(body.keys()) == CAPTURED_BODY_FIELDS
    assert body["appVersion"] == "1.6.10"
    assert body["countryCode"] == "US"
    assert body["platformVersion"] == "34"
    assert body["timeZone"] == "Europe/Warsaw"
    assert body["languageCode"] == "en-US"
    assert body["appBuild"] == "APP_BUILD"
    assert body["sdkVersion"] == "23.0.0"
    assert body["packageName"] == "ANDROID_PACKAGE"
    assert body["analyticsUserProperties"] == {}
    assert body["appInstanceIdToken"] == "auth-token"


async def test_body_serialization_is_compact_and_escapes_slashes() -> None:
    captured: list[httpx.Request] = []
    async with make_client(captured) as http:
        client = FirebaseClient(Settings(), http)
        await client.fetch_aztec_key()

    rc = next(r for r in captured if "firebaseremoteconfig" in r.url.host)
    raw = rc.content.decode()
    assert ", " not in raw, "JSONObject.toString() is compact — no space after ','"
    assert "Europe\\/Warsaw" in raw, "'/' must be escaped like Android JSONObject"


async def test_etag_revalidation_sent_on_second_fetch() -> None:
    captured: list[httpx.Request] = []
    async with make_client(captured, etag="etag-PROJECT_ID-firebase-fetch-CAPTURED_ETAG_NUMBER") as http:
        client = FirebaseClient(Settings(), http)
        await client.fetch_aztec_key()
        await client.fetch_aztec_key()

    first, second = [r for r in captured if "firebaseremoteconfig" in r.url.host]
    assert "If-None-Match" not in {k.decode() for k in dict(first.headers.raw)}
    assert captured_headers(second).get("If-None-Match") == "etag-PROJECT_ID-firebase-fetch-CAPTURED_ETAG_NUMBER"


async def test_http_304_raises_template_unchanged() -> None:
    captured: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        if "firebaseremoteconfig" in request.url.host:
            return httpx.Response(304, headers={"ETag": "etag-1"})
        if request.url.path.endswith("authTokens:generate"):
            return httpx.Response(200, json={"token": "t", "expiresIn": "1w"})
        return httpx.Response(200, json={"fid": "e" + "f" * 21, "refreshToken": "rt", "expiresIn": "1w"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FirebaseClient(Settings(), http)
        with pytest.raises(TemplateUnchangedError):
            await client.fetch_aztec_key()


async def test_no_change_state_raises_template_unchanged() -> None:
    """The observed revalidation shape: HTTP 200 + {"state": "NO_CHANGE"}."""

    async def handler(request: httpx.Request) -> httpx.Response:
        if "firebaseremoteconfig" in request.url.host:
            return httpx.Response(200, json={"state": "NO_CHANGE", "templateVersion": "16"})
        if request.url.path.endswith("authTokens:generate"):
            return httpx.Response(200, json={"token": "t", "expiresIn": "1w"})
        return httpx.Response(200, json={"fid": "e" + "f" * 21, "refreshToken": "rt", "expiresIn": "1w"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FirebaseClient(Settings(), http)
        with pytest.raises(TemplateUnchangedError):
            await client.fetch_aztec_key()


async def test_installation_requests_headers() -> None:
    captured: list[httpx.Request] = []
    async with make_client(captured) as http:
        client = FirebaseClient(Settings(), http)
        await client.fetch_aztec_key()

    install = next(r for r in captured if "firebaseinstallations" in r.url.host and "authTokens" not in r.url.path)
    headers = captured_headers(install)
    assert headers["User-Agent"].startswith("Dalvik/")
    assert headers["Content-Type"] == "application/json"
    assert headers["X-Goog-Api-Key"] == Settings().firebase_api_key
    assert headers["X-Android-Package"] == "ANDROID_PACKAGE"
    assert headers["X-Android-Cert"] == "ANDROID_CERT"
    assert headers["Accept-Encoding"] == "gzip"
    body = json.loads(install.content)
    assert list(body.keys()) == ["fid", "appId", "authVersion"]
    assert body["fid"][0] in "cdef"
    assert len(body["fid"]) == 22
