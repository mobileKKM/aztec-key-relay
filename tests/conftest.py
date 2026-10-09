"""Shared test fixtures: synthetic RSA keys and an app-with-fake-upstream factory."""

from __future__ import annotations

import os

import httpx
from fastapi.testclient import TestClient

from aztec_key_relay import main
from aztec_key_relay.config import get_settings
from aztec_key_relay.keys import fingerprint, parse_public_key

# The currently deployed aztecKey from mobile_kkm's ekp_crypto — a public
# value embedded in the official APK, used as a realistic test vector.
REAL_AZTEC_KEY_PEM = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4NgeDRNowqtK1GC3UgDkTquMtb2P0SFNsi54OWcvYtihKuOsr+Ye
K9UmDmfK5xCRzBmwJ3uMrjVFnqNTW2eFIxB0rqS2qo0p7XrRJLQ7By96L7fYJn4g
j4/IUER4vu/wLYzQMlCKD2mTtM6M2AaJA/otrbwPIintebttEfZ3oEvTmeifTYNP
MI648Zte140yVa0sipEr4Tjb26+lFn6hBT5pK+g7tuRBToiWPD1db+ysOcQx0PwL
WAO5E/7EfJM0kveA8t+SxXPiA6JR95sm5l8NE2mdjP/cRCw4qIiz7AKJqUMduKDw
gwLOkQXwSjXHNDR0q/N4dvfb97/hyea8ZwIDAQAB
-----END RSA PUBLIC KEY-----
"""


def generate_pkcs1_pem(bits: int = 2048) -> str:
    """Generates a fresh RSA keypair, returns the public key as PKCS#1 PEM."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1).decode()


def fingerprint_of(pem: str) -> str:
    return fingerprint(parse_public_key(pem))


class FakeFirebase:
    """httpx.MockTransport-based upstream: serves keys from a rotating list."""

    def __init__(self, keys: list[str]) -> None:
        self.keys = keys
        self.installations_created = 0
        self.auth_tokens_generated = 0
        self.rc_fetches = 0
        self.fail_next_rc = False
        self.rc_failures_remaining = 0
        self.etag_304_next = False

        async def handler(request: httpx.Request) -> httpx.Response:
            url = request.url
            if url.host == "firebaseinstallations.googleapis.com" and url.path.endswith("/authTokens:generate"):
                self.auth_tokens_generated += 1
                return httpx.Response(200, json={"token": "tok-1", "expiresIn": "604800s"})
            if url.host == "firebaseinstallations.googleapis.com":
                self.installations_created += 1
                return httpx.Response(200, json={"fid": "f" * 22, "refreshToken": "rt-1", "expiresIn": "1w"})
            if url.host == "firebaseremoteconfig.googleapis.com":
                if self.fail_next_rc or self.rc_failures_remaining > 0:
                    self.fail_next_rc = False
                    if self.rc_failures_remaining > 0:
                        self.rc_failures_remaining -= 1
                    return httpx.Response(500, text="boom")
                if self.etag_304_next:
                    self.etag_304_next = False
                    return httpx.Response(304, headers={"ETag": "etag-1"})
                self.rc_fetches += 1
                key = self.keys[min(self.rc_fetches - 1, len(self.keys) - 1)]
                return httpx.Response(
                    200,
                    headers={"ETag": "etag-1"},
                    json={"state": "UPDATE", "entries": {"aztecKey": key}},
                )
            return httpx.Response(404, text=f"unexpected {url.host}")

        self.transport = httpx.MockTransport(handler)


def build_app(
    keys: list[str],
    *,
    api_token: str | None = None,
    min_fetch_interval: int = 0,
    db_dir: str | None = None,
) -> tuple[TestClient, FakeFirebase]:
    """Builds a TestClient whose upstream is FakeFirebase.

    Settings flow through real env vars (pydantic-settings reads them), so
    the router's `Depends(get_settings)` sees the same values as lifespan.
    """
    fake = FakeFirebase(keys)
    env = {
        "RELAY_MIN_FETCH_INTERVAL": str(min_fetch_interval),
        "RELAY_DAILY_REFRESH_HOUR": "4",
    }
    if api_token:
        env["RELAY_API_TOKEN"] = api_token
    if db_dir:
        env["RELAY_DB_PATH"] = os.path.join(db_dir, "state.db")

    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    get_settings.cache_clear()
    try:
        client = TestClient(main.create_app(transport=fake.transport))
        client.__enter__()
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        get_settings.cache_clear()
    return client, fake
