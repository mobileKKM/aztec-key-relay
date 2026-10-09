"""Tests for the FastAPI surface — cache serving, refresh, rate limit, auth."""

from __future__ import annotations

import os

from conftest import REAL_AZTEC_KEY_PEM, build_app, generate_pkcs1_pem


def test_startup_fetches_when_cache_empty(tmp_path) -> None:
    client, fake = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        # Lifespan fetched once on startup (no cached key).
        assert fake.rc_fetches == 1
        body = client.get("/v1/aztec-key").json()
        assert body["pem"] == REAL_AZTEC_KEY_PEM
        assert body["bits"] == 2048
        assert body["stale"] is False
        assert body["version"] == 1
        assert len(body["fingerprint_sha256"]) == 64
        assert client.get("/ready").json() == {"ready": True, "stale": False}
    finally:
        client.__exit__(None, None, None)


def test_get_never_triggers_fetch(tmp_path) -> None:
    client, fake = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        assert fake.rc_fetches == 1
        for _ in range(5):
            assert client.get("/v1/aztec-key").status_code == 200
        assert fake.rc_fetches == 1  # unchanged
    finally:
        client.__exit__(None, None, None)


def test_refresh_rotates_key_and_bumps_version(tmp_path) -> None:
    rotated = generate_pkcs1_pem()
    client, _ = build_app([REAL_AZTEC_KEY_PEM, rotated], min_fetch_interval=0, db_dir=str(tmp_path))
    try:
        first = client.get("/v1/aztec-key").json()
        second = client.post("/v1/aztec-key/refresh").json()
        assert second["pem"] == rotated
        assert second["fingerprint_sha256"] != first["fingerprint_sha256"]
        assert second["version"] == 2
        assert client.get("/v1/aztec-key").json()["pem"] == rotated
    finally:
        client.__exit__(None, None, None)


def test_refresh_rate_limited(tmp_path) -> None:
    client, fake = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=60, db_dir=str(tmp_path))
    try:
        # Startup fetch already ran; an immediate refresh is rate limited.
        response = client.post("/v1/aztec-key/refresh")
        assert response.status_code == 429
        assert "Retry-After" in response.headers
        assert fake.rc_fetches == 1  # no extra upstream call
    finally:
        client.__exit__(None, None, None)


def test_failed_refresh_keeps_old_key_and_marks_stale(tmp_path) -> None:
    client, fake = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=0, db_dir=str(tmp_path))
    try:
        # Both retry attempts fail (fresh-installation retry included).
        fake.rc_failures_remaining = 99
        response = client.post("/v1/aztec-key/refresh")
        assert response.status_code == 502

        body = client.get("/v1/aztec-key").json()
        assert body["pem"] == REAL_AZTEC_KEY_PEM  # old key still served
        assert body["stale"] is True
        assert client.get("/ready").json() == {"ready": True, "stale": True}
    finally:
        client.__exit__(None, None, None)


def test_persisted_key_skips_startup_fetch(tmp_path) -> None:
    # First boot: fetches and persists to tmp_path/state.db.
    client1, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    client1.__exit__(None, None, None)

    # Second boot against the same db: no startup fetch.
    client2, fake2 = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        assert fake2.rc_fetches == 0
        assert client2.get("/v1/aztec-key").json()["pem"] == REAL_AZTEC_KEY_PEM
    finally:
        client2.__exit__(None, None, None)


def test_persisted_installation_is_restored(tmp_path) -> None:
    client1, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    client1.__exit__(None, None, None)

    client2, fake2 = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        # db has a cached key → no startup RC fetch; force a refresh and
        # check no new installation was created (FID restored from disk).
        client2.post("/v1/aztec-key/refresh")
        assert fake2.installations_created == 0
        assert fake2.rc_fetches == 1
    finally:
        client2.__exit__(None, None, None)


def test_api_token_required_when_configured(tmp_path) -> None:
    client, _ = build_app([REAL_AZTEC_KEY_PEM], api_token="sekrit", db_dir=str(tmp_path))
    try:
        assert client.get("/v1/aztec-key").status_code == 401
        assert client.post("/v1/aztec-key/refresh").status_code == 401
        ok = client.get("/v1/aztec-key", headers={"Authorization": "Bearer sekrit"})
        assert ok.status_code == 200
    finally:
        client.__exit__(None, None, None)


def test_open_when_no_token_configured(tmp_path) -> None:
    client, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        assert client.get("/v1/aztec-key").status_code == 200
    finally:
        client.__exit__(None, None, None)


def test_health_endpoint(tmp_path) -> None:
    client, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        assert client.get("/health").json() == {"status": "ok"}
    finally:
        client.__exit__(None, None, None)


def test_get_cache_control_headers(tmp_path) -> None:
    """Open mode: public + max-age — intermediary caches may serve repeats."""
    client, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        response = client.get("/v1/aztec-key")
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "public, max-age=300"
    finally:
        client.__exit__(None, None, None)


def test_get_cache_control_private_when_auth_enabled(tmp_path) -> None:
    """Bearer-auth mode: private — shared caches must not store token responses."""
    client, _ = build_app([REAL_AZTEC_KEY_PEM], api_token="sekrit", db_dir=str(tmp_path))
    try:
        response = client.get("/v1/aztec-key", headers={"Authorization": "Bearer sekrit"})
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "private, max-age=300"
    finally:
        client.__exit__(None, None, None)


def test_refresh_responses_are_never_cacheable(tmp_path) -> None:
    # 429 (rate limited) must not be cached.
    client, _ = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=60, db_dir=str(tmp_path))
    try:
        rate_limited = client.post("/v1/aztec-key/refresh")
        assert rate_limited.status_code == 429
        assert rate_limited.headers["Cache-Control"] == "no-store"
    finally:
        client.__exit__(None, None, None)

    # 502 (upstream failure) must not be cached either.
    client2, fake2 = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=0, db_dir=str(tmp_path))
    try:
        fake2.rc_failures_remaining = 99
        failed = client2.post("/v1/aztec-key/refresh")
        assert failed.status_code == 502
        assert failed.headers["Cache-Control"] == "no-store"
    finally:
        client2.__exit__(None, None, None)


def test_503_when_no_key_is_not_cacheable(tmp_path) -> None:
    """A cached 503 would mask a fast recovery — must be no-store."""
    # Startup fetch fails → no key cached → GET serves 503.
    empty_dir = str(tmp_path) + "_empty"
    os.makedirs(empty_dir, exist_ok=True)

    def arm_failures(fake) -> None:
        fake.rc_failures_remaining = 99

    client, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=empty_dir, pre_arm=arm_failures)
    try:
        response = client.get("/v1/aztec-key")
        assert response.status_code == 503
        assert response.headers["Cache-Control"] == "no-store"
    finally:
        client.__exit__(None, None, None)


def test_304_during_refresh_serves_cached_key(tmp_path) -> None:
    """A 304 upstream means 'unchanged' — the API returns the cached key, 200."""
    client, fake = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=0, db_dir=str(tmp_path))
    try:
        fake.etag_304_next = True
        response = client.post("/v1/aztec-key/refresh")
        assert response.status_code == 200
        assert response.json()["pem"] == REAL_AZTEC_KEY_PEM
        assert response.json()["stale"] is False
    finally:
        client.__exit__(None, None, None)
