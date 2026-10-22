"""Tests for the FastAPI surface — cache serving, refresh, rate limit, auth."""

from __future__ import annotations

import os
import sqlite3

from conftest import REAL_AZTEC_KEY_PEM, build_app, fingerprint_of, generate_pkcs1_pem


def _fail_rc(fake) -> None:
    fake.rc_failures_remaining = 99


def test_startup_fetches_when_cache_empty(tmp_path) -> None:
    client, fake = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        # Lifespan fetched once on startup (no cached key).
        assert fake.rc_fetches == 1
        body = client.get("/api/v1/aztec-key").json()
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
            assert client.get("/api/v1/aztec-key").status_code == 200
        assert fake.rc_fetches == 1  # unchanged
    finally:
        client.__exit__(None, None, None)


def test_refresh_rotates_key_and_bumps_version(tmp_path) -> None:
    rotated = generate_pkcs1_pem()
    client, _ = build_app([REAL_AZTEC_KEY_PEM, rotated], min_fetch_interval=0, db_dir=str(tmp_path))
    try:
        first = client.get("/api/v1/aztec-key").json()
        second = client.post("/api/v1/aztec-key/refresh").json()
        assert second["pem"] == rotated
        assert second["fingerprint_sha256"] != first["fingerprint_sha256"]
        assert second["version"] == 2
        assert client.get("/api/v1/aztec-key").json()["pem"] == rotated
    finally:
        client.__exit__(None, None, None)


def test_refresh_inside_window_after_success_returns_key(tmp_path) -> None:
    client, fake = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=60, db_dir=str(tmp_path))
    try:
        # Startup fetch just succeeded → a refresh inside the window gets that key.
        response = client.post("/api/v1/aztec-key/refresh")
        assert response.status_code == 200
        assert response.json()["pem"] == REAL_AZTEC_KEY_PEM
        assert fake.rc_fetches == 1  # no extra upstream call
    finally:
        client.__exit__(None, None, None)


def test_refresh_inside_window_after_failure_is_rate_limited(tmp_path) -> None:
    client, fake = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=60, db_dir=str(tmp_path), pre_arm=_fail_rc)
    try:
        response = client.post("/api/v1/aztec-key/refresh")
        assert response.status_code == 429
        assert "Retry-After" in response.headers
        assert fake.rc_fetches == 0
    finally:
        client.__exit__(None, None, None)


def test_failed_refresh_keeps_old_key_and_marks_stale(tmp_path) -> None:
    client, fake = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=0, db_dir=str(tmp_path))
    try:
        # Both retry attempts fail (fresh-installation retry included).
        fake.rc_failures_remaining = 99
        response = client.post("/api/v1/aztec-key/refresh")
        assert response.status_code == 502

        body = client.get("/api/v1/aztec-key").json()
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
        assert client2.get("/api/v1/aztec-key").json()["pem"] == REAL_AZTEC_KEY_PEM
    finally:
        client2.__exit__(None, None, None)


def test_persisted_installation_is_restored(tmp_path) -> None:
    client1, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    client1.__exit__(None, None, None)

    client2, fake2 = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        # db has a cached key → no startup RC fetch; force a refresh and
        # check no new installation was created (FID restored from disk).
        client2.post("/api/v1/aztec-key/refresh")
        assert fake2.installations_created == 0
        assert fake2.rc_fetches == 1
    finally:
        client2.__exit__(None, None, None)


def test_api_token_required_when_configured(tmp_path) -> None:
    client, _ = build_app([REAL_AZTEC_KEY_PEM], api_token="sekrit", db_dir=str(tmp_path))
    try:
        assert client.get("/api/v1/aztec-key").status_code == 401
        assert client.post("/api/v1/aztec-key/refresh").status_code == 401
        ok = client.get("/api/v1/aztec-key", headers={"Authorization": "Bearer sekrit"})
        assert ok.status_code == 200
    finally:
        client.__exit__(None, None, None)


def test_open_when_no_token_configured(tmp_path) -> None:
    client, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        assert client.get("/api/v1/aztec-key").status_code == 200
    finally:
        client.__exit__(None, None, None)


def test_health_endpoint(tmp_path) -> None:
    client, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        assert client.get("/health").json() == {"status": "ok"}
    finally:
        client.__exit__(None, None, None)


def test_get_has_etag_and_no_max_age(tmp_path) -> None:
    client, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        response = client.get("/api/v1/aztec-key")
        assert response.status_code == 200
        assert "ETag" in response.headers
        assert "Cache-Control" not in response.headers
    finally:
        client.__exit__(None, None, None)


def test_swagger_declares_bearer_scheme(tmp_path) -> None:
    client, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        schema = client.get("/openapi.json").json()
        assert schema["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"
    finally:
        client.__exit__(None, None, None)


def test_refresh_responses_are_never_cacheable(tmp_path) -> None:
    client, fake = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=0, db_dir=str(tmp_path))
    try:
        ok = client.post("/api/v1/aztec-key/refresh")
        assert ok.status_code == 200
        assert ok.headers["Cache-Control"] == "no-store"
        assert ok.headers["ETag"] == client.get("/api/v1/aztec-key").headers["ETag"]

        fake.rc_failures_remaining = 99
        failed = client.post("/api/v1/aztec-key/refresh")
        assert failed.status_code == 502
        assert failed.headers["Cache-Control"] == "no-store"
    finally:
        client.__exit__(None, None, None)

    # 429 (rate limited) must not be cached either.
    empty_dir = tmp_path / "empty"
    client2, _ = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=60, db_dir=str(empty_dir), pre_arm=_fail_rc)
    try:
        rate_limited = client2.post("/api/v1/aztec-key/refresh")
        assert rate_limited.status_code == 429
        assert rate_limited.headers["Cache-Control"] == "no-store"
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
        response = client.get("/api/v1/aztec-key")
        assert response.status_code == 503
        assert response.headers["Cache-Control"] == "no-store"
    finally:
        client.__exit__(None, None, None)


def test_304_during_refresh_serves_cached_key(tmp_path) -> None:
    """A 304 upstream means 'unchanged' — the API returns the cached key, 200."""
    client, fake = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=0, db_dir=str(tmp_path))
    try:
        fake.etag_304_next = True
        response = client.post("/api/v1/aztec-key/refresh")
        assert response.status_code == 200
        assert response.json()["pem"] == REAL_AZTEC_KEY_PEM
        assert response.json()["stale"] is False
    finally:
        client.__exit__(None, None, None)


def test_ready_is_503_without_key(tmp_path) -> None:
    client, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path), pre_arm=_fail_rc)
    try:
        response = client.get("/ready")
        assert response.status_code == 503
        assert response.json() == {"ready": False}
    finally:
        client.__exit__(None, None, None)


def test_conditional_get(tmp_path) -> None:
    client, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        first = client.get("/api/v1/aztec-key")
        etag = first.headers["ETag"]
        assert etag == f'"{fingerprint_of(REAL_AZTEC_KEY_PEM)}"'

        cached = client.get("/api/v1/aztec-key", headers={"If-None-Match": etag})
        assert cached.status_code == 304
        assert cached.content == b""
        assert cached.headers["ETag"] == etag

        other = client.get("/api/v1/aztec-key", headers={"If-None-Match": '"something-else"'})
        assert other.status_code == 200
    finally:
        client.__exit__(None, None, None)


def test_502_does_not_leak_upstream_details(tmp_path) -> None:
    client, fake = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=0, db_dir=str(tmp_path))
    try:
        fake.rc_failures_remaining = 99
        response = client.post("/api/v1/aztec-key/refresh")
        assert response.status_code == 502
        assert response.json() == {"detail": "upstream fetch failed"}
    finally:
        client.__exit__(None, None, None)


def test_304_without_cached_key_is_a_failure_not_a_crash(tmp_path) -> None:
    def arm_304(fake) -> None:
        fake.etag_304_next = True

    # Startup survives the 304 (no key to fall back on) …
    client, _ = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=0, db_dir=str(tmp_path), pre_arm=arm_304)
    try:
        assert client.get("/api/v1/aztec-key").status_code == 503
        # … and the next refresh fetches the full template.
        response = client.post("/api/v1/aztec-key/refresh")
        assert response.status_code == 200
        assert response.json()["pem"] == REAL_AZTEC_KEY_PEM
    finally:
        client.__exit__(None, None, None)


def test_rejected_key_does_not_commit_etag(tmp_path) -> None:
    client, fake = build_app([REAL_AZTEC_KEY_PEM, "not a key", "not a key"], min_fetch_interval=0, db_dir=str(tmp_path))
    try:
        assert client.post("/api/v1/aztec-key/refresh").status_code == 502
        assert client.post("/api/v1/aztec-key/refresh").status_code == 502
        # Startup committed etag-1; the rejected fetch must not replace it with
        # a "known" state — the request after it still revalidates against the
        # last *good* template, and the key stays stale until a good fetch.
        assert client.get("/api/v1/aztec-key").json()["stale"] is True
        assert [r.headers.get("If-None-Match") for r in fake.rc_requests] == [None, "etag-1", "etag-1"]
    finally:
        client.__exit__(None, None, None)


def test_rollback_to_previous_key_is_served(tmp_path) -> None:
    key_b = generate_pkcs1_pem()
    client, _ = build_app([REAL_AZTEC_KEY_PEM, key_b, REAL_AZTEC_KEY_PEM], min_fetch_interval=0, db_dir=str(tmp_path))
    try:
        assert client.post("/api/v1/aztec-key/refresh").json()["pem"] == key_b
        back = client.post("/api/v1/aztec-key/refresh").json()
        assert back["pem"] == REAL_AZTEC_KEY_PEM
        assert back["version"] == 3
        assert client.get("/api/v1/aztec-key").json()["pem"] == REAL_AZTEC_KEY_PEM
    finally:
        client.__exit__(None, None, None)


def test_same_key_refetch_updates_last_checked_only(tmp_path) -> None:
    client, _ = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=0, db_dir=str(tmp_path))
    try:
        first = client.get("/api/v1/aztec-key").json()
        again = client.post("/api/v1/aztec-key/refresh").json()
        assert again["version"] == first["version"]
        assert again["fetched_at"] == first["fetched_at"]
        assert again["last_checked_at"] > first["last_checked_at"]
    finally:
        client.__exit__(None, None, None)


def test_restart_reuses_persisted_auth_token(tmp_path) -> None:
    client1, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    client1.__exit__(None, None, None)

    client2, fake2 = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        assert client2.post("/api/v1/aztec-key/refresh").status_code == 200
        assert fake2.installations_created == 0
        assert fake2.auth_tokens_generated == 0
    finally:
        client2.__exit__(None, None, None)


def test_new_installation_is_persisted_after_304(tmp_path) -> None:
    client1, _ = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    client1.__exit__(None, None, None)
    with sqlite3.connect(tmp_path / "state.db") as conn:
        conn.execute("UPDATE fid_state SET auth_token = NULL, auth_expires_at = NULL")

    def revoke_then_304(fake) -> None:
        fake.auth_token_statuses = [404]  # stored installation was revoked
        fake.etag_304_next = True  # the replacement only ever sees a 304

    client2, fake2 = build_app([REAL_AZTEC_KEY_PEM], min_fetch_interval=0, db_dir=str(tmp_path), pre_arm=revoke_then_304)
    try:
        assert client2.post("/api/v1/aztec-key/refresh").status_code == 200
        assert fake2.installations_created == 1
    finally:
        client2.__exit__(None, None, None)

    # The replacement installation (with its fresh token) reached the disk.
    with sqlite3.connect(tmp_path / "state.db") as conn:
        assert conn.execute("SELECT auth_token FROM fid_state").fetchone()[0] == "tok-1"


def test_old_database_is_migrated(tmp_path) -> None:
    db = tmp_path / "state.db"
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """
            CREATE TABLE key_history (id INTEGER PRIMARY KEY AUTOINCREMENT, pem TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE, fetched_at TEXT NOT NULL);
            CREATE TABLE fid_state (id INTEGER PRIMARY KEY CHECK (id = 1), fid TEXT NOT NULL,
                refresh_token TEXT NOT NULL, auth_token TEXT, auth_expires_at TEXT);
            """
        )
        conn.execute(
            "INSERT INTO key_history (pem, fingerprint, fetched_at) VALUES (?, ?, ?)",
            (REAL_AZTEC_KEY_PEM, fingerprint_of(REAL_AZTEC_KEY_PEM), "2026-10-01T00:00:00+00:00"),
        )
    client, fake = build_app([REAL_AZTEC_KEY_PEM], db_dir=str(tmp_path))
    try:
        assert fake.rc_fetches == 0
        body = client.get("/api/v1/aztec-key").json()
        assert body["fetched_at"] == body["last_checked_at"] == "2026-10-01T00:00:00+00:00"
    finally:
        client.__exit__(None, None, None)


def test_blank_api_token_means_open(tmp_path, monkeypatch) -> None:
    from aztec_key_relay.config import Settings

    monkeypatch.setenv("RELAY_API_TOKEN", "  ")
    assert Settings().relay_api_token is None
