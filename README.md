# aztec-key-relay

Small [FastAPI](https://fastapi.tiangolo.com/) service that fetches the **`aztecKey`** — the RSA-2048 public key the official mKKM Android client uses to encrypt `assign-e` / `contract-e` request payloads — from **Firebase Remote Config**, and serves it to the [mobile_kkm](https://github.com/divadsn/mobile_kkm) app.

> Unofficial reverse-engineering project, not affiliated with or endorsed by the operators of mKKM/EKP. The upstream protocol details (Firebase project, API key, headers) come from the official APK and are documented in mobile_kkm's `ekp_crypto` package.

## Why

The key lives in Firebase Remote Config (project id in `.env`, key `aztecKey`) and can be **rotated server-side at any time**. Today a rotation means re-capturing traffic with mitmproxy and shipping an app update.

Fetching it directly from every app install has a privacy cost: each device becomes a separate **Firebase Installation** (FID + auth tokens + IP) in Google's records. This relay reduces that to **one shared installation** — end-user devices never contact Google at all; they only talk to this service.

## What it does

- **Daily refresh** — a background task re-fetches the key at a fixed UTC hour (+ 15 min jitter).
- **On-demand refresh** — `POST /api/v1/aztec-key/refresh` for when the app's assign/contract request failed (likely rotation). Rate-limited (default 60 s) so a fleet of failing clients can't hammer Firebase.
- **Fetch on startup only when the cache is empty** — fresh deployments serve a key immediately; restarts with a good key don't touch upstream.
- **Never loses a good key** — upstream failures keep serving the cached key with `stale: true`; invalid PEMs (not RSA, < 2048 bits, unparseable) are rejected outright.
- **Rotation history** — the last N keys (default 10) are kept in SQLite; the response's `version` increments on each *new* fingerprint.

## API

| Endpoint | Description |
|---|---|
| `GET /api/v1/aztec-key` | Cached key. Never triggers a fetch. `503` if none was ever fetched. `Cache-Control: public, max-age=300` (`private` when `RELAY_API_TOKEN` is set; configurable via `RELAY_CACHE_MAX_AGE`). |
| `POST /api/v1/aztec-key/refresh` | Force an upstream fetch (single-flight). `429` + `Retry-After` inside the rate window; `502` if upstream fails (old key stays cached, marked stale). Never cacheable (`no-store`). |
| `GET /health` | Liveness. |
| `GET /ready` | Readiness — `ready: true` once a key is cached. |

`GET /api/v1/aztec-key` response:

```json
{
  "pem": "-----BEGIN RSA PUBLIC KEY-----…",
  "fingerprint_sha256": "3a291ed03894511d…",
  "fetched_at": "2026-10-09T12:57:37.514901+00:00",
  "age_seconds": 10,
  "version": 1,
  "stale": false,
  "bits": 2048
}
```

The fingerprint is SHA-256 over the key's SPKI (DER) encoding — a stable rotation signal: the app can compare fingerprints to detect a changed key cheaply.

When `RELAY_API_TOKEN` is set, the `/api/v1/*` endpoints require `Authorization: Bearer <token>`; unset = open.

## How the upstream fetch works

Mirrors the official client's flow (Firebase Installations SDK + Remote Config SDK, both pinned to the official app's identity — all values ship in the APK):

1. **Installations** — `POST …/installations` with a client-generated FID (`^[cdef][\w-]{21}$`) → `fid` + `refreshToken`; `POST …/{fid}/authTokens:generate` → a week-long auth token. Created once, persisted, refreshed when expired (< 5 min left). A revoked FID triggers exactly one retry with a fresh installation.
2. **Remote Config** — `POST …/namespaces/firebase:fetch` with `X-Android-Package`/`X-Android-Cert`/`X-Goog-Firebase-Installations-Auth` headers → flat `entries.aztecKey` map.

The service persists `fid` + `refresh_token` in SQLite (`data/state.db`, WAL) so restarts reuse the **same** installation identity.

## Configuration

Copy `.env.example` to `.env`. Everything has working defaults; the interesting knobs:

| Variable | Default | |
|---|---|---|
| `RELAY_API_TOKEN` | *(unset)* | Bearer token for `/api/v1/*`; unset = open. |
| `RELAY_MIN_FETCH_INTERVAL` | `60` | Min seconds between upstream fetches (refresh endpoint). |
| `RELAY_DAILY_REFRESH_HOUR` | `4` | UTC hour for the daily refresh. |
| `RELAY_DB_PATH` | `data/state.db` | SQLite path (key history + installation identity). |
| `RELAY_KEY_HISTORY` | `10` | Historical keys to keep. |
| `RELAY_CACHE_MAX_AGE` | `300` | `Cache-Control` max-age (seconds) for `GET /api/v1/aztec-key`. |

## Run

```bash
uv sync
uv run uvicorn aztec_key_relay.main:app --host 127.0.0.1 --port 8000
```

Or with Docker:

```bash
docker compose up -d --build
```

The `data/` directory holds `state.db` — mount it somewhere durable, or you get a new Firebase Installation on every redeploy.

## Tests

```bash
uv run pytest
```

Upstream calls are mocked with `httpx.MockTransport`; no network needed. The suite pins: PEM parsing (PKCS#1 + SPKI, weak/garbage/non-RSA rejection), fingerprint stability, the installation lifecycle (create → reuse token → restore from disk → retry on revoked FID), and the API contract (cache serving never fetches, rotation bumps `version`, rate limit `429` + `Retry-After`, failed refresh keeps the old key and flips `stale`, startup fetch only when the cache is empty, optional bearer auth).

## License

GPL-3.0-or-later — see the repository [LICENSE](LICENSE).
Copyright (C) 2026 David Sn.
