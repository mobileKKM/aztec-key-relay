"""SQLite persistence: current key + rotation history + installation state.

Deliberately stdlib `sqlite3` — a key relay needs no server database. The
database lives under the mounted ``data/`` volume so the Firebase
Installation identity (and the last good key) survive restarts.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from .keys import KeyRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS key_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pem TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fid_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    fid TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    auth_token TEXT,
    auth_expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_key_history_fetched_at ON key_history(fetched_at DESC);
"""


def _to_iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _from_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


class Store:
    """Thread-safe accessor around one SQLite file (WAL mode)."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)

    # ── Keys ─────────────────────────────────────────────────────────────────

    def current_key(self) -> KeyRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, pem, fingerprint, fetched_at FROM key_history ORDER BY fetched_at DESC, id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return KeyRecord(
            pem=row["pem"],
            fingerprint=row["fingerprint"],
            fetched_at=_from_iso(row["fetched_at"]),
            version=row["id"],
            bits=-1,  # not persisted; recomputed on demand in the service layer
        )

    def save_key(self, pem: str, fingerprint: str, fetched_at: datetime, *, max_history: int) -> KeyRecord:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO key_history (pem, fingerprint, fetched_at) VALUES (?, ?, ?)",
                (pem, fingerprint, _to_iso(fetched_at)),
            )
            # Trim to the newest max_history entries (rotation history).
            self._conn.execute(
                "DELETE FROM key_history WHERE id NOT IN (SELECT id FROM key_history ORDER BY fetched_at DESC, id DESC LIMIT ?)",
                (max_history,),
            )
        saved = self.current_key()
        assert saved is not None
        return saved

    # ── Firebase Installation state ──────────────────────────────────────────

    def load_fid_state(self) -> tuple[str, str] | None:
        with self._lock:
            row = self._conn.execute("SELECT fid, refresh_token FROM fid_state WHERE id = 1").fetchone()
        return (row["fid"], row["refresh_token"]) if row else None

    def save_fid_state(self, fid: str, refresh_token: str, auth_token: str | None, auth_expires_at: datetime | None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO fid_state (id, fid, refresh_token, auth_token, auth_expires_at) "
                "VALUES (1, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET fid = excluded.fid, refresh_token = excluded.refresh_token, "
                "auth_token = excluded.auth_token, auth_expires_at = excluded.auth_expires_at",
                (fid, refresh_token, auth_token, _to_iso(auth_expires_at) if auth_expires_at else None),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
