"""SQLite persistence: current key + rotation history + installation state.

Deliberately stdlib `sqlite3` — a key relay needs no server database. The
database lives under the mounted ``data/`` volume so the Firebase
Installation identity (and the last good key) survive restarts.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .keys import KeyRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS key_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pem TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    fetched_at TEXT NOT NULL,
    last_checked_at TEXT
);
CREATE TABLE IF NOT EXISTS fid_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    fid TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    auth_token TEXT,
    auth_expires_at TEXT
);
"""

# Columns added after the first release: (table, column, type).
_MIGRATIONS = [("key_history", "last_checked_at", "TEXT")]


def _to_iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _from_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


@dataclass(frozen=True, slots=True)
class FidState:
    fid: str
    refresh_token: str
    auth_token: str | None
    auth_expires_at: datetime | None


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
            for table, column, sql_type in _MIGRATIONS:
                existing = {row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})")}
                if column not in existing:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")

    # ── Keys ─────────────────────────────────────────────────────────────────

    def _current_row(self) -> sqlite3.Row | None:
        # Newest insert wins. AUTOINCREMENT never reuses ids, so a re-inserted
        # (rolled-back) key always sorts above the key it replaced.
        return self._conn.execute(
            "SELECT id, pem, fingerprint, fetched_at, last_checked_at FROM key_history ORDER BY id DESC LIMIT 1"
        ).fetchone()

    def current_key(self) -> KeyRecord | None:
        with self._lock:
            row = self._current_row()
        if row is None:
            return None
        fetched_at = _from_iso(row["fetched_at"])
        return KeyRecord(
            pem=row["pem"],
            fingerprint=row["fingerprint"],
            fetched_at=fetched_at,
            last_checked_at=_from_iso(row["last_checked_at"]) if row["last_checked_at"] else fetched_at,
            version=row["id"],
        )

    def save_key(self, pem: str, fingerprint: str, fetched_at: datetime, *, max_history: int) -> KeyRecord:
        """Records a fetched key and makes it the current one.

        Same key as now → only `last_checked_at` moves. A different key —
        including one seen before (rotation A → B → A) — becomes a new row,
        so `version` goes up and clients notice the change.
        """
        now = _to_iso(fetched_at)
        with self._lock, self._conn:
            current = self._current_row()
            if current is not None and current["fingerprint"] == fingerprint:
                self._conn.execute("UPDATE key_history SET last_checked_at = ? WHERE id = ?", (now, current["id"]))
            else:
                self._conn.execute("DELETE FROM key_history WHERE fingerprint = ?", (fingerprint,))
                self._conn.execute(
                    "INSERT INTO key_history (pem, fingerprint, fetched_at, last_checked_at) VALUES (?, ?, ?, ?)",
                    (pem, fingerprint, now, now),
                )
            # Trim to the newest max_history entries (rotation history).
            self._conn.execute(
                "DELETE FROM key_history WHERE id NOT IN (SELECT id FROM key_history ORDER BY id DESC LIMIT ?)",
                (max_history,),
            )
        saved = self.current_key()
        assert saved is not None
        return saved

    def touch_current(self, checked_at: datetime) -> None:
        """Upstream confirmed the current key is unchanged (HTTP 304)."""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE key_history SET last_checked_at = ? WHERE id = (SELECT MAX(id) FROM key_history)",
                (_to_iso(checked_at),),
            )

    # ── Firebase Installation state ──────────────────────────────────────────

    def load_fid_state(self) -> FidState | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT fid, refresh_token, auth_token, auth_expires_at FROM fid_state WHERE id = 1"
            ).fetchone()
        if row is None:
            return None
        return FidState(
            fid=row["fid"],
            refresh_token=row["refresh_token"],
            auth_token=row["auth_token"],
            auth_expires_at=_from_iso(row["auth_expires_at"]) if row["auth_expires_at"] else None,
        )

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
