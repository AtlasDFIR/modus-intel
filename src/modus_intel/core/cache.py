from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional


def default_cache_path() -> Path:
    """
    Windows: %LOCALAPPDATA%/MODUS-Intel/cache.db
    Other:   ~/.cache/modus-intel/cache.db
    """
    local_appdata = os.getenv("LOCALAPPDATA")

    if local_appdata:
        base = Path(local_appdata) / "MODUS-Intel"
    else:
        base = Path.home() / ".cache" / "modus-intel"

    base.mkdir(parents=True, exist_ok=True)
    return base / "cache.db"


class Cache:
    """
    Simple SQLite-backed TTL cache for provider results.

    Entries are keyed by provider, IOC type, and normalized IOC value.
    Values are stored as compact JSON and expire automatically on read.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or default_cache_path()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache (
                    cache_key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_expires_at ON cache(expires_at)"
            )
            conn.commit()

    @staticmethod
    def make_key(provider: str, indicator_type: str, indicator_value: str) -> str:
        return f"{provider}:{indicator_type}:{indicator_value}"

    def get(self, cache_key: str) -> Optional[dict[str, Any]]:
        now = int(time.time())

        with self._connect() as conn:
            row = conn.execute(
                "SELECT value_json, expires_at FROM cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()

            if row is None:
                return None

            value_json, expires_at = row

            if expires_at <= now:
                conn.execute(
                    "DELETE FROM cache WHERE cache_key = ?",
                    (cache_key,),
                )
                conn.commit()
                return None

            return json.loads(value_json)

    def set(self, cache_key: str, value: dict[str, Any], ttl_seconds: int) -> None:
        now = int(time.time())
        ttl_seconds = max(1, ttl_seconds)
        expires_at = now + ttl_seconds
        value_json = json.dumps(value, separators=(",", ":"))

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cache (cache_key, value_json, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    value_json = excluded.value_json,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                """,
                (cache_key, value_json, now, expires_at),
            )
            conn.commit()

    def purge_expired(self) -> int:
        now = int(time.time())

        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM cache WHERE expires_at <= ?",
                (now,),
            )
            conn.commit()
            return cur.rowcount