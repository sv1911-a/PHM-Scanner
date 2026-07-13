"""Small SQLite cache for source adapters."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class SourceCache:
    """TTL-based SQLite cache for adapter responses."""

    def __init__(self, db_path: str | Path = "investigations/source_cache.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS source_cache (
                    cache_key TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    value_json TEXT NOT NULL
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_source_cache_namespace ON source_cache(namespace)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_source_cache_expires ON source_cache(expires_at)")

    @staticmethod
    def make_key(namespace: str, key: str) -> str:
        digest = hashlib.sha256(f"{namespace}:{key}".encode("utf-8")).hexdigest()
        return f"{namespace}:{digest}"

    def get(self, namespace: str, key: str) -> Any | None:
        cache_key = self.make_key(namespace, key)
        now = time.time()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value_json, expires_at FROM source_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
            if row is None:
                return None
            if float(row["expires_at"]) < now:
                connection.execute("DELETE FROM source_cache WHERE cache_key = ?", (cache_key,))
                return None
            return json.loads(row["value_json"])

    def set(self, namespace: str, key: str, value: Any, ttl_seconds: int = 3600) -> None:
        cache_key = self.make_key(namespace, key)
        now = time.time()
        expires = now + max(1, int(ttl_seconds))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO source_cache(cache_key, namespace, key_hash, created_at, expires_at, value_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (cache_key, namespace, hashlib.sha256(key.encode()).hexdigest(), now, expires, json.dumps(value, sort_keys=True, default=str)),
            )

    def purge_expired(self) -> int:
        now = time.time()
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM source_cache WHERE expires_at < ?", (now,))
            return int(cursor.rowcount)
