"""SQLite investigation storage for SPECTRE."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from spectre.core.models import InvestigationReport, to_primitive


class InvestigationStore:
    """Persist investigation reports to SQLite.

    The storage layer intentionally starts small: immutable report snapshots plus
    enough indexed metadata to list previous runs. More normalized tables can be
    added later for graph queries and timeline search.
    """

    def __init__(self, db_path: str | Path = "investigations/spectre.db") -> None:
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
                CREATE TABLE IF NOT EXISTS investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    target TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    finding_count INTEGER NOT NULL,
                    report_json TEXT NOT NULL
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_investigations_target ON investigations(target)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_investigations_category ON investigations(category)")

    def save(self, report: InvestigationReport) -> int:
        payload = to_primitive(report)
        finding_count = sum(len(result.findings) for result in report.results)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO investigations(category, target, generated_at, finding_count, report_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    report.category.value,
                    report.target,
                    report.generated_at,
                    finding_count,
                    json.dumps(payload, sort_keys=True, default=str),
                ),
            )
            return int(cursor.lastrowid)

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, category, target, generated_at, finding_count
                FROM investigations
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def load(self, investigation_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT report_json FROM investigations WHERE id = ?",
                (investigation_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["report_json"])
