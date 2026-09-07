"""Optional SQLite persistence for analysis history.

Disabled by default. When ``DEVSECOPS_PERSISTENCE_ENABLED=true`` the engine keeps
a local SQLite database of every analysis so the history endpoints
(``/api/v1/analyses`` …) return real data. The core pipeline never depends on
it — a write failure is logged and swallowed, never surfaced to the caller.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from pathlib import Path
from typing import Protocol

from models import (
    AnalysisSummary,
    AnalyzeResponse,
    Severity,
)

logger = logging.getLogger("devsecops-automation-engine.persistence")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id      TEXT PRIMARY KEY,
    filename         TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    gate_passed      INTEGER NOT NULL,
    total_findings   INTEGER NOT NULL,
    highest_severity TEXT NOT NULL,
    remediation_mode TEXT NOT NULL,
    report_json      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses (created_at DESC);
"""


class AnalysisStore(Protocol):
    enabled: bool

    async def save(self, response: AnalyzeResponse) -> bool: ...

    async def list_recent(self, limit: int = 50) -> list[AnalysisSummary]: ...

    async def get_report(self, analysis_id: str) -> AnalyzeResponse | None: ...

    async def close(self) -> None: ...


class NullAnalysisStore:
    """No-op store used when persistence is disabled."""

    enabled = False

    async def save(self, response: AnalyzeResponse) -> bool:
        return False

    async def list_recent(self, limit: int = 50) -> list[AnalysisSummary]:
        return []

    async def get_report(self, analysis_id: str) -> AnalyzeResponse | None:
        return None

    async def close(self) -> None:
        return None


class SqliteAnalysisStore:
    """Thread-off-loaded SQLite store. One connection, serialised by a lock."""

    enabled = True

    def __init__(self, database_path: str | Path) -> None:
        self._path = Path(database_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = asyncio.Lock()

    async def save(self, response: AnalyzeResponse) -> bool:
        row = (
            response.analysis_id,
            response.filename,
            response.created_at.isoformat(),
            int(response.gate_passed),
            response.metrics.total_findings,
            response.metrics.highest_severity.value,
            response.remediation_mode,
            response.model_dump_json(),
        )
        try:
            async with self._lock:
                await asyncio.to_thread(self._insert, row)
            return True
        except Exception:
            logger.exception("failed to persist analysis %s", response.analysis_id)
            return False

    def _insert(self, row: tuple[object, ...]) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO analyses "
                "(analysis_id, filename, created_at, gate_passed, total_findings, "
                " highest_severity, remediation_mode, report_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                row,
            )

    async def list_recent(self, limit: int = 50) -> list[AnalysisSummary]:
        limit = max(1, min(limit, 500))
        async with self._lock:
            rows = await asyncio.to_thread(self._select_recent, limit)
        return [
            AnalysisSummary(
                analysis_id=r["analysis_id"],
                filename=r["filename"],
                created_at=r["created_at"],
                gate_passed=bool(r["gate_passed"]),
                total_findings=r["total_findings"],
                highest_severity=Severity(r["highest_severity"]),
                remediation_mode=r["remediation_mode"],
            )
            for r in rows
        ]

    def _select_recent(self, limit: int) -> list[sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT analysis_id, filename, created_at, gate_passed, total_findings, "
            "highest_severity, remediation_mode FROM analyses "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return cur.fetchall()

    async def get_report(self, analysis_id: str) -> AnalyzeResponse | None:
        async with self._lock:
            raw = await asyncio.to_thread(self._select_report, analysis_id)
        if raw is None:
            return None
        return AnalyzeResponse.model_validate(json.loads(raw))

    def _select_report(self, analysis_id: str) -> str | None:
        cur = self._conn.execute("SELECT report_json FROM analyses WHERE analysis_id = ?", (analysis_id,))
        row = cur.fetchone()
        return row["report_json"] if row else None

    async def close(self) -> None:
        async with self._lock:
            await asyncio.to_thread(self._conn.close)


def build_store(enabled: bool, database_path: str | Path) -> AnalysisStore:
    if not enabled:
        logger.info("persistence disabled; analysis history is not retained")
        return NullAnalysisStore()
    store = SqliteAnalysisStore(database_path)
    logger.info("persistence enabled at %s", database_path)
    return store
