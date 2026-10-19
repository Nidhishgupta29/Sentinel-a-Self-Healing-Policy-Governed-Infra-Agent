"""Durable, queryable audit records for policy decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Any


_VALID_DECISIONS = {"allow", "block", "rollback"}


class _ClosingConnection(sqlite3.Connection):
    """Close SQLite handles when used with a context manager on Windows."""

    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


class AuditLog:
    """Store policy decisions in a small SQLite database.

    A connection is opened for each operation so records remain usable by
    separate policy checks and processes without sharing mutable connection
    state.  The database contains only decision metadata, never patch content.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=5,
            factory=_ClosingConnection,
        )
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK (
                        decision IN ('allow', 'block', 'rollback')
                    ),
                    reason TEXT NOT NULL
                )
                """
            )
            schema_row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'audit_log'"
            ).fetchone()
            schema = str(schema_row[0]).lower() if schema_row else ""
            if "rollback" not in schema:
                connection.execute(
                    """
                    CREATE TABLE audit_log_migrated (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        action TEXT NOT NULL,
                        decision TEXT NOT NULL CHECK (
                            decision IN ('allow', 'block', 'rollback')
                        ),
                        reason TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO audit_log_migrated (id, timestamp, action, decision, reason)
                    SELECT id, timestamp, action, decision, reason FROM audit_log
                    """
                )
                connection.execute("DROP TABLE audit_log")
                connection.execute("ALTER TABLE audit_log_migrated RENAME TO audit_log")

    def record(
        self,
        *,
        action: str,
        decision: str,
        reason: str,
        timestamp: str | None = None,
    ) -> dict[str, str]:
        """Append one decision and return its query-shaped representation."""
        if decision not in _VALID_DECISIONS:
            raise ValueError("decision must be 'allow', 'block', or 'rollback'")
        if not action:
            raise ValueError("action must not be empty")
        if not reason:
            raise ValueError("reason must not be empty")

        recorded_at = timestamp or datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_log (timestamp, action, decision, reason) VALUES (?, ?, ?, ?)",
                (recorded_at, action, decision, reason),
            )
        return {
            "timestamp": recorded_at,
            "action": action,
            "decision": decision,
            "reason": reason,
        }

    def query(
        self,
        *,
        action: str | None = None,
        decision: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, str]]:
        """Return audit records in insertion order, optionally filtered."""
        if decision is not None and decision not in _VALID_DECISIONS:
            raise ValueError("decision must be 'allow', 'block', or 'rollback'")
        if limit is not None and (not isinstance(limit, int) or limit <= 0):
            raise ValueError("limit must be a positive integer")

        clauses: list[str] = []
        parameters: list[Any] = []
        if action is not None:
            clauses.append("action = ?")
            parameters.append(action)
        if decision is not None:
            clauses.append("decision = ?")
            parameters.append(decision)

        statement = (
            "SELECT timestamp, action, decision, reason FROM audit_log"
            + (" WHERE " + " AND ".join(clauses) if clauses else "")
            + " ORDER BY id ASC"
        )
        if limit is not None:
            statement += " LIMIT ?"
            parameters.append(limit)

        with self._connect() as connection:
            rows = connection.execute(statement, parameters).fetchall()
        return [dict(row) for row in rows]


__all__ = ["AuditLog"]
