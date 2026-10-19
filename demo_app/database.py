"""SQLite storage and deterministic demo data for Sentinel."""

import os
import sqlite3
from pathlib import Path


DEFAULT_DATABASE_PATH = Path(__file__).resolve().parent / "sentinel.db"
DATABASE_PATH = Path(os.getenv("SENTINEL_DB_PATH", DEFAULT_DATABASE_PATH))

DEMO_USERS = (
    (1, "Alice Johnson", "alice@example.com"),
    (2, "Bob Smith", "bob@example.com"),
    (3, "Charlie Davis", "charlie@example.com"),
)


def get_connection() -> sqlite3.Connection:
    """Open a connection configured to return rows by column name."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    """Create the schema and insert the stable demo users if needed."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE
            )
            """
        )
        connection.executemany(
            "INSERT OR IGNORE INTO users (id, name, email) VALUES (?, ?, ?)",
            DEMO_USERS,
        )


def row_to_user(row: sqlite3.Row) -> dict[str, object]:
    return {"id": row["id"], "name": row["name"], "email": row["email"]}
