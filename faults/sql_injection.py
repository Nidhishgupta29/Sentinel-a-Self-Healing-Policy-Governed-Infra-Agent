"""INTENTIONAL VULNERABILITY: isolated SQL-injection demonstration only.

This module is deliberately excluded from the normal application path.
"""

import sqlite3


def vulnerable_raw_sql_search(connection: sqlite3.Connection, term: str) -> list[sqlite3.Row]:
    """INTENTIONALLY VULNERABLE: interpolates untrusted input into SQL."""
    query = (
        "SELECT id, name, email FROM users "
        f"WHERE name LIKE '%{term}%' OR email LIKE '%{term}%'"
    )
    return connection.execute(query).fetchall()
