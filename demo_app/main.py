"""FastAPI entry point for the Sentinel Phase 1 demo service."""

from fastapi import FastAPI, HTTPException, Query

from demo_app.database import get_connection, initialize_database, row_to_user


app = FastAPI(title="Sentinel Demo")
initialize_database()


@app.get("/health")
def health() -> dict[str, str]:
    try:
        with get_connection() as connection:
            connection.execute("SELECT 1").fetchone()
    except Exception:
        return {"status": "unhealthy", "database": "error"}
    return {"status": "healthy", "database": "ok"}


@app.get("/users/{user_id}")
def get_user(user_id: int) -> dict[str, object]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, name, email FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    return row_to_user(row)


@app.get("/search")
def search_users(q: str = Query(..., min_length=1)) -> dict[str, list[dict[str, object]]]:
    pattern = f"%{q}%"
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, name, email FROM users
            WHERE name LIKE ? OR email LIKE ?
            ORDER BY id
            """,
            (pattern, pattern),
        ).fetchall()
    return {"users": [row_to_user(row) for row in rows]}
