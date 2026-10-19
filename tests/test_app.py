from fastapi.testclient import TestClient

from demo_app.main import app


client = TestClient(app)


def test_health_reports_healthy_database():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "database": "ok"}


def test_user_lookup_returns_demo_user():
    response = client.get("/users/1")

    assert response.status_code == 200
    assert response.json() == {
        "id": 1,
        "name": "Alice Johnson",
        "email": "alice@example.com",
    }


def test_user_lookup_returns_not_found_for_unknown_user():
    response = client.get("/users/999")

    assert response.status_code == 404


def test_search_returns_matching_users():
    response = client.get("/search", params={"q": "alice"})

    assert response.status_code == 200
    assert response.json() == {
        "users": [
            {"id": 1, "name": "Alice Johnson", "email": "alice@example.com"}
        ]
    }


def test_search_returns_empty_list_when_nothing_matches():
    response = client.get("/search", params={"q": "no-such-user"})

    assert response.status_code == 200
    assert response.json() == {"users": []}


def test_search_resists_sql_injection():
    response = client.get("/search", params={"q": "' OR 1=1 --"})

    assert response.status_code == 200
    assert response.json() == {"users": []}
