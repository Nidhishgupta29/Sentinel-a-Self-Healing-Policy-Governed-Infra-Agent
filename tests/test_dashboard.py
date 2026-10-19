from pathlib import Path

from fastapi.testclient import TestClient

from dashboard.app import create_app
from sentinel.policy.audit_log import AuditLog


def test_dashboard_routes_render_historical_run_and_postmortem(tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.sqlite3")
    audit.record(
        action="patch demo_app/main.py",
        decision="allow",
        reason="path and content satisfy policy",
    )
    postmortems = tmp_path / "postmortems"
    postmortems.mkdir()
    postmortem = postmortems / "20261019_120000_sql_injection.md"
    postmortem.write_text(
        "# Postmortem: sql_injection — fixed\n\n"
        "Timestamp: 2026-10-19T12:00:00+00:00\n"
        "Status: fixed\n"
        "Severity: critical\n\n"
        "## What happened\n\nDetected SQL injection.\n\n"
        "## Diagnosis\n\nroot cause: raw SQL; confidence: 99\n\n"
        "## Actions taken\n\n- Detect completed.\n- Sandbox passed.\n\n"
        "## Outcome\nFinal status: fixed.\n",
        encoding="utf-8",
    )

    client = TestClient(
        create_app(
            audit_log_path=audit.path,
            postmortems_dir=postmortems,
            results_path=tmp_path / "missing-results.md",
        )
    )

    home = client.get("/")
    detail = client.get(f"/run/{postmortem.name}")
    rendered_postmortem = client.get(f"/postmortem/{postmortem.name}")

    assert home.status_code == 200
    assert "Sentinel Dashboard" in home.text
    assert "sql_injection" in home.text
    assert "fixed" in home.text
    assert detail.status_code == 200
    assert "Run timeline" in detail.text
    assert "Policy" in detail.text
    assert rendered_postmortem.status_code == 200
    assert "Postmortem: sql_injection" in rendered_postmortem.text
