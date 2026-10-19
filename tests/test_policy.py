from pathlib import Path

import pytest

from sentinel.policy.audit_log import AuditLog
from sentinel.policy.policy_engine import PolicyEngine


POLICY_PATH = Path(__file__).parents[1] / "sentinel" / "policy" / "policy.yaml"


def make_engine(tmp_path: Path) -> PolicyEngine:
    return PolicyEngine(
        policy_path=POLICY_PATH,
        audit_log=AuditLog(tmp_path / "audit.sqlite3"),
    )


def test_allowed_patch_returns_allow_decision_and_audits_check(tmp_path: Path):
    engine = make_engine(tmp_path)

    decision = engine.evaluate(
        {"faults/example.py": "def safe_search(term):\n    return term\n"}
    )

    assert decision.decision == "allow"
    assert decision.allowed is True
    assert decision.reason
    entries = engine.audit_log.query()
    assert len(entries) == 1
    assert entries[0]["action"] == "patch faults/example.py"
    assert entries[0]["decision"] == "allow"
    assert entries[0]["reason"] == decision.reason
    assert entries[0]["timestamp"]


def test_env_patch_is_blocked_and_audited(tmp_path: Path):
    engine = make_engine(tmp_path)

    decision = engine.evaluate({"demo_app/.env": "DATABASE_URL=sqlite:///safe.db\n"})

    assert decision.decision == "block"
    assert decision.allowed is False
    assert ".env" in decision.reason
    assert engine.audit_log.query(decision="block")[0]["decision"] == "block"


def test_policy_file_patch_is_blocked(tmp_path: Path):
    engine = make_engine(tmp_path)

    decision = engine.evaluate(
        {"sentinel/policy/policy.yaml": "allowed_paths:\n  - '**/*'\n"}
    )

    assert decision.decision == "block"
    assert "policy" in decision.reason.lower()


@pytest.mark.parametrize(
    "contents",
    [
        "import os\nos.system('rm -rf /tmp/example')\n",
        "cursor.execute('DROP TABLE users')\n",
        "import requests\nrequests.get('https://example.invalid')\n",
    ],
)
def test_destructive_or_network_patch_content_is_blocked(
    tmp_path: Path, contents: str
):
    engine = make_engine(tmp_path)

    decision = engine.evaluate({"demo_app/main.py": contents})

    assert decision.decision == "block"
    assert decision.allowed is False
    assert decision.reason


def test_path_traversal_is_blocked(tmp_path: Path):
    engine = make_engine(tmp_path)

    decision = engine.evaluate({"faults/../demo_app/main.py": "VALUE = 1\n"})

    assert decision.decision == "block"
    assert "travers" in decision.reason.lower()


def test_audit_query_can_filter_decisions(tmp_path: Path):
    engine = make_engine(tmp_path)
    engine.evaluate({"faults/allowed.py": "VALUE = 1\n"})
    engine.evaluate({".env": "TOKEN=not-a-secret-example\n"})

    allowed = engine.audit_log.query(decision="allow")
    blocked = engine.audit_log.query(decision="block")

    assert len(allowed) == 1
    assert allowed[0]["action"] == "patch faults/allowed.py"
    assert len(blocked) == 1
    assert blocked[0]["action"] == "patch .env"
