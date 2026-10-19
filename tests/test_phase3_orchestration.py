from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from sentinel.orchestrator import CONFIDENCE_THRESHOLD, SentinelOrchestrator
from sentinel.policy.audit_log import AuditLog
from sentinel.policy.policy_engine import PolicyEngine
from sentinel.rollback import HealthChecker


POLICY_PATH = Path(__file__).parents[1] / "sentinel" / "policy" / "policy.yaml"


class Detector:
    def detect(self, log_text):
        return SimpleNamespace(fault="sql_injection", severity="critical")


class Diagnoser:
    def __init__(self, confidence: int):
        self.confidence = confidence

    def diagnose(self, anomaly):
        return SimpleNamespace(root_cause="raw SQL", confidence=self.confidence)


class Patcher:
    def __init__(self, patches):
        self.patches = patches
        self.calls = 0

    def create_patch(self, diagnosis):
        self.calls += 1
        return self.patches


class Sandbox:
    def __init__(self, calls, passed=True):
        self.calls = calls
        self.passed = passed

    def run(self, patches):
        self.calls.append("sandbox")
        return SimpleNamespace(passed=self.passed, diagnostics="sandbox details")


class Policy:
    def __init__(self, calls, allowed=True, reason="allowed"):
        self.calls = calls
        self.allowed = allowed
        self.reason = reason

    def check(self, patches):
        self.calls.append("policy")
        return SimpleNamespace(allowed=self.allowed, reason=self.reason)


def _orchestrator(
    tmp_path: Path,
    *,
    confidence=99,
    patches=None,
    calls=None,
    policy=None,
    sandbox=None,
    health_checker=None,
):
    target = tmp_path / "faults" / "sql_injection.py"
    target.parent.mkdir(exist_ok=True)
    if not target.exists():
        target.write_text("original", encoding="utf-8")
    calls = calls if calls is not None else []
    patcher = Patcher(patches or {"faults/sql_injection.py": "patched"})
    orchestrator = SentinelOrchestrator(
        Detector(),
        Diagnoser(confidence),
        patcher,
        sandbox or Sandbox(calls),
        source_dir=tmp_path,
        policy_engine=policy,
        health_checker=health_checker,
    )
    return orchestrator, target, patcher, calls


def test_default_confidence_threshold_is_70():
    assert CONFIDENCE_THRESHOLD == 70


def test_low_confidence_stops_before_patching(tmp_path: Path):
    calls = []
    orchestrator, target, patcher, _ = _orchestrator(
        tmp_path,
        confidence=69,
        calls=calls,
        policy=Policy(calls),
        sandbox=Sandbox(calls),
    )

    result = orchestrator.run("SQL injection detected")

    assert result.status == "needs_human_review"
    assert result.applied is False
    assert patcher.calls == 0
    assert calls == []
    assert target.read_text(encoding="utf-8") == "original"


def test_policy_blocked_patch_never_reaches_sandbox_or_source(tmp_path: Path):
    calls = []
    policy = Policy(calls, allowed=False, reason="patch path is not allowed")
    orchestrator, target, patcher, _ = _orchestrator(
        tmp_path,
        calls=calls,
        policy=policy,
        sandbox=Sandbox(calls),
    )

    result = orchestrator.run("SQL injection detected")

    assert result.status == "policy_blocked"
    assert result.policy_allowed is False
    assert result.policy_reason == "patch path is not allowed"
    assert result.applied is False
    assert patcher.calls == 1
    assert calls == ["policy"]
    assert target.read_text(encoding="utf-8") == "original"


def test_healthy_apply_runs_policy_then_sandbox_then_health(tmp_path: Path):
    calls = []
    policy = Policy(calls)

    def health_check(source_dir: Path) -> bool:
        calls.append("health")
        return (source_dir / "faults" / "sql_injection.py").read_text() == "patched"

    orchestrator, target, _, _ = _orchestrator(
        tmp_path,
        calls=calls,
        policy=policy,
        sandbox=Sandbox(calls),
        health_checker=HealthChecker(health_check),
    )

    result = orchestrator.run("SQL injection detected")

    assert result.status == "applied"
    assert result.sandbox_passed is True
    assert result.health_passed is True
    assert result.applied is True
    assert calls == ["policy", "sandbox", "health"]
    assert target.read_text(encoding="utf-8") == "patched"


def test_failed_health_check_restores_every_pre_patch_file(tmp_path: Path):
    calls = []
    first = tmp_path / "faults" / "sql_injection.py"
    second = tmp_path / "demo_app" / "main.py"
    second.parent.mkdir()
    first.parent.mkdir(exist_ok=True)
    first.write_text("old fault", encoding="utf-8")
    second.write_text("old app", encoding="utf-8")
    patches = {
        "faults/sql_injection.py": "new fault",
        "demo_app/main.py": "new app",
    }

    def failed_health_check(source_dir: Path) -> bool:
        calls.append("health")
        return False

    orchestrator, _, _, _ = _orchestrator(
        tmp_path,
        patches=patches,
        calls=calls,
        policy=Policy(calls),
        sandbox=Sandbox(calls),
        health_checker=HealthChecker(failed_health_check),
    )

    result = orchestrator.run("SQL injection detected")

    assert result.status == "rolled_back"
    assert result.sandbox_passed is True
    assert result.health_passed is False
    assert result.applied is False
    assert result.rollback_result is not None
    assert result.rollback_result.restored is True
    assert result.rollback_reason
    assert calls == ["policy", "sandbox", "health"]
    assert first.read_text(encoding="utf-8") == "old fault"
    assert second.read_text(encoding="utf-8") == "old app"


def test_real_policy_blocks_env_before_sandbox_and_records_block(tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.sqlite3")
    policy = PolicyEngine(policy_path=POLICY_PATH, audit_log=audit)

    class UnexpectedSandbox:
        def run(self, patches):
            raise AssertionError("blocked patches must not reach the sandbox")

    orchestrator, target, patcher, _ = _orchestrator(
        tmp_path,
        patches={".env": "EXAMPLE_VALUE=not-a-secret\n"},
        policy=policy,
        sandbox=UnexpectedSandbox(),
    )

    result = orchestrator.run("SQL injection detected")

    assert result.status == "policy_blocked"
    assert result.policy_allowed is False
    assert patcher.calls == 1
    assert target.read_text(encoding="utf-8") == "original"
    blocked = audit.query(decision="block")
    assert len(blocked) == 1
    assert blocked[0]["action"] == "patch .env"


def test_failed_health_check_records_rollback_event(tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.sqlite3")
    policy = PolicyEngine(policy_path=POLICY_PATH, audit_log=audit)
    calls = []

    orchestrator, target, _, _ = _orchestrator(
        tmp_path,
        calls=calls,
        policy=policy,
        sandbox=Sandbox(calls),
        health_checker=HealthChecker(lambda source_dir: False),
    )

    result = orchestrator.run("SQL injection detected")

    assert result.status == "rolled_back"
    assert result.applied is False
    assert target.read_text(encoding="utf-8") == "original"
    assert audit.query(decision="allow")[0]["action"] == "patch faults/sql_injection.py"
    rollback_events = audit.query(action="rollback")
    assert len(rollback_events) == 1
    assert rollback_events[0]["decision"] == "rollback"
    assert "health check" in rollback_events[0]["reason"]
