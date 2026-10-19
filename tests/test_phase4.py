from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from faults.cascading_demo import CASCADING_LOG
from faults.prompt_injection_log import PROMPT_INJECTION_LOG
from sentinel.detector import Anomaly, Detector
from sentinel.orchestrator import SentinelOrchestrator
from sentinel.policy import AuditLog, PolicyEngine
from sentinel.postmortem import PostmortemGenerator
from sentinel.rollback import HealthChecker


POLICY_PATH = Path(__file__).parents[1] / "sentinel" / "policy" / "policy.yaml"


class RecordingDiagnoser:
    def __init__(self, confidence: int = 99):
        self.confidence = confidence
        self.calls: list[object] = []

    def diagnose(self, anomaly):
        self.calls.append(anomaly)
        fault = getattr(anomaly, "fault", "unknown")
        return SimpleNamespace(
            fault=fault,
            root_cause=f"root cause for {fault}",
            confidence=self.confidence,
        )


class RecordingPatcher:
    def __init__(self, patch_for_fault=None):
        self.patch_for_fault = patch_for_fault or (lambda fault: {f"faults/{fault}.py": "patched\n"})
        self.calls: list[object] = []

    def create_patch(self, diagnosis):
        self.calls.append(diagnosis)
        return self.patch_for_fault(getattr(diagnosis, "fault", "unknown"))


class PassingSandbox:
    def __init__(self):
        self.calls: list[object] = []

    def run(self, patches):
        self.calls.append(patches)
        return SimpleNamespace(passed=True, diagnostics="sandbox passed")


class FailingIfCalledSandbox:
    def run(self, patches):
        raise AssertionError("suspicious input must not reach the sandbox")


class StaticDetector:
    def __init__(self, anomalies):
        self.anomalies = anomalies

    def detect(self, log_text):
        return self.anomalies


def make_policy(tmp_path: Path) -> tuple[PolicyEngine, AuditLog]:
    audit = AuditLog(tmp_path / "audit.sqlite3")
    return PolicyEngine(policy_path=POLICY_PATH, audit_log=audit), audit


def make_postmortem(tmp_path: Path) -> PostmortemGenerator:
    return PostmortemGenerator(tmp_path / "postmortems")


def test_prompt_injection_detected_as_suspicious_input():
    anomalies = Detector().detect(PROMPT_INJECTION_LOG)

    assert anomalies is not None
    assert len(anomalies) == 1
    assert anomalies[0].fault == "suspicious_input"
    assert anomalies[0].severity == "suspicious_input"
    assert "ignore previous instructions" in anomalies[0].evidence.lower()
    assert "SYSTEM:" in anomalies[0].evidence


def test_suspicious_input_never_reaches_diagnoser_or_patcher(tmp_path: Path):
    policy, audit = make_policy(tmp_path)
    diagnoser = RecordingDiagnoser()
    patcher = RecordingPatcher()
    postmortem = make_postmortem(tmp_path)
    result = SentinelOrchestrator(
        Detector(),
        diagnoser,
        patcher,
        FailingIfCalledSandbox(),
        source_dir=tmp_path,
        policy_engine=policy,
        audit_log=audit,
        postmortem_generator=postmortem,
    ).run(PROMPT_INJECTION_LOG)

    assert result.status == "needs_human_review"
    assert diagnoser.calls == []
    assert patcher.calls == []
    assert result.applied is False


def test_suspicious_input_routes_to_human_review_with_correct_reason(tmp_path: Path):
    policy, audit = make_policy(tmp_path)
    result = SentinelOrchestrator(
        Detector(),
        RecordingDiagnoser(),
        RecordingPatcher(),
        FailingIfCalledSandbox(),
        source_dir=tmp_path,
        policy_engine=policy,
        audit_log=audit,
        postmortem_generator=make_postmortem(tmp_path),
    ).run(PROMPT_INJECTION_LOG)

    assert result.status == "needs_human_review"
    assert "suspicious_input" in result.diagnostics
    assert "confidence" not in result.diagnostics.lower()


def test_suspicious_input_audit_event_logged(tmp_path: Path):
    policy, audit = make_policy(tmp_path)
    SentinelOrchestrator(
        Detector(),
        RecordingDiagnoser(),
        RecordingPatcher(),
        FailingIfCalledSandbox(),
        source_dir=tmp_path,
        policy_engine=policy,
        audit_log=audit,
        postmortem_generator=make_postmortem(tmp_path),
    ).run(PROMPT_INJECTION_LOG)

    events = audit.query(action="suspicious_input_detected")
    assert len(events) == 1
    assert events[0]["decision"] == "block"
    assert "ignore previous instructions" in events[0]["reason"].lower()


def _successful_orchestrator(tmp_path: Path):
    target = tmp_path / "demo_app" / "main.py"
    target.parent.mkdir()
    target.write_text("original\n", encoding="utf-8")
    policy, audit = make_policy(tmp_path)
    diagnoser = RecordingDiagnoser()
    patcher = RecordingPatcher(lambda fault: {"demo_app/main.py": "patched\n"})
    postmortem = make_postmortem(tmp_path)
    orchestrator = SentinelOrchestrator(
        Detector(),
        diagnoser,
        patcher,
        PassingSandbox(),
        source_dir=tmp_path,
        policy_engine=policy,
        audit_log=audit,
        postmortem_generator=postmortem,
    )
    return orchestrator, target, postmortem


def test_postmortem_generated_for_successful_fix(tmp_path: Path):
    orchestrator, target, postmortem = _successful_orchestrator(tmp_path)

    result = orchestrator.run("faults/sql_injection.py: OR 1=1 --")

    assert result.applied is True
    assert target.read_text(encoding="utf-8") == "patched\n"
    assert result.postmortem_path is not None
    content = result.postmortem_path.read_text(encoding="utf-8")
    assert "# Postmortem: sql_injection — fixed" in content
    assert "## What happened" in content
    assert "## Diagnosis" in content
    assert "## Actions taken" in content
    assert "## Outcome" in content
    assert postmortem.last_path == result.postmortem_path


def test_postmortem_generated_for_policy_block(tmp_path: Path):
    policy, audit = make_policy(tmp_path)
    postmortem = make_postmortem(tmp_path)
    result = SentinelOrchestrator(
        Detector(),
        RecordingDiagnoser(),
        RecordingPatcher(lambda fault: {".env": "EXAMPLE_VALUE=not-a-secret\n"}),
        FailingIfCalledSandbox(),
        source_dir=tmp_path,
        policy_engine=policy,
        audit_log=audit,
        postmortem_generator=postmortem,
    ).run("faults/sql_injection.py: OR 1=1 --")

    assert result.status == "policy_blocked"
    content = result.postmortem_path.read_text(encoding="utf-8")
    assert "# Postmortem: sql_injection — blocked" in content
    assert "policy" in content.lower()


def test_postmortem_generated_for_rollback(tmp_path: Path):
    orchestrator, target, _ = _successful_orchestrator(tmp_path)
    orchestrator.health_checker = HealthChecker(lambda source_dir: False)

    result = orchestrator.run("faults/sql_injection.py: OR 1=1 --")

    assert result.status == "rolled_back"
    assert target.read_text(encoding="utf-8") == "original\n"
    content = result.postmortem_path.read_text(encoding="utf-8")
    assert "# Postmortem: sql_injection — rolled_back" in content
    assert "rollback" in content.lower()


def test_postmortem_generated_for_human_review(tmp_path: Path):
    policy, audit = make_policy(tmp_path)
    postmortem = make_postmortem(tmp_path)
    result = SentinelOrchestrator(
        Detector(),
        RecordingDiagnoser(confidence=69),
        RecordingPatcher(),
        FailingIfCalledSandbox(),
        source_dir=tmp_path,
        policy_engine=policy,
        audit_log=audit,
        postmortem_generator=postmortem,
    ).run("faults/sql_injection.py: OR 1=1 --")

    assert result.status == "needs_human_review"
    content = result.postmortem_path.read_text(encoding="utf-8")
    assert "# Postmortem: sql_injection — needs_human_review" in content
    assert "Diagnosis skipped" not in content
    assert "confidence" in content.lower()


def test_postmortem_file_exists_on_disk_with_correct_naming(tmp_path: Path):
    orchestrator, _, _ = _successful_orchestrator(tmp_path)

    result = orchestrator.run("faults/sql_injection.py: OR 1=1 --")

    assert result.postmortem_path.is_file()
    assert result.postmortem_path.parent == tmp_path / "postmortems"
    assert result.postmortem_path.name.endswith("_sql_injection.md")


def test_cascading_faults_detected_as_multiple_anomalies():
    anomalies = Detector().detect(CASCADING_LOG)

    assert anomalies is not None
    assert len(anomalies) == 2
    assert {anomaly.fault for anomaly in anomalies} == {"memory_leak", "slow_query"}


def test_cascading_faults_processed_in_severity_priority_order(tmp_path: Path):
    anomalies = [
        Anomaly("slow_query", "low", "slow query", "log"),
        Anomaly("memory_leak", "critical", "memory leak", "log"),
    ]
    diagnoser = RecordingDiagnoser()
    patcher = RecordingPatcher()
    policy, audit = make_policy(tmp_path)
    orchestrator = SentinelOrchestrator(
        StaticDetector(anomalies),
        diagnoser,
        patcher,
        PassingSandbox(),
        source_dir=tmp_path,
        policy_engine=policy,
        audit_log=audit,
        postmortem_generator=make_postmortem(tmp_path),
    )

    result = orchestrator.run(CASCADING_LOG)

    assert [item.fault for item in diagnoser.calls] == ["memory_leak", "slow_query"]
    assert [item.anomaly.fault for item in result.anomaly_results] == [
        "memory_leak",
        "slow_query",
    ]


def test_cascading_faults_single_postmortem_lists_all(tmp_path: Path):
    anomalies = [
        Anomaly("memory_leak", "critical", "memory leak", "log"),
        Anomaly("slow_query", "medium", "slow query", "log"),
    ]
    policy, audit = make_policy(tmp_path)
    result = SentinelOrchestrator(
        StaticDetector(anomalies),
        RecordingDiagnoser(),
        RecordingPatcher(),
        PassingSandbox(),
        source_dir=tmp_path,
        policy_engine=policy,
        audit_log=audit,
        postmortem_generator=make_postmortem(tmp_path),
    ).run(CASCADING_LOG)

    assert result.postmortem_path.name.endswith("_multi.md")
    content = result.postmortem_path.read_text(encoding="utf-8")
    assert "memory_leak" in content
    assert "slow_query" in content
    assert content.count("## What happened") == 1


def test_cascading_continues_processing_after_one_anomaly_blocked(tmp_path: Path):
    anomalies = [
        Anomaly("memory_leak", "critical", "memory leak", "log"),
        Anomaly("slow_query", "medium", "slow query", "log"),
    ]

    def patch_for_fault(fault):
        if fault == "memory_leak":
            return {".env": "EXAMPLE_VALUE=not-a-secret\n"}
        return {"faults/slow_query.py": "patched\n"}

    policy, audit = make_policy(tmp_path)
    diagnoser = RecordingDiagnoser()
    patcher = RecordingPatcher(patch_for_fault)
    result = SentinelOrchestrator(
        StaticDetector(anomalies),
        diagnoser,
        patcher,
        PassingSandbox(),
        source_dir=tmp_path,
        policy_engine=policy,
        audit_log=audit,
        postmortem_generator=make_postmortem(tmp_path),
    ).run(CASCADING_LOG)

    assert [item.fault for item in diagnoser.calls] == ["memory_leak", "slow_query"]
    assert result.anomaly_results[0].status == "policy_blocked"
    assert result.anomaly_results[1].applied is True
    assert (tmp_path / "faults" / "slow_query.py").read_text(encoding="utf-8") == "patched\n"
