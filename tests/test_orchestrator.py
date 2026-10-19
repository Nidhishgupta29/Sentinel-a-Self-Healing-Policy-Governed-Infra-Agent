from pathlib import Path

from sentinel.orchestrator import SentinelOrchestrator


class Detector:
    def detect(self, log_text):
        return {"signature": "sql-injection", "severity": "critical"}


class Diagnoser:
    def diagnose(self, anomaly):
        return {"root_cause": "raw SQL", "confidence": 99}


class Patcher:
    def create_patch(self, diagnosis):
        return {"demo_app/main.py": "patched"}


class Sandbox:
    def __init__(self, passed):
        self.passed = passed
        self.calls = []

    def run(self, patches):
        self.calls.append(patches)
        return type("Result", (), {"passed": self.passed, "diagnostics": "details"})()


def test_successful_flow_applies_patch_after_passing_sandbox(tmp_path: Path):
    target = tmp_path / "demo_app" / "main.py"
    target.parent.mkdir()
    target.write_text("original", encoding="utf-8")
    sandbox = Sandbox(True)

    result = SentinelOrchestrator(
        Detector(), Diagnoser(), Patcher(), sandbox, source_dir=tmp_path
    ).run("SQL injection detected")

    assert result.applied is True
    assert target.read_text(encoding="utf-8") == "patched"
    assert sandbox.calls == [{"demo_app/main.py": "patched"}]


def test_failed_sandbox_does_not_apply_patch(tmp_path: Path):
    target = tmp_path / "demo_app" / "main.py"
    target.parent.mkdir()
    target.write_text("original", encoding="utf-8")
    sandbox = Sandbox(False)

    result = SentinelOrchestrator(
        Detector(), Diagnoser(), Patcher(), sandbox, source_dir=tmp_path
    ).run("SQL injection detected")

    assert result.applied is False
    assert result.sandbox_passed is False
    assert target.read_text(encoding="utf-8") == "original"
