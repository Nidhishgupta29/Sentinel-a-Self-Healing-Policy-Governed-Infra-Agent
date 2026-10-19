"""Run the Phase 2 application tests in an isolated patched source copy."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Mapping, Sequence

from sandbox.runner import LocalSandboxRunner, SandboxRunner


@dataclass(frozen=True)
class SandboxResult:
    """Outcome and diagnostics from the isolated test run."""

    passed: bool
    return_code: int
    stdout: str
    stderr: str
    temp_path: Path

    @property
    def diagnostics(self) -> str:
        """Human-readable subprocess diagnostics."""
        parts = [part for part in (self.stdout, self.stderr) if part]
        return "\n".join(parts)


class SentinelSandboxAdapter:
    """Adapt the replaceable root sandbox runner to Sentinel's test contract."""

    def __init__(
        self,
        source_dir: str | Path,
        runner: SandboxRunner | None = None,
        command: Sequence[str] | None = None,
    ) -> None:
        self.source_dir = Path(source_dir)
        self.runner = runner or LocalSandboxRunner()
        self.command = tuple(command or (sys.executable, "-m", "pytest", "tests/test_app.py"))

    def run(self, patches: Mapping[str, str]) -> SandboxResult:
        result = self.runner.run(self.source_dir, patches, self.command)
        return SandboxResult(
            passed=result.return_code == 0,
            return_code=result.return_code,
            stdout=result.stdout,
            stderr=result.stderr,
            temp_path=result.temp_path,
        )


SandboxAdapter = SentinelSandboxAdapter
