import shutil
import json
from pathlib import Path

from sentinel.detector import Detector
from sentinel.diagnoser import Diagnoser
from sentinel.orchestrator import SentinelOrchestrator
from sentinel.patcher import Patcher
from sentinel.sandbox import SentinelSandboxAdapter


SAFE_FAULT_PATCH = '''"""Patched SQL-injection demonstration."""

import sqlite3


def vulnerable_raw_sql_search(connection: sqlite3.Connection, term: str) -> list[sqlite3.Row]:
    pattern = f"%{term}%"
    query = "SELECT id, name, email FROM users WHERE name LIKE ? OR email LIKE ?"
    return connection.execute(query, (pattern, pattern)).fetchall()
'''


class FakeLLM:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if prompt.startswith("Diagnose"):
            return '{"root_cause":"raw SQL interpolation","confidence":99}'
        return json.dumps({"path": "faults/sql_injection.py", "content": SAFE_FAULT_PATCH})


def test_core_loop_repairs_sql_injection_in_isolated_project_copy(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    for directory in ("demo_app", "faults", "tests"):
        shutil.copytree(Path(directory), project / directory)
    llm = FakeLLM()

    result = SentinelOrchestrator(
        Detector(),
        Diagnoser(llm),
        Patcher(llm),
        SentinelSandboxAdapter(project),
        source_dir=project,
    ).run("faults/sql_injection.py active: search failed for ' OR 1=1 --")

    assert result.sandbox_passed is True
    assert result.applied is True
    assert (project / "faults/sql_injection.py").read_text(encoding="utf-8") == SAFE_FAULT_PATCH
    assert len(llm.prompts) == 2
