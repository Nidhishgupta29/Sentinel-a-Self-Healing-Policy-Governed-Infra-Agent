import pytest

from sentinel.diagnoser.diagnoser import Diagnosis
from sentinel.patcher.patcher import PatchError, Patcher


class FakeLLM:
    def __init__(self, response: str):
        self.response = response
        self.prompts: list[str] = []

    def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.response


DIAGNOSIS = Diagnosis(
    fault="sql_injection",
    root_cause="Raw SQL interpolates request input",
    confidence=99,
)
SAFE_CONTENT = '''import sqlite3

def vulnerable_raw_sql_search(connection: sqlite3.Connection, term: str):
    pattern = f"%{term}%"
    query = "SELECT id, name, email FROM users WHERE name LIKE ? OR email LIKE ?"
    return connection.execute(query, (pattern, pattern)).fetchall()
'''


def test_patcher_returns_parameterized_file_content_patch():
    llm = FakeLLM(
        '{"path":"faults/sql_injection.py", "content":' + repr(SAFE_CONTENT).replace("'", '"') + '}'
    )
    # Use JSON-safe encoding in the fake response.
    import json
    llm.response = json.dumps({"path": "faults/sql_injection.py", "content": SAFE_CONTENT})

    patch = Patcher(llm).create_patch(DIAGNOSIS)

    assert patch.path == "faults/sql_injection.py"
    assert "LIKE ? OR email LIKE ?" in patch.content
    assert "f\"WHERE" not in patch.content
    assert llm.prompts and "Raw SQL" in llm.prompts[0]


@pytest.mark.parametrize(
    "response",
    [
        '{"path":"demo_app/main.py", "content":"x"}',
        '{"path":"faults/sql_injection.py", "content":"# no vulnerable function"}',
        '```diff\n--- faults/sql_injection.py\n+++ faults/sql_injection.py\n```',
        '{"path":"faults/sql_injection.py", "content":"def vulnerable_raw_sql_search(c, t):\\n return c.execute(f\\\"SELECT * FROM users WHERE name = \'{t}\'\\\")"}',
    ],
)
def test_patcher_rejects_invalid_or_unsafe_boundaries(response: str):
    with pytest.raises(PatchError):
        Patcher(FakeLLM(response)).create_patch(DIAGNOSIS)
