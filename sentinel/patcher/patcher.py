"""Validated file-content patch generation for the isolated SQLi fault."""

from dataclasses import dataclass
import json
from typing import Protocol

from sentinel.diagnoser.diagnoser import Diagnosis


class LLMClient(Protocol):
    def complete(self, prompt: str) -> str: ...


@dataclass(frozen=True)
class FilePatch:
    path: str
    content: str


class PatchError(ValueError):
    """Raised when a model response is not a safe, bounded file patch."""


class Patcher:
    _target = "faults/sql_injection.py"

    def __init__(self, client: LLMClient):
        self._client = client

    def create_patch(self, diagnosis: Diagnosis) -> FilePatch:
        prompt = (
            "Create a JSON file-content patch for the diagnosed Sentinel fault. "
            "Only path faults/sql_injection.py is permitted. Replace raw SQL "
            "interpolation with demo_app's parameterized LIKE query using ? placeholders. "
            f"Diagnosis: {diagnosis.root_cause} (confidence {diagnosis.confidence})"
        )
        response = self._client.complete(prompt)
        try:
            payload = json.loads(response)
            path = payload["path"]
            content = payload["content"]
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PatchError("LLM patch must be a JSON object with path and content") from exc
        if not isinstance(path, str) or path != self._target or not isinstance(content, str):
            raise PatchError("patch path or content is invalid")
        if "```" in content or "vulnerable_raw_sql_search" not in content:
            raise PatchError("patch must contain the bounded vulnerable function")
        if "LIKE ?" not in content or "OR email LIKE ?" not in content:
            raise PatchError("patch must use the parameterized LIKE query")
        if "execute(query, (pattern, pattern))" not in content:
            raise PatchError("patch must bind both query parameters")
        if "f\"WHERE" in content or "f'WHERE" in content or "f\"SELECT" in content or "f'SELECT" in content:
            raise PatchError("patch still interpolates SQL")
        return FilePatch(path=path, content=content)
