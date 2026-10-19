"""LLM-backed diagnosis contracts for Sentinel anomalies."""

from dataclasses import dataclass
import json
from typing import Protocol

from sentinel.detector.detector import Anomaly


class LLMClient(Protocol):
    def complete(self, prompt: str) -> str: ...


@dataclass(frozen=True)
class Diagnosis:
    fault: str
    root_cause: str
    confidence: int


class DiagnosisError(ValueError):
    """Raised when the injected model returns an unusable diagnosis."""


class Diagnoser:
    def __init__(self, client: LLMClient):
        self._client = client

    def diagnose(self, anomaly: Anomaly) -> Diagnosis:
        prompt = (
            "Diagnose this Sentinel anomaly. Return JSON with string root_cause "
            "and integer confidence from 0 to 100.\n"
            f"fault={anomaly.fault}; severity={anomaly.severity}; "
            f"evidence={anomaly.evidence}"
        )
        try:
            result = json.loads(self._client.complete(prompt))
            root_cause = result["root_cause"]
            confidence = result["confidence"]
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DiagnosisError("LLM diagnosis must be valid JSON") from exc
        if (
            not isinstance(root_cause, str)
            or not root_cause.strip()
            or isinstance(confidence, bool)
            or not isinstance(confidence, int)
            or not 0 <= confidence <= 100
        ):
            raise DiagnosisError("diagnosis has invalid root cause or confidence")
        return Diagnosis(anomaly.fault, root_cause.strip(), confidence)
