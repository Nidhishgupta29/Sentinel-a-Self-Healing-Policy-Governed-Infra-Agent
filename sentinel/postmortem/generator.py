"""Generate deterministic Markdown records for completed Sentinel runs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


class PostmortemGenerator:
    """Write one human-readable postmortem for each completed run."""

    def __init__(self, output_dir: str | Path = "postmortems") -> None:
        self.output_dir = Path(output_dir)
        self.last_path: Path | None = None

    def generate(self, run_result: Any) -> str:
        """Render and persist a Markdown postmortem, returning its content."""
        started_at = self._started_at(run_result)
        outcomes = self._outcomes(run_result)
        fault = self._fault_name(run_result, outcomes)
        status = self._canonical_status(self._value(run_result, "status", "unknown"))
        anomalies = [self._value(outcome, "anomaly") for outcome in outcomes]
        severities = self._severities(anomalies)

        what_happened = self._what_happened(run_result, anomalies)
        diagnosis = self._diagnosis(run_result, outcomes)
        actions = self._actions(run_result, outcomes)
        outcome = self._outcome(run_result, status)
        timestamp = started_at.isoformat()

        content = "\n".join(
            [
                f"# Postmortem: {fault} — {status}",
                "",
                f"Timestamp: {timestamp}",
                f"Status: {status}",
                f"Severity: {severities}",
                "",
                "## What happened",
                "",
                what_happened,
                "",
                "## Diagnosis",
                "",
                diagnosis,
                "",
                "## Actions taken",
                "",
                actions,
                "",
                "## Outcome",
                outcome,
                "",
            ]
        )

        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{started_at.strftime('%Y%m%d_%H%M%S')}_{self._slug(fault)}.md"
        self.last_path = self.output_dir / filename
        suffix = 1
        while self.last_path.exists():
            self.last_path = self.output_dir / (
                f"{started_at.strftime('%Y%m%d_%H%M%S')}_{self._slug(fault)}_{suffix}.md"
            )
            suffix += 1
        self.last_path.write_text(content, encoding="utf-8")
        return content

    @staticmethod
    def _value(value: Any, name: str, default: Any = None) -> Any:
        if isinstance(value, Mapping):
            return value.get(name, default)
        return getattr(value, name, default)

    @classmethod
    def _outcomes(cls, run_result: Any) -> list[Any]:
        outcomes = cls._value(run_result, "anomaly_results", ())
        if outcomes:
            return list(outcomes)
        return [run_result]

    @classmethod
    def _fault_name(cls, run_result: Any, outcomes: list[Any]) -> str:
        if len(outcomes) > 1:
            return "multi"
        anomaly = cls._value(outcomes[0], "anomaly") if outcomes else None
        fault = cls._value(anomaly, "fault")
        if fault:
            return str(fault)
        return str(cls._value(run_result, "fault", "unknown"))

    @classmethod
    def _severities(cls, anomalies: Iterable[Any]) -> str:
        values: list[str] = []
        for anomaly in anomalies:
            severity = cls._value(anomaly, "severity")
            if severity is not None and str(severity) not in values:
                values.append(str(severity))
        return ", ".join(values) if values else "unknown"

    @classmethod
    def _what_happened(cls, run_result: Any, anomalies: list[Any]) -> str:
        descriptions: list[str] = []
        for anomaly in anomalies:
            fault = cls._value(anomaly, "fault", "unknown")
            severity = cls._value(anomaly, "severity", "unknown")
            evidence = cls._value(anomaly, "evidence", "no evidence recorded")
            descriptions.append(
                f"Detected {fault} with {severity} severity; evidence: {evidence}."
            )
        if descriptions:
            return " ".join(descriptions)
        status = cls._value(run_result, "status", "unknown")
        return f"No anomaly details were available for this {status} run."

    @classmethod
    def _diagnosis(cls, run_result: Any, outcomes: list[Any]) -> str:
        lines: list[str] = []
        for outcome in outcomes:
            diagnosis = cls._value(outcome, "diagnosis")
            fault = cls._value(cls._value(outcome, "anomaly"), "fault", "anomaly")
            if diagnosis is None:
                reason = (
                    cls._value(outcome, "review_reason")
                    or cls._value(outcome, "policy_reason")
                    or cls._value(outcome, "diagnostics")
                    or "the pipeline stopped before diagnosis"
                )
                lines.append(f"Diagnosis skipped: {reason}")
                continue
            root_cause = cls._value(diagnosis, "root_cause", "not provided")
            confidence = cls._value(diagnosis, "confidence", "unknown")
            lines.append(f"{fault}: root cause: {root_cause}; confidence: {confidence}")
        if lines:
            return "\n".join(lines)
        return "Diagnosis skipped: no anomaly was detected."

    @classmethod
    def _actions(cls, run_result: Any, outcomes: list[Any]) -> str:
        lines: list[str] = []
        for outcome in outcomes:
            actions = cls._value(outcome, "actions_taken", ())
            if actions:
                lines.extend(f"- {action}" for action in actions)
                continue
            status = cls._value(outcome, "status", "unknown")
            diagnostics = cls._value(outcome, "diagnostics", "")
            lines.append(f"- Run reached status: {status}." + (f" {diagnostics}" if diagnostics else ""))
        if not lines:
            lines.append("- No actions were taken.")
        return "\n".join(lines)

    @classmethod
    def _outcome(cls, run_result: Any, status: str) -> str:
        diagnostics = cls._value(run_result, "diagnostics", "")
        summary = {
            "fixed": "The proposed repair was applied successfully.",
            "blocked": "The proposed action was stopped by a guardrail.",
            "rolled_back": "The applied change failed health validation and was restored.",
            "needs_human_review": "Automation stopped and requires human review.",
        }.get(status, "The run completed without an automated change.")
        return f"Final status: {status}. {summary}" + (f" {diagnostics}" if diagnostics else "")

    @staticmethod
    def _canonical_status(status: str) -> str:
        return {
            "applied": "fixed",
            "policy_blocked": "blocked",
            "sandbox_failed": "blocked",
            "rollback_failed": "rolled_back",
        }.get(status, status)

    @staticmethod
    def _started_at(run_result: Any) -> datetime:
        value = PostmortemGenerator._value(run_result, "started_at")
        if isinstance(value, datetime):
            return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value)
                return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _slug(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "unknown"


__all__ = ["PostmortemGenerator"]
