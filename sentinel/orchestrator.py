"""Single-fault SQL-injection detection, repair, and verification loop."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Any, Mapping, Protocol

from sentinel.policy import PolicyEngine as LoadedPolicyEngine
from sentinel.postmortem import PostmortemGenerator
from sentinel.rollback import Backup, HealthChecker, HealthCheckResult, RollbackResult


logger = logging.getLogger(__name__)
CONFIDENCE_THRESHOLD = 70


def _announce(message: str, *args: object) -> None:
    """Emit progress to both normal logs and an interactive console."""
    rendered = message % args if args else message
    logger.info(rendered)
    print(f"[sentinel] {rendered}")


@dataclass(frozen=True)
class OrchestrationResult:
    """The observable outcome of one repair attempt."""

    anomaly: Any
    diagnosis: Any
    patches: Mapping[str, str]
    sandbox_passed: bool
    applied: bool
    diagnostics: str = ""
    status: str = ""
    policy_allowed: bool | None = None
    policy_reason: str = ""
    health_passed: bool | None = None
    health_reason: str = ""
    rollback_result: RollbackResult | None = None
    rollback_reason: str = ""
    anomaly_results: tuple["OrchestrationResult", ...] = ()
    actions_taken: tuple[str, ...] = ()
    review_reason: str = ""
    started_at: datetime | None = None
    postmortem_path: Path | None = None

    @property
    def rolled_back(self) -> bool:
        return self.rollback_result is not None and self.rollback_result.restored

    @property
    def outcomes(self) -> tuple["OrchestrationResult", ...]:
        """Alias for the per-anomaly outcomes in a cascading run."""
        return self.anomaly_results

    @property
    def per_anomaly_results(self) -> tuple["OrchestrationResult", ...]:
        return self.anomaly_results

    @property
    def results(self) -> tuple["OrchestrationResult", ...]:
        return self.anomaly_results

    @property
    def canonical_status(self) -> str:
        """Return the Phase 4 status vocabulary without breaking old callers."""
        return {
            "applied": "fixed",
            "policy_blocked": "blocked",
            "sandbox_failed": "blocked",
            "rollback_failed": "rolled_back",
        }.get(self.status, self.status)

    @property
    def reason(self) -> str:
        return self.review_reason or self.policy_reason or self.rollback_reason or self.diagnostics


@dataclass(frozen=True)
class PolicyDecision:
    """The small policy boundary expected by the orchestrator."""

    allowed: bool
    reason: str = ""


class PolicyEngine(Protocol):
    """Policy implementations validate and audit a proposed patch."""

    def check(self, patches: Mapping[str, str]) -> PolicyDecision:
        """Return an object exposing ``allowed`` and ``reason``."""


class _AllowAllPolicy:
    """Compatibility policy used when Phase 2 callers inject none."""

    def check(self, patches: Mapping[str, str]) -> PolicyDecision:
        return PolicyDecision(True, "no policy engine configured")


class SentinelOrchestrator:
    """Coordinate injected SQL-injection components without owning their logic."""

    def __init__(
        self,
        detector,
        diagnoser,
        patcher,
        sandbox,
        source_dir: str | Path,
        policy_engine: PolicyEngine | None = None,
        health_checker=None,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
        audit_log=None,
        postmortem_generator=None,
        postmortem_dir: str | Path | None = None,
    ):
        if isinstance(confidence_threshold, bool) or not 0 <= confidence_threshold <= 100:
            raise ValueError("confidence_threshold must be between 0 and 100")
        self.detector = detector
        self.diagnoser = diagnoser
        self.patcher = patcher
        self.sandbox = sandbox
        self.source_dir = Path(source_dir)
        self.policy_engine = policy_engine or LoadedPolicyEngine()
        self.health_checker = health_checker or HealthChecker()
        self.confidence_threshold = confidence_threshold
        self.audit_log = audit_log or getattr(self.policy_engine, "audit_log", None)
        if postmortem_generator is not None and postmortem_dir is not None:
            raise ValueError("provide either postmortem_generator or postmortem_dir")
        self.postmortem_generator = postmortem_generator or PostmortemGenerator(
            postmortem_dir or self.source_dir / "postmortems"
        )

    def run(self, log_text: str) -> OrchestrationResult:
        started_at = datetime.now(timezone.utc)
        _announce("Sentinel step: detect")
        detected = self.detector.detect(log_text)
        anomalies = self._normalize_anomalies(detected)
        if not anomalies:
            _announce("Sentinel: no anomaly detected")
            return self._finish(
                OrchestrationResult(
                    None,
                    None,
                    {},
                    False,
                    False,
                    status="no_anomaly",
                    started_at=started_at,
                )
            )

        ordered = sorted(
            enumerate(anomalies),
            key=lambda item: (-self._severity_priority(item[1]), item[0]),
        )
        outcomes = [
            self._process_anomaly(anomaly, started_at)
            for _, anomaly in ordered
        ]
        if len(outcomes) == 1:
            return self._finish(outcomes[0])
        return self._finish(self._aggregate_outcomes(outcomes, started_at))

    def _process_anomaly(self, anomaly: Any, started_at: datetime) -> OrchestrationResult:
        fault = str(self._field(anomaly, "fault", "unknown"))
        severity = str(self._field(anomaly, "severity", "unknown"))
        evidence = str(self._field(anomaly, "evidence", "no evidence recorded"))
        actions = [f"Detected {fault} anomaly with {severity} severity."]

        if fault == "suspicious_input":
            reason = f"suspicious_input: detector flagged suspicious input; evidence: {evidence}"
            _announce("Sentinel: suspicious input detected; patching stopped")
            self._record_audit("suspicious_input_detected", "block", reason)
            actions.append("Blocked suspicious input before diagnosis or patch generation.")
            return OrchestrationResult(
                anomaly,
                None,
                {},
                False,
                False,
                diagnostics=reason,
                status="needs_human_review",
                policy_allowed=False,
                policy_reason=reason,
                actions_taken=tuple(actions),
                review_reason="suspicious_input",
                started_at=started_at,
            )

        _announce("Sentinel step: diagnose (%s)", fault)
        diagnosis = self.diagnoser.diagnose(anomaly)
        confidence = self._confidence(diagnosis)
        actions.append(
            f"Diagnosis completed with confidence {confidence} (threshold {self.confidence_threshold})."
        )
        if confidence < self.confidence_threshold:
            reason = (
                f"low_confidence: diagnosis confidence {confidence} is below threshold "
                f"{self.confidence_threshold}"
            )
            _announce("Sentinel: %s; patching stopped", reason)
            self._record_audit("confidence gate", "block", reason)
            actions.append("Stopped before patch generation for human review.")
            return OrchestrationResult(
                anomaly,
                diagnosis,
                {},
                False,
                False,
                diagnostics=reason,
                status="needs_human_review",
                actions_taken=tuple(actions),
                review_reason="low_confidence",
                started_at=started_at,
            )

        _announce("Sentinel step: patch (%s)", fault)
        patches = self._normalize_patches(self.patcher.create_patch(diagnosis))
        actions.append(f"Generated patch for {', '.join(patches)}.")

        _announce("Sentinel step: policy (%s)", fault)
        policy_decision = self.policy_engine.check(patches)
        policy_allowed, policy_reason = self._policy_decision(policy_decision)
        if not policy_allowed:
            reason = policy_reason or "policy blocked the proposed patch"
            _announce("Sentinel: policy blocked patch (%s)", reason)
            actions.append(f"Policy blocked the patch: {reason}")
            return OrchestrationResult(
                anomaly,
                diagnosis,
                patches,
                False,
                False,
                diagnostics=reason,
                status="policy_blocked",
                policy_allowed=False,
                policy_reason=reason,
                actions_taken=tuple(actions),
                started_at=started_at,
            )
        actions.append(f"Policy allowed the patch: {policy_reason}")

        _announce("Sentinel step: sandbox (%s)", fault)
        sandbox_result = self.sandbox.run(patches)
        diagnostics = getattr(sandbox_result, "diagnostics", "")
        if not sandbox_result.passed:
            _announce("Sentinel: sandbox failed; patch not applied (%s)", diagnostics)
            actions.append(f"Sandbox failed: {diagnostics or 'no diagnostics'}")
            return OrchestrationResult(
                anomaly,
                diagnosis,
                patches,
                False,
                False,
                diagnostics=diagnostics,
                status="sandbox_failed",
                policy_allowed=True,
                policy_reason=policy_reason,
                actions_taken=tuple(actions),
                started_at=started_at,
            )
        actions.append(f"Sandbox passed: {diagnostics or 'no diagnostics'}")

        backup = Backup.capture(self.source_dir, patches)
        _announce("Sentinel step: apply (%s)", fault)
        self._apply_patches(patches)
        actions.append(f"Applied patch for {', '.join(patches)}.")
        _announce("Sentinel: patch applied; running health check")
        health_result = self._run_health_check()
        if not health_result.passed:
            health_reason = health_result.reason or "health check failed"
            rollback_reason = f"health check failed: {health_reason}"
            _announce("Sentinel: %s; rolling back", health_reason)
            rollback_result = backup.restore(rollback_reason)
            self._record_audit("rollback", "rollback", rollback_result.reason)
            _announce(
                "Sentinel: rollback %s (%s)",
                "completed" if rollback_result.restored else "failed",
                rollback_result.reason,
            )
            actions.append(f"Health check failed: {health_reason}")
            actions.append(f"Rollback: {rollback_result.reason}")
            combined_diagnostics = "\n".join(
                part for part in (diagnostics, health_reason, rollback_result.reason) if part
            )
            return OrchestrationResult(
                anomaly,
                diagnosis,
                patches,
                True,
                False,
                diagnostics=combined_diagnostics,
                status="rolled_back" if rollback_result.restored else "rollback_failed",
                policy_allowed=True,
                policy_reason=policy_reason,
                health_passed=False,
                health_reason=health_reason,
                rollback_result=rollback_result,
                rollback_reason=rollback_result.reason,
                actions_taken=tuple(actions),
                started_at=started_at,
            )

        _announce("Sentinel: health check passed")
        actions.append(f"Health check passed: {health_result.reason or 'healthy'}")
        return OrchestrationResult(
            anomaly,
            diagnosis,
            patches,
            True,
            True,
            diagnostics=diagnostics,
            status="applied",
            policy_allowed=True,
            policy_reason=policy_reason,
            health_passed=True,
            health_reason=health_result.reason,
            actions_taken=tuple(actions),
            started_at=started_at,
        )

    def _aggregate_outcomes(
        self, outcomes: list[OrchestrationResult], started_at: datetime
    ) -> OrchestrationResult:
        statuses = [outcome.status for outcome in outcomes]
        if any(status == "needs_human_review" for status in statuses):
            status = "needs_human_review"
        elif any(status in {"rolled_back", "rollback_failed"} for status in statuses):
            status = "rolled_back"
        elif any(status in {"policy_blocked", "sandbox_failed"} for status in statuses):
            status = "blocked"
        else:
            status = "fixed"

        patches: dict[str, str] = {}
        for outcome in outcomes:
            patches.update(outcome.patches)
        diagnostics = "\n".join(
            outcome.diagnostics for outcome in outcomes if outcome.diagnostics
        )
        policy_reasons = "; ".join(
            outcome.policy_reason for outcome in outcomes if outcome.policy_reason
        )
        review_reasons = "; ".join(
            outcome.review_reason for outcome in outcomes if outcome.review_reason
        )
        health_values = [outcome.health_passed for outcome in outcomes]
        health_passed = None if any(value is None for value in health_values) else all(health_values)
        return OrchestrationResult(
            tuple(outcome.anomaly for outcome in outcomes),
            tuple(outcome.diagnosis for outcome in outcomes),
            patches,
            all(outcome.sandbox_passed for outcome in outcomes),
            all(outcome.applied for outcome in outcomes),
            diagnostics=diagnostics,
            status=status,
            policy_allowed=all(
                outcome.policy_allowed is not False for outcome in outcomes
            ),
            policy_reason=policy_reasons,
            health_passed=health_passed,
            rollback_result=next(
                (outcome.rollback_result for outcome in outcomes if outcome.rollback_result),
                None,
            ),
            rollback_reason="; ".join(
                outcome.rollback_reason for outcome in outcomes if outcome.rollback_reason
            ),
            anomaly_results=tuple(outcomes),
            actions_taken=tuple(
                action
                for outcome in outcomes
                for action in outcome.actions_taken
            ),
            review_reason=review_reasons,
            started_at=started_at,
        )

    def _finish(self, result: OrchestrationResult) -> OrchestrationResult:
        """Generate exactly one postmortem immediately before returning."""
        self.postmortem_generator.generate(result)
        path = getattr(self.postmortem_generator, "last_path", None)
        if path is None:
            return result
        return replace(result, postmortem_path=Path(path))

    @staticmethod
    def _normalize_anomalies(detected: Any) -> list[Any]:
        if detected is None:
            return []
        if isinstance(detected, (list, tuple)):
            return list(detected)
        return [detected]

    @staticmethod
    def _field(value: Any, name: str, default: Any = None) -> Any:
        if isinstance(value, Mapping):
            return value.get(name, default)
        return getattr(value, name, default)

    @classmethod
    def _severity_priority(cls, anomaly: Any) -> int:
        fault = cls._field(anomaly, "fault", "")
        severity = cls._field(anomaly, "severity", "")
        if fault == "suspicious_input" or severity == "suspicious_input":
            return 4
        return {
            "critical": 3,
            "medium": 2,
            "low": 1,
        }.get(str(severity).lower(), 0)

    def _apply_patches(self, patches: Mapping[str, str]) -> None:
        for relative_name, contents in patches.items():
            relative_path = Path(relative_name)
            if relative_path.is_absolute() or ".." in relative_path.parts:
                raise ValueError(f"Patch path must stay inside the source: {relative_name}")
            target = self.source_dir / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(contents, encoding="utf-8")

    def _run_health_check(self) -> HealthCheckResult:
        checker = self.health_checker
        try:
            if hasattr(checker, "check"):
                value = checker.check(self.source_dir)
            elif hasattr(checker, "run"):
                value = checker.run(self.source_dir)
            elif callable(checker):
                value = HealthChecker(checker).check(self.source_dir)
            else:
                raise TypeError("health_checker must expose check/run or be callable")
            if isinstance(value, HealthCheckResult):
                return value
            return HealthChecker._normalize(value)
        except Exception as exc:
            return HealthCheckResult(False, f"health check raised {exc}")

    def _record_audit(self, action: str, decision: str, reason: str) -> None:
        """Write optional orchestration events without coupling test doubles."""
        if self.audit_log is None:
            return
        try:
            self.audit_log.record(action=action, decision=decision, reason=reason)
        except Exception as exc:
            _announce("Sentinel: audit log write failed (%s)", exc)

    @staticmethod
    def _confidence(diagnosis: Any) -> int:
        if isinstance(diagnosis, Mapping):
            confidence = diagnosis.get("confidence")
        else:
            confidence = getattr(diagnosis, "confidence", None)
        if isinstance(confidence, bool) or not isinstance(confidence, int):
            raise TypeError("diagnosis must expose an integer confidence")
        if not 0 <= confidence <= 100:
            raise ValueError("diagnosis confidence must be between 0 and 100")
        return confidence

    @staticmethod
    def _policy_decision(decision: Any) -> tuple[bool, str]:
        allowed = getattr(decision, "allowed", None)
        reason = getattr(decision, "reason", "")
        if not isinstance(allowed, bool):
            raise TypeError("policy.check must return an object with boolean allowed")
        return allowed, str(reason)

    @staticmethod
    def _normalize_patches(patch_result) -> Mapping[str, str]:
        """Normalize one FilePatch or a mapping for swappable patchers."""
        if isinstance(patch_result, Mapping):
            return patch_result
        path = getattr(patch_result, "path", None)
        content = getattr(patch_result, "content", None)
        if isinstance(path, str) and isinstance(content, str):
            return {path: content}
        raise TypeError("patcher must return a mapping or file patch")


Orchestrator = SentinelOrchestrator
