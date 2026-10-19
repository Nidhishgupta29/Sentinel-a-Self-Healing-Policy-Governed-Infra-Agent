"""Detection of normal faults and untrusted prompt-injection log input."""

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Union


@dataclass(frozen=True)
class Anomaly:
    fault: str
    severity: str
    evidence: str
    source: str
    matched_pattern: str | None = None


class AnomalyCollection(list[Anomaly]):
    """List result that preserves attribute access for old single-fault callers."""

    @property
    def fault(self) -> str:
        return self[0].fault

    @property
    def severity(self) -> str:
        return self[0].severity

    @property
    def evidence(self) -> str:
        return self[0].evidence

    @property
    def source(self) -> str:
        return self[0].source


@dataclass(frozen=True)
class LogInput:
    value: Union[str, Path]

    @property
    def text(self) -> str:
        if isinstance(self.value, Path):
            return self.value.read_text(encoding="utf-8")
        return self.value


class Detector:
    """Recognize faults, prioritizing suspicious instructions in log input."""

    _signature = re.compile(
        r"(?:['\"]\s*or\s+\d+\s*=\s*\d+|\bor\s+1\s*=\s*1)\s*(?:--|#|/\*)",
        re.IGNORECASE,
    )

    _suspicious_patterns: tuple[tuple[str, re.Pattern[str]], ...] = (
        (
            "ignore all previous instructions",
            re.compile(r"ignore\s+all\s+previous\s+instructions", re.IGNORECASE),
        ),
        (
            "ignore previous instructions",
            re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
        ),
        (
            "disable the policy engine",
            re.compile(r"disable\s+the\s+policy\s+engine", re.IGNORECASE),
        ),
        (
            "disable policy",
            re.compile(r"disable\s+policy", re.IGNORECASE),
        ),
        (
            "delete all files",
            re.compile(r"delete\s+all\s+files", re.IGNORECASE),
        ),
        (
            "bypass policy",
            re.compile(r"bypass\s+policy", re.IGNORECASE),
        ),
        (
            "skip policy check",
            re.compile(r"skip\s+policy\s+check", re.IGNORECASE),
        ),
        (
            "SYSTEM imperative",
            re.compile(
                r"\bSYSTEM:\s*(?:ignore|disable|delete|bypass|skip|execute|run|"
                r"override|remove|reveal|exfiltrate)\b[^\r\n]*",
                re.IGNORECASE,
            ),
        ),
    )

    _fault_signatures: tuple[tuple[str, str, re.Pattern[str]], ...] = (
        (
            "sql_injection",
            "critical",
            _signature,
        ),
        (
            "memory_leak",
            "medium",
            re.compile(r"(?:memory[_\s-]+leak|out\s+of\s+memory)", re.IGNORECASE),
        ),
        (
            "slow_query",
            "low",
            re.compile(r"(?:slow[_\s-]+query|query\s+latency)", re.IGNORECASE),
        ),
    )

    def detect(self, log: Union[str, Path]) -> AnomalyCollection | None:
        if not isinstance(log, (str, Path)):
            raise TypeError("log must be text or a pathlib.Path")
        path = Path(log) if isinstance(log, Path) else None
        text = log.read_text(encoding="utf-8") if path is not None else log

        suspicious = self._find_suspicious(text)
        if suspicious is not None:
            pattern_name, match = suspicious
            return AnomalyCollection(
                [
                    Anomaly(
                        fault="suspicious_input",
                        severity="suspicious_input",
                        evidence=self._evidence(text, match, pattern_name),
                        source=str(path) if path is not None else "log",
                        matched_pattern=pattern_name,
                    )
                ]
            )

        anomalies: list[Anomaly] = []
        for fault, severity, signature in self._fault_signatures:
            match = signature.search(text)
            if match is None:
                continue
            if fault == "sql_injection" and "faults/sql_injection.py" not in text:
                continue
            anomalies.append(
                Anomaly(
                    fault=fault,
                    severity=severity,
                    evidence=match.group(0),
                    source=str(path) if path is not None else "log",
                )
            )

        if not anomalies:
            return None
        return AnomalyCollection(anomalies)

    def _find_suspicious(
        self, text: str
    ) -> tuple[str, re.Match[str]] | None:
        matches: list[tuple[int, int, str, re.Match[str]]] = []
        for order, (name, pattern) in enumerate(self._suspicious_patterns):
            match = pattern.search(text)
            if match is not None:
                matches.append((match.start(), order, name, match))
        if not matches:
            return None
        _, _, name, match = min(matches, key=lambda item: (item[0], item[1]))
        return name, match

    @staticmethod
    def _evidence(text: str, match: re.Match[str], pattern_name: str) -> str:
        start = max(0, match.start() - 50)
        end = min(len(text), match.end() + 50)
        context = text[start:end]
        return f"pattern={pattern_name}; context={context}"
