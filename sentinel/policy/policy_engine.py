"""Policy validation for proposed relative file patches."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from typing import Mapping

import yaml

from .audit_log import AuditLog


DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.yaml")


@dataclass(frozen=True)
class PolicyDecision:
    """An explicit allow/block outcome and the reason for it."""

    decision: str
    reason: str
    checked_paths: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def blocked(self) -> bool:
        return self.decision == "block"


class PolicyEngine:
    """Load a policy file and validate patches before sandbox execution."""

    def __init__(
        self,
        policy_path: str | Path | None = None,
        audit_log: AuditLog | str | Path | None = None,
    ) -> None:
        self.policy_path = Path(policy_path or DEFAULT_POLICY_PATH)
        self._config = self._load_policy(self.policy_path)
        self.allowed_paths = self._string_list("allowed_paths")
        self.denied_paths = self._string_list("denied_paths")
        self.denied_content_patterns = self._compile_content_patterns()
        if audit_log is None:
            audit_log = self.policy_path.with_name("audit.sqlite3")
        self.audit_log = audit_log if isinstance(audit_log, AuditLog) else AuditLog(audit_log)

    def evaluate(self, patches: Mapping[str, str]) -> PolicyDecision:
        """Evaluate every proposed patch and return one aggregate decision.

        Checks are performed in sorted path order so the first reported
        blocking reason is stable regardless of mapping insertion order.  A
        separate audit record is written for every proposed path.
        """
        if not isinstance(patches, Mapping):
            raise TypeError("patches must be a mapping of relative paths to text")

        if not patches:
            reason = "no patches proposed"
            self.audit_log.record(action="patch batch", decision="allow", reason=reason)
            return PolicyDecision("allow", reason)

        decisions = [
            self.check_patch(relative_path, contents)
            for relative_path, contents in sorted(
                patches.items(), key=lambda item: str(item[0])
            )
        ]
        checked_paths = tuple(
            str(relative_path)
            for relative_path, _ in sorted(
                patches.items(), key=lambda item: str(item[0])
            )
        )
        blocked = [decision for decision in decisions if decision.blocked]
        if blocked:
            reason = blocked[0].reason if len(blocked) == 1 else (
                f"patch set blocked: {blocked[0].reason}"
            )
            return PolicyDecision("block", reason, checked_paths)

        reason = decisions[0].reason if len(decisions) == 1 else (
            f"all {len(decisions)} proposed patches are allowed by policy"
        )
        return PolicyDecision("allow", reason, checked_paths)

    def check_patch(self, relative_path: str, contents: str) -> PolicyDecision:
        """Check one patch and write its allow/block result to the audit log."""
        action = f"patch {relative_path}"
        normalized, path_error = self._normalize_relative_path(relative_path)
        if path_error is not None:
            return self._record_block(action, path_error, relative_path)
        if not isinstance(contents, str):
            return self._record_block(
                action,
                "patch content must be text",
                relative_path,
            )

        for pattern in self.denied_paths:
            if self._matches_path(normalized, pattern):
                reason = f"path '{relative_path}' is denied by pattern '{pattern}'"
                return self._record_block(action, reason, relative_path)

        if not any(self._matches_path(normalized, pattern) for pattern in self.allowed_paths):
            reason = f"path '{relative_path}' is outside allowed policy globs"
            return self._record_block(action, reason, relative_path)

        for name, pattern in self.denied_content_patterns:
            if pattern.search(contents):
                reason = f"patch content matches denied pattern '{name}'"
                return self._record_block(action, reason, relative_path)

        reason = f"path '{relative_path}' and its content satisfy policy"
        self.audit_log.record(action=action, decision="allow", reason=reason)
        return PolicyDecision("allow", reason, (str(relative_path),))

    def check(self, patches: Mapping[str, str]) -> PolicyDecision:
        """Compatibility name for callers that invoke a policy check."""
        return self.evaluate(patches)

    def evaluate_patch(
        self,
        patches_or_path: Mapping[str, str] | str,
        contents: str | None = None,
    ) -> PolicyDecision:
        """Evaluate a patch mapping, or one path/content pair when supplied."""
        if isinstance(patches_or_path, Mapping):
            if contents is not None:
                raise TypeError("contents is only valid when checking one path")
            return self.evaluate(patches_or_path)
        if contents is None:
            raise TypeError("contents is required when checking one path")
        return self.check_patch(patches_or_path, contents)

    def _record_block(
        self, action: str, reason: str, relative_path: object
    ) -> PolicyDecision:
        self.audit_log.record(action=action, decision="block", reason=reason)
        return PolicyDecision("block", reason, (str(relative_path),))

    @staticmethod
    def _load_policy(path: Path) -> Mapping[str, object]:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as error:
            raise ValueError(f"unable to read policy file: {path}") from error
        if not isinstance(raw, Mapping):
            raise ValueError("policy file must contain a mapping")
        return raw

    def _string_list(self, key: str) -> tuple[str, ...]:
        value = self._config.get(key, ())
        if not isinstance(value, (list, tuple)) or not all(
            isinstance(item, str) and item for item in value
        ):
            raise ValueError(f"policy field '{key}' must be a list of strings")
        return tuple(value)

    def _compile_content_patterns(self) -> tuple[tuple[str, re.Pattern[str]], ...]:
        value = self._config.get("denied_content_patterns", ())
        if not isinstance(value, (list, tuple)):
            raise ValueError("policy field 'denied_content_patterns' must be a list")

        compiled: list[tuple[str, re.Pattern[str]]] = []
        for index, item in enumerate(value):
            if isinstance(item, str):
                name = f"pattern_{index + 1}"
                expression = item
            elif isinstance(item, Mapping):
                name = item.get("name")
                expression = item.get("regex", item.get("pattern"))
                if not isinstance(name, str) or not name:
                    raise ValueError("each denied content pattern needs a name")
            else:
                raise ValueError("denied content patterns must be strings or mappings")
            if not isinstance(expression, str) or not expression:
                raise ValueError(f"denied content pattern '{name}' needs a regex")
            try:
                compiled.append((name, re.compile(expression)))
            except re.error as error:
                raise ValueError(f"invalid denied content regex '{name}'") from error
        return tuple(compiled)

    @staticmethod
    def _normalize_relative_path(relative_path: object) -> tuple[str, str | None]:
        if not isinstance(relative_path, str) or not relative_path:
            return "", "patch path must be a non-empty relative string"
        if "\x00" in relative_path:
            return "", "patch path contains a null byte"

        posix_path = relative_path.replace("\\", "/")
        pure_posix = PurePosixPath(posix_path)
        pure_windows = PureWindowsPath(relative_path)
        if pure_posix.is_absolute() or pure_windows.is_absolute() or pure_windows.drive:
            return "", f"patch path must be relative: {relative_path}"
        if ".." in pure_posix.parts:
            return "", f"patch path traversal is blocked: {relative_path}"

        normalized = "/".join(part for part in pure_posix.parts if part not in {"", "."})
        if not normalized:
            return "", "patch path must identify a file"
        return normalized, None

    @staticmethod
    def _matches_path(path: str, pattern: str) -> bool:
        normalized_pattern = pattern.replace("\\", "/")
        return PurePosixPath(path).match(normalized_pattern)


__all__ = ["DEFAULT_POLICY_PATH", "PolicyDecision", "PolicyEngine"]
