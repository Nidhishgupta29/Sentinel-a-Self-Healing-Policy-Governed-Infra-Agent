"""Post-apply health-check contracts for Sentinel."""

from __future__ import annotations

from dataclasses import dataclass
import inspect
import json
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.request import urlopen


@dataclass(frozen=True)
class HealthCheckResult:
    """Normalized result of a post-apply health check."""

    passed: bool
    reason: str = ""
    status_code: int | None = None

    @property
    def healthy(self) -> bool:
        return self.passed

    @property
    def ok(self) -> bool:
        return self.passed


class HealthChecker:
    """Run an injected callable or a local HTTP health endpoint.

    The callable may accept the applied source directory as a ``Path`` or take
    no arguments. It may return a bool, a :class:`HealthCheckResult`, or an
    object exposing ``passed``/``healthy`` and an optional ``reason``.
    """

    def __init__(
        self,
        check_callable: Callable[..., Any] | None = None,
        *,
        url: str | None = None,
        timeout: float = 5.0,
        check: Callable[..., Any] | None = None,
    ) -> None:
        if check_callable is not None and check is not None:
            raise ValueError("provide only one health-check callable")
        self._check_callable = check_callable or check
        if self._check_callable is not None and url is not None:
            raise ValueError("configure either a health-check callable or a URL")
        self.url = url
        self.timeout = timeout

    def check(self, source_dir: str | Path | None = None) -> HealthCheckResult:
        if self._check_callable is not None:
            try:
                value = self._invoke_callable(source_dir)
            except Exception as exc:  # a failed check should be rollback-safe
                return HealthCheckResult(False, f"health check raised {exc}")
            return self._normalize(value)

        if self.url is not None:
            return self._check_http()

        # A missing checker is a deliberate backwards-compatible no-op. An
        # orchestrator with an injected checker still gets the full health gate.
        return HealthCheckResult(True, "no health check configured")

    def run(self, source_dir: str | Path | None = None) -> HealthCheckResult:
        """Alias for callers that use runner-style terminology."""
        return self.check(source_dir)

    def __call__(self, source_dir: str | Path | None = None) -> HealthCheckResult:
        return self.check(source_dir)

    def _invoke_callable(self, source_dir: str | Path | None) -> Any:
        callback = self._check_callable
        if callback is None:
            raise RuntimeError("health-check callable is not configured")
        try:
            signature = inspect.signature(callback)
            try:
                signature.bind(source_dir)
            except TypeError:
                return callback()
        except (TypeError, ValueError):
            # Some builtins do not expose a signature; the documented callable
            # form receives the source directory.
            pass
        return callback(source_dir)

    @staticmethod
    def _normalize(value: Any) -> HealthCheckResult:
        if isinstance(value, HealthCheckResult):
            return value
        if isinstance(value, bool):
            return HealthCheckResult(
                value,
                "health check passed" if value else "health check returned false",
            )

        if isinstance(value, Mapping):
            passed = value.get("passed", value.get("healthy", value.get("ok")))
            if passed is None:
                raise TypeError("health check mapping must contain passed or healthy")
            return HealthCheckResult(
                bool(passed),
                str(value.get("reason", "")),
                value.get("status_code"),
            )

        passed = getattr(value, "passed", None)
        if passed is None:
            passed = getattr(value, "healthy", None)
        if passed is None:
            passed = getattr(value, "ok", None)
        if passed is None:
            raise TypeError("health check must return bool or an object with passed")
        reason = str(getattr(value, "reason", ""))
        status_code = getattr(value, "status_code", None)
        return HealthCheckResult(bool(passed), reason, status_code)

    def _check_http(self) -> HealthCheckResult:
        assert self.url is not None
        try:
            response = urlopen(self.url, timeout=self.timeout)
            try:
                status_code = response.getcode()
                body = response.read()
            finally:
                response.close()
        except Exception as exc:
            return HealthCheckResult(False, f"HTTP health check failed: {exc}")

        if status_code != 200:
            return HealthCheckResult(False, f"HTTP health check returned {status_code}", status_code)

        # The demo app exposes {"status": "healthy"}; for a generic local
        # endpoint, a successful HTTP response without JSON is also healthy.
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return HealthCheckResult(True, "HTTP health check passed", status_code)
        if isinstance(payload, dict) and payload.get("status") not in (None, "healthy"):
            return HealthCheckResult(
                False,
                f"HTTP health status was {payload.get('status')!r}",
                status_code,
            )
        return HealthCheckResult(True, "HTTP health check passed", status_code)
