"""Interfaces for running commands against an isolated source copy."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Mapping, Protocol, Sequence


@dataclass(frozen=True)
class SandboxResult:
    """The observable result of a sandbox command execution."""

    return_code: int
    stdout: str
    stderr: str
    temp_path: Path


class SandboxRunner(Protocol):
    """Runner interface that can also be implemented by a Docker backend."""

    def run(
        self,
        source_dir: str | Path,
        patches: Mapping[str, str],
        command: Sequence[str],
        timeout: float | None = None,
    ) -> SandboxResult:
        """Run ``command`` from a patched, isolated copy of ``source_dir``."""


class LocalSandboxRunner:
    """Run a command in a temporary local copy of a source directory."""

    def run(
        self,
        source_dir: str | Path,
        patches: Mapping[str, str],
        command: Sequence[str],
        timeout: float | None = None,
    ) -> SandboxResult:
        source = Path(source_dir)
        if not source.is_dir():
            raise NotADirectoryError(f"Source directory does not exist: {source}")
        if not command:
            raise ValueError("command must contain at least one argument")

        temp_path = Path(tempfile.mkdtemp(prefix="sentinel-sandbox-"))
        try:
            shutil.copytree(source, temp_path, dirs_exist_ok=True)
            self._apply_patches(temp_path, patches)
            completed = subprocess.run(
                list(command),
                cwd=temp_path,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
        except BaseException:
            shutil.rmtree(temp_path, ignore_errors=True)
            raise

        return SandboxResult(
            return_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            temp_path=temp_path,
        )

    @staticmethod
    def _apply_patches(temp_path: Path, patches: Mapping[str, str]) -> None:
        for relative_name, contents in patches.items():
            relative_path = Path(relative_name)
            if relative_path.is_absolute() or ".." in relative_path.parts:
                raise ValueError(f"Patch path must stay inside the source: {relative_name}")
            target = temp_path / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(contents, encoding="utf-8")
