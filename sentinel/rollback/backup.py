"""Pre-apply file snapshots and restoration for Sentinel rollbacks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


def _safe_relative_path(relative_name: str) -> Path:
    relative_path = Path(relative_name)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError(f"Patch path must stay inside the source: {relative_name}")
    return relative_path


@dataclass(frozen=True)
class RollbackResult:
    """The result of restoring a pre-apply snapshot."""

    restored: bool
    reason: str
    restored_files: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def success(self) -> bool:
        """Alias useful to callers that model rollback as an operation result."""
        return self.restored


class Backup:
    """Snapshot the files a patch will touch and restore them later.

    A missing file is recorded explicitly so a patch that creates a file can be
    rolled back by removing that file. File contents are kept as bytes so the
    snapshot does not change line endings or encoding details.
    """

    def __init__(
        self,
        source_dir: str | Path,
        contents: Mapping[str, bytes | None],
        existing_parents: set[Path] | None = None,
    ):
        self.source_dir = Path(source_dir)
        self._contents = dict(contents)
        self._existing_parents = existing_parents or set()

    @classmethod
    def capture(
        cls, source_dir: str | Path, patches: Mapping[str, str]
    ) -> "Backup":
        source = Path(source_dir)
        contents: dict[str, bytes | None] = {}
        existing_parents: set[Path] = set()
        for relative_name in patches:
            relative_path = _safe_relative_path(relative_name)
            target = source / relative_path
            parent = target.parent
            while parent != source and source in parent.parents:
                if parent.exists():
                    existing_parents.add(parent)
                parent = parent.parent
            if target.exists():
                if not target.is_file():
                    raise ValueError(f"Cannot back up non-file patch target: {relative_name}")
                contents[relative_name] = target.read_bytes()
            else:
                contents[relative_name] = None
        return cls(source, contents, existing_parents)

    # ``create`` is a readable compatibility alias for callers that treat a
    # backup as a factory rather than a snapshot operation.
    create = capture

    def restore(self, reason: str = "rollback requested") -> RollbackResult:
        restored_files: list[str] = []
        errors: list[str] = []

        for relative_name, original in self._contents.items():
            try:
                target = self.source_dir / _safe_relative_path(relative_name)
                if original is None:
                    if target.is_file() or target.is_symlink():
                        target.unlink()
                        self._remove_new_empty_parents(target.parent)
                    elif target.exists():
                        raise IsADirectoryError(str(target))
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(original)
                restored_files.append(relative_name)
            except (OSError, ValueError) as exc:
                errors.append(f"{relative_name}: {exc}")

        final_reason = reason
        if errors:
            final_reason = f"{reason}; restore errors: {'; '.join(errors)}"
        return RollbackResult(
            restored=not errors,
            reason=final_reason,
            restored_files=tuple(restored_files),
            errors=tuple(errors),
        )

    def _remove_new_empty_parents(self, parent: Path) -> None:
        while parent != self.source_dir and self.source_dir in parent.parents:
            if parent in self._existing_parents:
                break
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent


FileBackup = Backup
RollbackManager = Backup
