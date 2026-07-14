"""Deterministic, bounded local change planning and application."""

from __future__ import annotations

import hashlib
from difflib import SequenceMatcher
from dataclasses import dataclass
from pathlib import Path

from atlas_gardener.contracts import sha256_value
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.safety import (
    MAX_CHANGED_FILES,
    MAX_CHANGED_LINES,
    safe_relative_path,
)


@dataclass(frozen=True)
class FileChange:
    """One fully specified local file edit or deletion."""

    path: str
    before: bytes | None
    after: bytes | None
    allow_binary_delete: bool = False

    @property
    def action(self) -> str:
        if self.before is None:
            return "create"
        if self.after is None:
            return "delete"
        return "replace"

    def digest_record(self) -> dict[str, str | None]:
        return {
            "action": self.action,
            "after_sha256": _bytes_digest(self.after),
            "before_sha256": _bytes_digest(self.before),
            "path": self.path,
        }


def _bytes_digest(value: bytes | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class ChangePlan:
    """A sorted, one-fixer plan that can be regenerated before apply."""

    fixer_id: str
    changes: tuple[FileChange, ...]

    @classmethod
    def create(cls, fixer_id: str, changes: list[FileChange]) -> "ChangePlan":
        ordered = tuple(sorted(changes, key=lambda change: change.path))
        if not ordered:
            raise SafetyRefusal("the fixer found no deterministic change to propose")
        paths = [change.path for change in ordered]
        if len(paths) != len(set(paths)):
            raise SafetyRefusal("a proposal may affect each file at most once")
        if len(ordered) > MAX_CHANGED_FILES:
            raise SafetyRefusal(
                f"proposal changes {len(ordered)} files; maximum is {MAX_CHANGED_FILES}"
            )
        changed_lines = sum(_changed_line_count(change) for change in ordered)
        if changed_lines > MAX_CHANGED_LINES:
            raise SafetyRefusal(
                f"proposal changes {changed_lines} lines; maximum is {MAX_CHANGED_LINES}"
            )
        return cls(fixer_id=fixer_id, changes=ordered)

    @property
    def files_affected(self) -> list[str]:
        return [change.path for change in self.changes]

    @property
    def patch_digest(self) -> str:
        return sha256_value([change.digest_record() for change in self.changes])

    @property
    def changed_lines(self) -> int:
        return sum(_changed_line_count(change) for change in self.changes)

    def apply(self, repository: Path) -> None:
        """Apply only after all paths and preimages have been revalidated."""

        resolved: list[tuple[FileChange, Path]] = []
        for change in self.changes:
            path = safe_relative_path(repository, change.path, allow_missing=True)
            current = path.read_bytes() if path.exists() else None
            if current != change.before:
                raise SafetyRefusal(
                    f"target changed since proposal generation: {change.path}"
                )
            if (
                current is not None
                and b"\x00" in current
                and not change.allow_binary_delete
            ):
                raise SafetyRefusal(f"binary file refused during apply: {change.path}")
            resolved.append((change, path))

        for change, path in resolved:
            if change.after is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(change.after)


def _changed_line_count(change: FileChange) -> int:
    if change.allow_binary_delete and change.after is None:
        return 1
    before = _text_lines(change.before)
    after = _text_lines(change.after)
    changed = 0
    for tag, before_start, before_end, after_start, after_end in SequenceMatcher(
        None, before, after, autojunk=False
    ).get_opcodes():
        if tag != "equal":
            changed += (before_end - before_start) + (after_end - after_start)
    return changed


def _text_lines(value: bytes | None) -> list[str]:
    if value is None:
        return []
    if b"\x00" in value:
        raise SafetyRefusal("binary content cannot be line-counted")
    try:
        return value.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise SafetyRefusal("non-UTF-8 content cannot be changed") from error
