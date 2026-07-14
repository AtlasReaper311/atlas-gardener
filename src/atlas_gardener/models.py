"""Small immutable models used by the proposal engine."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RepositoryClassification:
    """Independent repository lifecycle, scope, and provenance axes."""

    lifecycle: str
    scope: str
    provenance: str


@dataclass(frozen=True)
class Refusal:
    """A deterministic, machine-readable explanation for no proposal."""

    finding_fingerprint: str
    repository: str
    reason: str
    fixer_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "finding_fingerprint": self.finding_fingerprint,
            "repository": self.repository,
            "reason": self.reason,
        }
        if self.fixer_id is not None:
            result["fixer_id"] = self.fixer_id
        return result


@dataclass(frozen=True)
class LoadedFinding:
    """A validated Finding together with its source path."""

    path: Path
    value: dict[str, Any]
