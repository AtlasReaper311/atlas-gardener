"""Run-scoped Atlas Gardener write-target validation."""
from __future__ import annotations

import json
import os
from typing import Any, Mapping

from atlas_gardener.errors import SafetyRefusal

WRITE_MODES = {"pr-only", "automerge-low-risk"}


def _covered_repositories(coverage: dict[str, Any]) -> set[str]:
    repositories = {coverage["canary"]["repository"]}
    for batch in coverage["batches"]:
        repositories.update(batch["repositories"])
    return repositories


def resolve_write_targets(
    policy: dict[str, Any],
    coverage: dict[str, Any],
    mode: str,
    environment: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Return the exact approved write targets or fail closed for a write mode."""
    if mode not in WRITE_MODES:
        return ()

    variable = policy.get("write_targets_variable")
    if variable != "ATLAS_GARDENER_WRITE_TARGETS_JSON":
        raise SafetyRefusal("Atlas Gardener write-target authority is missing or invalid")

    values = environment if environment is not None else os.environ
    raw = values.get(variable, "").strip()
    if not raw:
        raise SafetyRefusal("Atlas Gardener write mode requires explicit write targets")

    try:
        targets = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SafetyRefusal("Atlas Gardener write targets must be valid JSON") from error

    if not isinstance(targets, list) or not all(isinstance(item, str) for item in targets):
        raise SafetyRefusal("Atlas Gardener write targets must be a JSON string array")
    if not targets:
        raise SafetyRefusal("Atlas Gardener write targets cannot be empty in write mode")
    if targets != sorted(targets):
        raise SafetyRefusal("Atlas Gardener write targets must be sorted")
    if len(targets) != len(set(targets)):
        raise SafetyRefusal("Atlas Gardener write targets must be unique")

    covered = _covered_repositories(coverage)
    uncovered = [repository for repository in targets if repository not in covered]
    if uncovered:
        raise SafetyRefusal(
            "Atlas Gardener write targets are outside verified public coverage: "
            + ", ".join(uncovered)
        )

    return tuple(targets)
