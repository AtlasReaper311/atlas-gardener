"""Fail-closed automation policy extended for accepted ADR-0015 authority."""
from __future__ import annotations

import copy
import re
from typing import Any

from atlas_gardener import _automation_core as _core
from atlas_gardener._automation_core import *  # noqa: F401,F403
from atlas_gardener.errors import ContractError, SafetyRefusal

_NEW_FIXERS = {
    "npm-security-update": [
        r"^(?:[A-Za-z0-9._-]+/)*package-lock\.json$",
        r"^(?:[A-Za-z0-9._-]+/)*package\.json$",
    ],
    "python-security-pin": [
        r"^(?:[A-Za-z0-9._-]+/)*requirements\.txt$",
    ],
    "container-digest-pin": [
        r"^(?:[A-Za-z0-9._-]+/)*Dockerfile[A-Za-z0-9._-]*$",
    ],
}
_ALL_FIXERS = set(_core.AUTO_FIXERS) | {
    "workflow-timeout",
    "workflow-permissions",
    "action-pin-plan",
} | set(_NEW_FIXERS)


def validate_policy(policy: dict[str, Any], coverage: dict[str, Any]) -> dict[str, Any]:
    """Validate legacy invariants plus the exact accepted ADR-0015 fixer set."""

    fixers = policy.get("fixers")
    if not isinstance(fixers, dict) or set(fixers) != _ALL_FIXERS:
        raise ContractError("automation fixer policy is incomplete")

    legacy = copy.deepcopy(policy)
    for fixer_id in _NEW_FIXERS:
        legacy["fixers"].pop(fixer_id, None)
    _core.validate_policy(legacy, copy.deepcopy(coverage))

    for fixer_id, patterns in _NEW_FIXERS.items():
        fixer = fixers.get(fixer_id)
        if not isinstance(fixer, dict):
            raise ContractError(f"automation fixer policy is malformed: {fixer_id}")
        if fixer.get("risk_class") != "review-required":
            raise ContractError(f"dependency/container fixer must remain review-required: {fixer_id}")
        if fixer.get("minimum_mode") != "pr-only":
            raise ContractError(f"dependency/container fixer must require pr-only mode: {fixer_id}")
        if fixer.get("automatic_merge") is not False:
            raise ContractError(f"dependency/container fixer cannot automatically merge: {fixer_id}")
        if fixer.get("allowed_path_patterns") != patterns:
            raise ContractError(f"dependency/container fixer path authority changed: {fixer_id}")
        if fixer.get("automatic_merge_paths") != [] or fixer.get("automatic_merge_added_lines") != []:
            raise ContractError(f"dependency/container fixer gained automatic-merge material: {fixer_id}")
    return policy


def validate_fixer_plan_paths(plan: dict[str, Any], policy: dict[str, Any]) -> None:
    """Require every planned file to match the selected fixer's own authority."""

    fixer = plan.get("fixer")
    fixer_id = fixer.get("id") if isinstance(fixer, dict) else None
    fixer_policy = policy.get("fixers", {}).get(fixer_id)
    if not isinstance(fixer_policy, dict):
        raise SafetyRefusal("plan fixer is absent from the automation policy")
    patterns = fixer_policy.get("allowed_path_patterns")
    if not isinstance(patterns, list) or not patterns:
        raise SafetyRefusal("plan fixer has no allowed path-pattern authority")
    try:
        compiled = [re.compile(pattern) for pattern in patterns]
    except (TypeError, re.error) as error:
        raise SafetyRefusal("plan fixer path-pattern authority is malformed") from error
    files = plan.get("files")
    if not isinstance(files, list) or not files:
        raise SafetyRefusal("plan has no bounded file set")
    for item in files:
        path = item.get("path") if isinstance(item, dict) else None
        if not isinstance(path, str) or not any(pattern.fullmatch(path) for pattern in compiled):
            raise SafetyRefusal(
                f"planned path is outside selected fixer authority: {path!r}"
            )


def automatic_merge_eligible(plan: dict[str, Any], policy: dict[str, Any]):
    validate_fixer_plan_paths(plan, policy)
    return _core.automatic_merge_eligible(plan, policy)
