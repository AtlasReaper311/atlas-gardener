"""Allowlisted deterministic Atlas Gardener fixer routing."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from atlas_gardener import _fixers_core as _core
from atlas_gardener._fixers_core import *
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.graph_fixers_minimal import npm_graph_plan
from atlas_gardener.security_fixers import (
    container_digest_plan,
    npm_security_plan,
    python_security_plan,
)

FIXER_VERSION = _core.FIXER_VERSION
RULE_FIXERS = dict(_core.RULE_FIXERS)
RULE_FIXERS["container-digest"] = "container-digest-pin"


def _structured_input(
    *,
    finding: dict[str, Any] | None,
    remediation_input: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if remediation_input is not None:
        return remediation_input
    if finding is None:
        return None
    remediation = finding.get("remediation")
    if not isinstance(remediation, dict):
        return None
    candidate = remediation.get("candidate")
    return candidate if isinstance(candidate, dict) else None


def fixer_for_finding(finding: dict[str, Any]) -> str:
    """Route one validated Finding to a closed deterministic fixer."""

    rule_id = finding.get("rule_id")
    candidate = _structured_input(finding=finding, remediation_input=None)
    if rule_id == "dependency-vulnerability":
        if not isinstance(candidate, dict):
            raise SafetyRefusal(
                "dependency-vulnerability requires structured remediation input"
            )
        kind = candidate.get("kind")
        if kind == "npm-lock-security-remediation":
            return "npm-lock-security-remediation"
        if kind != "dependency-update":
            raise SafetyRefusal(
                "dependency-vulnerability candidate kind has no allowlisted fixer"
            )
        ecosystem = candidate.get("ecosystem")
        if ecosystem == "npm":
            return "npm-security-update"
        if ecosystem == "PyPI":
            return "python-security-pin"
        raise SafetyRefusal("dependency candidate ecosystem has no allowlisted fixer")
    if rule_id == "container-digest":
        if not isinstance(candidate, dict) or candidate.get("kind") != "container-digest-pin":
            raise SafetyRefusal(
                "container-digest requires a structured container-digest-pin candidate"
            )
        return "container-digest-pin"
    return _core.fixer_for_finding(finding)


def build_plan(
    fixer_id: str,
    repository: Path,
    *,
    finding: dict[str, Any] | None = None,
    files: list[str] | None = None,
    pins_file: Path | None = None,
    remediation_input: dict[str, Any] | None = None,
):
    """Build one bounded plan and regenerate candidate-driven plans exactly."""

    candidate = _structured_input(
        finding=finding,
        remediation_input=remediation_input,
    )
    if fixer_id == "npm-lock-security-remediation":
        plan = npm_graph_plan(repository, candidate)
    elif fixer_id == "npm-security-update":
        plan = npm_security_plan(repository, candidate)
    elif fixer_id == "python-security-pin":
        plan = python_security_plan(repository, candidate)
    elif fixer_id == "container-digest-pin":
        plan = container_digest_plan(repository, candidate)
    else:
        return _core.build_plan(
            fixer_id,
            repository,
            finding=finding,
            files=files,
            pins_file=pins_file,
        )
    if files is not None and plan.files_affected != sorted(files):
        raise SafetyRefusal("candidate fixer regenerated a different reviewed file set")
    return plan
