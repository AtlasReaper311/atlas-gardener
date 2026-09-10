"""GitHub App PR adapter with candidate-aware deterministic regeneration."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atlas_gardener import _github_app_pr_core as _core
from atlas_gardener._github_app_pr_core import *
from atlas_gardener.contracts import ContractSet, read_json
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.fixers import build_plan
from atlas_gardener.safety import (
    classification_for,
    ensure_clean_worktree,
    ensure_remediation_allowed,
)

# Existing tests and automatic GitHub code intentionally consume these bounded
# private helpers. Preserve their stable names across the module split.
def _allowed_api_operation(method: str, path: str, allow_not_found: bool) -> bool:
    return _core._allowed_api_operation(method, path, allow_not_found)


def _plan_digest(plan: dict[str, Any]) -> str:
    return _core._plan_digest(plan)


def _pr_body(plan: dict[str, Any]) -> str:
    return _core._pr_body(plan)


def _regenerate_reviewed_plan(
    *,
    proposal_path: Path,
    repository: Path,
    contracts: ContractSet,
    pins_file: Path | None,
):
    proposal = contracts.validate_proposal(read_json(proposal_path))
    repository = repository.resolve(strict=True)
    classification = classification_for(repository.name, repository)
    ensure_remediation_allowed(repository.name, classification)
    ensure_clean_worktree(repository, fixer_id=proposal["fixer"]["id"])

    expires = datetime.fromisoformat(proposal["expires_at"].replace("Z", "+00:00"))
    if expires < datetime.now(timezone.utc):
        raise SafetyRefusal("proposal has expired and must be regenerated")

    change_plan = build_plan(
        proposal["fixer"]["id"],
        repository,
        files=proposal["files_affected"],
        pins_file=pins_file,
        remediation_input=proposal.get("remediation_input"),
    )
    if change_plan.files_affected != proposal["files_affected"]:
        raise SafetyRefusal("regenerated files differ from the reviewed proposal")
    if change_plan.patch_digest != proposal["patch_digest"]:
        raise SafetyRefusal("regenerated patch digest differs from the reviewed proposal")
    return proposal, change_plan, classification


_core._regenerate_reviewed_plan = _regenerate_reviewed_plan
build_pr_plan = _core.build_pr_plan
