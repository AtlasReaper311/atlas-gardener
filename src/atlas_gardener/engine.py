"""Contract-aware proposal generation with ADR-0015 remediation input binding."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path

from atlas_gardener import _engine_core as _core
from atlas_gardener._engine_core import *  # noqa: F401,F403
from atlas_gardener.contracts import ContractSet, read_json
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.fixers import build_plan
from atlas_gardener.safety import (
    classification_for,
    ensure_apply_target,
    ensure_clean_worktree,
    ensure_remediation_allowed,
)

_NEW_FIXERS = {"npm-security-update", "python-security-pin", "container-digest-pin"}
_CORE_PROPOSE = _core.propose


def propose(
    finding: dict,
    repository: Path,
    contracts: ContractSet,
    *,
    pins_file: Path | None = None,
    classification_override=None,
):
    proposal, plan, evidence = _CORE_PROPOSE(
        finding,
        repository,
        contracts,
        pins_file=pins_file,
        classification_override=classification_override,
    )
    remediation = finding.get("remediation")
    candidate = remediation.get("candidate") if isinstance(remediation, dict) else None
    if candidate is not None:
        proposal = copy.deepcopy(proposal)
        proposal["remediation_input"] = copy.deepcopy(candidate)
        if proposal["fixer"]["id"] in _NEW_FIXERS:
            proposal["risk_class"] = "medium"
        proposal["proposal_id"] = contracts.proposal_id(proposal)
        proposal = contracts.validate_proposal(proposal)
    return proposal, plan, evidence


# scan() lives in the preserved core module and resolves its module-global
# propose symbol at runtime. Bind it to the candidate-aware implementation only
# after retaining the original implementation above.
_core.propose = propose
scan = _core.scan


def apply_proposal(
    proposal_path: Path,
    repository: Path,
    contracts: ContractSet,
    *,
    apply: bool = False,
    allow_local_target: bool = False,
    pins_file: Path | None = None,
) -> dict:
    """Regenerate candidate-driven proposals from their bound structured input."""

    proposal = contracts.validate_proposal(read_json(proposal_path))
    repository = repository.resolve(strict=True)
    if not repository.is_dir():
        raise SafetyRefusal(f"target repository is not a directory: {repository}")
    classification = classification_for(repository.name, repository)
    ensure_remediation_allowed(repository.name, classification)
    expires = datetime.fromisoformat(proposal["expires_at"].replace("Z", "+00:00"))
    if expires < datetime.now(timezone.utc):
        raise SafetyRefusal("proposal has expired and must be regenerated")
    fixer_id = proposal["fixer"]["id"]
    ensure_clean_worktree(repository, fixer_id=fixer_id)
    plan = build_plan(
        fixer_id,
        repository,
        files=proposal["files_affected"],
        pins_file=pins_file,
        remediation_input=proposal.get("remediation_input"),
    )
    if plan.files_affected != proposal["files_affected"]:
        raise SafetyRefusal("regenerated files differ from the reviewed proposal")
    if plan.patch_digest != proposal["patch_digest"]:
        raise SafetyRefusal("regenerated patch digest differs from the reviewed proposal")
    if apply:
        ensure_apply_target(repository, allow_local_target=allow_local_target)
        plan.apply(repository)
    return {
        "schema_version": "atlas-gardener/apply-result/v1",
        "proposal_id": proposal["proposal_id"],
        "mode": "local-apply" if apply else "dry-run",
        "applied": apply,
        "files_affected": plan.files_affected,
        "patch_digest": plan.patch_digest,
    }
