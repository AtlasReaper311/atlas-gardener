"""Contract-aware ingestion, proposal generation, scan reporting, and local apply."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from atlas_gardener.changes import ChangePlan
from atlas_gardener.contracts import ContractSet, load_findings, read_json
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.fixers import FIXER_VERSION, build_plan, fixer_for_finding
from atlas_gardener.models import Refusal, RepositoryClassification
from atlas_gardener.safety import (
    classification_for,
    ensure_apply_target,
    ensure_clean_worktree,
    ensure_remediation_allowed,
)


def propose(
    finding: dict[str, Any],
    repository: Path,
    contracts: ContractSet,
    *,
    pins_file: Path | None = None,
    classification_override: RepositoryClassification | None = None,
) -> tuple[dict[str, Any], ChangePlan, dict[str, Any]]:
    """Create one schema-valid proposal and its separate redacted evidence summary."""

    finding = contracts.validate_finding(finding)
    repository = repository.resolve(strict=True)
    if not repository.is_dir():
        raise SafetyRefusal(f"target repository is not a directory: {repository}")
    repository_name = finding["subject"]["repository"].split("/", 1)[1]
    if repository.name != repository_name:
        raise SafetyRefusal(
            f"Finding targets {repository_name!r}, but --repo names {repository.name!r}"
        )
    if not finding["remediation"]["eligible"]:
        raise SafetyRefusal(
            "Finding is not remediation eligible: " + finding["remediation"]["reason"]
        )

    classification = classification_for(
        repository_name,
        repository,
        override=classification_override,
    )
    ensure_remediation_allowed(repository_name, classification)
    fixer_id = fixer_for_finding(finding)
    ensure_clean_worktree(repository, fixer_id=fixer_id)
    plan = build_plan(fixer_id, repository, finding=finding, pins_file=pins_file)
    proposal = _build_proposal(finding, plan, contracts)
    evidence = {
        "schema_version": "atlas-gardener/proposal-evidence/v1",
        "proposal_id": proposal["proposal_id"],
        "finding_fingerprint": finding["fingerprint"],
        "evidence_summary": finding["evidence"]["summary"],
        "evidence_references": finding["evidence"]["references"],
        "redacted": finding["evidence"]["redacted"],
    }
    return proposal, plan, evidence


def _build_proposal(
    finding: dict[str, Any],
    plan: ChangePlan,
    contracts: ContractSet,
) -> dict[str, Any]:
    detected = datetime.fromisoformat(finding["detected_at"].replace("Z", "+00:00"))
    expires = (detected + timedelta(days=7)).astimezone(timezone.utc)
    proposal: dict[str, Any] = {
        "schema_version": "atlas-control-plane/remediation-proposal/v1",
        "proposal_id": "proposal:sha256:" + "0" * 64,
        "finding_fingerprint": finding["fingerprint"],
        "fixer": {"id": plan.fixer_id, "version": FIXER_VERSION},
        "files_affected": plan.files_affected,
        "risk_class": "low",
        "patch_digest": plan.patch_digest,
        "validation_plan": [
            {
                "check_id": "diff-check",
                "command": "git diff --check",
                "expected": "No whitespace errors are reported.",
            },
            {
                "check_id": "status-review",
                "command": "git status --short",
                "expected": "Only the reviewed proposal files are changed.",
            },
        ],
        "rollback_plan": [
            "Restore the affected files from the reviewed branch or delete the unmerged branch; main remains unchanged."
        ],
        "expires_at": expires.isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    proposal["proposal_id"] = contracts.proposal_id(proposal)
    return contracts.validate_proposal(proposal)


def scan(
    findings_path: Path,
    estate_root: Path,
    contracts: ContractSet,
    *,
    pins_file: Path | None = None,
) -> dict[str, Any]:
    """Produce a deterministic dry-run report for validated, deduplicated Findings."""

    loaded = load_findings(findings_path, contracts)
    proposals: list[dict[str, Any]] = []
    refusals: list[Refusal] = []
    evidence_summaries: list[dict[str, Any]] = []

    for item in loaded:
        finding = item.value
        repository_name = finding["subject"]["repository"].split("/", 1)[1]
        repository = estate_root / repository_name
        fixer_id: str | None = None
        try:
            if not repository.is_dir():
                raise SafetyRefusal(
                    f"target repository directory does not exist: {repository}"
                )
            fixer_id = fixer_for_finding(finding)
            proposal, _, evidence = propose(
                finding,
                repository,
                contracts,
                pins_file=pins_file,
            )
            proposals.append(proposal)
            evidence_summaries.append(evidence)
        except SafetyRefusal as error:
            refusals.append(
                Refusal(
                    finding["fingerprint"],
                    finding["subject"]["repository"],
                    str(error),
                    fixer_id,
                )
            )

    proposals.sort(key=lambda value: value["proposal_id"])
    evidence_summaries.sort(key=lambda value: value["proposal_id"])
    refusal_values = sorted(
        (refusal.as_dict() for refusal in refusals),
        key=lambda value: (
            value["finding_fingerprint"],
            value["repository"],
            value.get("fixer_id", ""),
            value["reason"],
        ),
    )
    return {
        "schema_version": "atlas-gardener/scan-report/v1",
        "dry_run": True,
        "findings_loaded": len(loaded),
        "proposals": proposals,
        "refusals": refusal_values,
        "evidence_summaries": evidence_summaries,
    }


def apply_proposal(
    proposal_path: Path,
    repository: Path,
    contracts: ContractSet,
    *,
    apply: bool = False,
    allow_local_target: bool = False,
    pins_file: Path | None = None,
) -> dict[str, Any]:
    """Regenerate and optionally apply a proposal after all safety checks pass."""

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
    )
    if plan.files_affected != proposal["files_affected"]:
        raise SafetyRefusal("regenerated files differ from the reviewed proposal")
    if plan.patch_digest != proposal["patch_digest"]:
        raise SafetyRefusal(
            "regenerated patch digest differs from the reviewed proposal"
        )
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
