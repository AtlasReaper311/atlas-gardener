"""Scheduled automatic-remediation controller with fail-closed evidence."""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from atlas_gardener.automatic_github import find_existing, prepare_commit, publish_prepared
from atlas_gardener.automation import (
    automatic_merge_eligible,
    build_approval,
    controller_run_identity,
    coverage_classifications,
    new_evidence,
    object_digest,
    read_object,
    remediation_key,
    resolve_mode,
    validate_bundle,
    validate_policy,
)
from atlas_gardener.contracts import ContractSet, write_json
from atlas_gardener.engine import propose
from atlas_gardener.errors import ContractError, GardenerError, SafetyRefusal
from atlas_gardener.fixers import fixer_for_finding
from atlas_gardener.github_app_auth import mint_repository_token, private_key_from_environment
from atlas_gardener.github_app_pr import _plan_digest, build_pr_plan, validate_pr_plan
from atlas_gardener.notifications import build_notification, send_notification


def _git(command: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        ["git", *command],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "git failed"
        raise SafetyRefusal(detail[:500])
    return completed.stdout.strip()


def _checkout_target(snapshot: dict[str, Any], root: Path) -> Path:
    repository = snapshot["repository"]
    name = repository.rsplit("/", 1)[-1]
    target = root / name
    if target.exists():
        shutil.rmtree(target)
    _git(
        [
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            f"https://github.com/{repository}.git",
            str(target),
        ]
    )
    _git(
        ["checkout", "-B", snapshot["base_branch"], snapshot["base_sha"]],
        cwd=target,
    )
    if _git(["rev-parse", "HEAD"], cwd=target) != snapshot["base_sha"]:
        raise SafetyRefusal("target checkout does not match the Finding bundle base commit")
    if _git(["branch", "--show-current"], cwd=target) != snapshot["base_branch"]:
        raise SafetyRefusal("target checkout does not use the reviewed base branch")
    if _git(["status", "--porcelain=v1"], cwd=target):
        raise SafetyRefusal("target checkout is dirty before proposal generation")
    return target


def _source_run(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository": bundle["producer"],
        "workflow": bundle["source_workflow"],
        "run_id": bundle["source_run_id"],
        "run_attempt": bundle["source_run_attempt"],
        "commit": bundle["source_commit"],
    }


def _branch_for(key: str, fixer_id: str) -> str:
    digest = key.removeprefix("sha256:")
    return f"gardener/{fixer_id}-{digest[:12]}"


def _with_deterministic_branch(plan: dict[str, Any], key: str) -> dict[str, Any]:
    value = copy.deepcopy(plan)
    value["branch"] = _branch_for(key, value["fixer"]["id"])
    value["plan_digest"] = _plan_digest(value)
    return validate_pr_plan(value)


def _eligibility_plan(plan: dict[str, Any], change_plan: Any) -> dict[str, Any]:
    value = copy.deepcopy(plan)
    before_by_path = {
        change.path: (
            change.before.decode("utf-8")
            if change.before is not None and b"\x00" not in change.before
            else None
        )
        for change in change_plan.changes
    }
    for item in value["files"]:
        item["before_text"] = before_by_path.get(item["path"])
    return value


def _notification_for(evidence: dict[str, Any], run_url: str) -> dict[str, Any]:
    if evidence["mode"] == "disabled":
        return build_notification(
            event="kill_switch_active",
            level="info",
            title="Atlas Gardener controller disabled",
            message="The controller validated source authority and performed no target writes.",
            run_url=run_url,
            fields={"mode": "disabled"},
        )
    if evidence["refusals"]:
        return build_notification(
            event="remediation_refused",
            level="warning",
            title="Atlas Gardener remediation refused",
            message=(
                f"{len(evidence['refusals'])} Finding(s) failed closed; "
                f"{len(evidence['pull_requests'])} pull request outcome(s) were recorded."
            ),
            run_url=run_url,
            fields={
                "mode": evidence["mode"],
                "refusals": str(len(evidence["refusals"])),
            },
        )
    if any(item.get("state") == "merged" for item in evidence["pull_requests"]):
        return build_notification(
            event="pr_merged",
            level="success",
            title="Atlas Gardener remediation merged",
            message="A previously approved low-risk Gardener remediation is now merged.",
            run_url=run_url,
            fields={"mode": evidence["mode"]},
        )
    if evidence["pull_requests"]:
        return build_notification(
            event="pr_opened",
            level="info",
            title="Atlas Gardener pull request outcome",
            message=(
                f"Recorded {len(evidence['pull_requests'])} deterministic "
                "Gardener pull request outcome(s)."
            ),
            run_url=run_url,
            fields={"mode": evidence["mode"]},
        )
    return build_notification(
        event="finding_received",
        level="info",
        title="Atlas Gardener Finding bundle processed",
        message=(
            f"Processed {len(evidence['finding_fingerprints'])} Finding(s) "
            "without a target write."
        ),
        run_url=run_url,
        fields={"mode": evidence["mode"]},
    )


def _sort_evidence(evidence: dict[str, Any]) -> None:
    for key in (
        "finding_fingerprints",
        "proposals",
        "plans",
        "repositories_skipped",
        "refusals",
        "pull_requests",
        "ci",
        "merge_outcomes",
        "tokens",
        "notifications",
    ):
        evidence[key] = sorted(
            evidence[key],
            key=lambda item: (
                json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
            ),
        )


def _write_evidence(output_path: Path, evidence: dict[str, Any]) -> dict[str, Any]:
    material = dict(evidence)
    material.pop("evidence_digest", None)
    evidence["evidence_digest"] = object_digest(material)
    write_json(output_path, evidence)
    return evidence


def run_controller(
    *,
    infra_root: Path,
    bundle_path: Path | None,
    output_path: Path,
    work_root: Path,
    attestation_verified: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    infra_root = infra_root.resolve(strict=True)
    policy = validate_policy(
        read_object(
            infra_root / "policy/gardener-automation.json",
            label="automation policy",
        ),
        read_object(
            infra_root / "policy/gardener-github-app-coverage.json",
            label="coverage policy",
        ),
    )
    coverage = read_object(
        infra_root / "policy/gardener-github-app-coverage.json",
        label="coverage policy",
    )
    registry = read_object(
        infra_root / "policy/estate-registry.json",
        label="estate registry",
    )
    mode, write_gate = resolve_mode(policy)
    evidence = new_evidence(mode=mode, policy=policy, coverage=coverage, bundle=None)
    evidence["write_gate_enabled"] = write_gate
    evidence["attestation_verified"] = attestation_verified
    evidence["authority_commit"] = _git(["rev-parse", "HEAD"], cwd=infra_root)

    if mode == "disabled":
        _sort_evidence(evidence)
        return _write_evidence(output_path, evidence)
    if bundle_path is None:
        raise SafetyRefusal("non-disabled controller mode requires a Finding bundle")
    if policy["finding_bundle"]["require_attestation"] and not attestation_verified:
        raise SafetyRefusal("Finding bundle attestation was not verified")

    contracts = ContractSet(infra_root / "contracts/v1")
    bundle = validate_bundle(
        read_object(bundle_path.resolve(strict=True), label="Finding bundle"),
        policy=policy,
        contracts=contracts,
        now=now,
    )
    evidence["bundle_digest"] = bundle["bundle_digest"]
    if bundle["authority_commit"] != evidence["authority_commit"]:
        raise SafetyRefusal(
            "Finding bundle was produced against a different Atlas Infra commit"
        )
    classifications = coverage_classifications(coverage, registry)
    snapshots = {
        item["repository"]: item for item in bundle["repository_snapshots"]
    }
    source_run = _source_run(bundle)
    controller_run = controller_run_identity()
    work_root.mkdir(parents=True, exist_ok=True)
    os.environ["ATLAS_GARDENER_INFRA_ROOT"] = str(infra_root)

    for finding in bundle["findings"]:
        fingerprint = finding["fingerprint"]
        repository = finding["subject"]["repository"]
        evidence["finding_fingerprints"].append(fingerprint)
        fixer_id: str | None = None
        token_record: dict[str, Any] | None = None
        try:
            if repository not in classifications:
                raise SafetyRefusal(
                    "repository is outside verified public Gardener coverage"
                )
            classification = classifications[repository]
            repository_policy = policy["repository_eligibility"]
            if classification["lifecycle"] not in repository_policy["lifecycles"]:
                raise SafetyRefusal(
                    "repository lifecycle is not eligible: "
                    + classification["lifecycle"]
                )
            if classification["scope"] not in repository_policy["scopes"]:
                raise SafetyRefusal(
                    "repository scope is not eligible: " + classification["scope"]
                )
            if classification["provenance"] not in repository_policy["provenance"]:
                raise SafetyRefusal(
                    "repository provenance is not eligible: "
                    + classification["provenance"]
                )
            snapshot = snapshots.get(repository)
            if snapshot is None:
                raise SafetyRefusal(
                    "Finding bundle has no exact repository base snapshot"
                )
            fixer_id = fixer_for_finding(finding)
            target = _checkout_target(snapshot, work_root)
            proposal, change_plan, proposal_evidence = propose(
                finding,
                target,
                contracts,
            )
            proposal_path = (
                work_root
                / f"{fingerprint.removeprefix('sha256:')}.proposal.json"
            )
            write_json(proposal_path, proposal)
            plan = build_pr_plan(
                proposal_path=proposal_path,
                repository=target,
                contracts=contracts,
                base_branch=snapshot["base_branch"],
            )
            key = remediation_key(
                repository=repository,
                rule_id=finding["rule_id"],
                finding_fingerprint=fingerprint,
                fixer_id=plan["fixer"]["id"],
                fixer_version=plan["fixer"]["version"],
                base_sha=plan["base_sha"],
            )
            plan = _with_deterministic_branch(plan, key)
            eligible, eligibility_reason = automatic_merge_eligible(
                _eligibility_plan(plan, change_plan),
                policy,
            )
            evidence["proposals"].append(
                {
                    "proposal_id": proposal["proposal_id"],
                    "finding_fingerprint": fingerprint,
                    "repository": repository,
                    "fixer_id": fixer_id,
                    "evidence": proposal_evidence,
                }
            )
            evidence["plans"].append(
                {
                    "plan_digest": plan["plan_digest"],
                    "remediation_key": key,
                    "repository": repository,
                    "base_sha": plan["base_sha"],
                    "patch_digest": plan["patch_digest"],
                    "automatic_merge_eligible": eligible,
                    "eligibility_reason": eligibility_reason,
                }
            )
            if mode == "observe":
                continue

            app_id = os.environ.get("ATLAS_GARDENER_APP_ID", "").strip()
            if not app_id:
                raise SafetyRefusal("ATLAS_GARDENER_APP_ID is not configured")
            with tempfile.TemporaryDirectory(
                prefix="atlas-gardener-key-"
            ) as key_directory:
                key_path = private_key_from_environment(Path(key_directory))
                token = mint_repository_token(
                    app_id=app_id,
                    private_key_path=key_path,
                    repository=repository,
                )
                token_record = {
                    "repository": repository,
                    "minted": True,
                    "revoked": False,
                }
                try:
                    existing = find_existing(
                        plan=plan,
                        remediation_key=key,
                        token=token.value,
                    )
                    if existing is not None:
                        state = (
                            "merged"
                            if existing.get("merged_at")
                            else existing.get("state", "unknown")
                        )
                        evidence["pull_requests"].append(
                            {
                                "repository": repository,
                                "remediation_key": key,
                                "number": existing.get("number"),
                                "url": existing.get("html_url"),
                                "state": state,
                                "idempotent": True,
                            }
                        )
                        continue
                    prepared = prepare_commit(plan=plan, token=token.value)
                    approval = build_approval(
                        policy=policy,
                        coverage=coverage,
                        bundle=bundle,
                        finding=finding,
                        proposal=proposal,
                        plan=plan,
                        expected_head_sha=prepared["commit_sha"],
                        mode=mode,
                        source_run=source_run,
                        controller_run=controller_run,
                        now=now,
                    )
                    ready = mode == "automerge-low-risk" and eligible
                    result = publish_prepared(
                        plan=plan,
                        prepared=prepared,
                        approval=approval,
                        token=token.value,
                        ready=ready,
                    )
                    evidence["pull_requests"].append(
                        {
                            "repository": repository,
                            "remediation_key": key,
                            "approval_id": approval["approval_id"],
                            "number": result["pull_request"]["number"],
                            "url": result["pull_request"]["url"],
                            "state": "open",
                            "draft": result["pull_request"]["draft"],
                            "target_gate_requested": result[
                                "target_gate_requested"
                            ],
                            "idempotent": False,
                        }
                    )
                finally:
                    try:
                        token.revoke()
                    except GardenerError as error:
                        token_record["revoke_error"] = str(error)
                        raise
                    finally:
                        token_record["revoked"] = token.revoked
        except (
            ContractError,
            GardenerError,
            OSError,
            UnicodeError,
            ValueError,
        ) as error:
            evidence["refusals"].append(
                {
                    "finding_fingerprint": fingerprint,
                    "repository": repository,
                    "fixer_id": fixer_id,
                    "reason": str(error),
                }
            )
        finally:
            if token_record is not None:
                evidence["tokens"].append(token_record)

    _sort_evidence(evidence)
    run_url = (
        os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        + "/"
        + os.environ.get("GITHUB_REPOSITORY", "AtlasReaper311/atlas-gardener")
        + "/actions/runs/"
        + os.environ.get("GITHUB_RUN_ID", "local")
    )
    try:
        notification = send_notification(_notification_for(evidence, run_url))
    except GardenerError as error:
        notification = {"status": "failed", "reason": str(error)}
    evidence["notifications"].append(notification)
    _sort_evidence(evidence)
    return _write_evidence(output_path, evidence)
