"""Fail-closed automatic-remediation policy, bundle, approval and evidence logic."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from atlas_gardener.contracts import ContractSet, canonical_json, sha256_value
from atlas_gardener.errors import ContractError, SafetyRefusal

POLICY_SCHEMA = "atlas-gardener/automation-policy/v1"
BUNDLE_SCHEMA = "atlas-control-plane/gardener-finding-bundle/v1"
APPROVAL_SCHEMA = "atlas-control-plane/gardener-automation-approval/v1"
EVIDENCE_SCHEMA = "atlas-gardener/controller-evidence/v1"
MODES = ("disabled", "observe", "pr-only", "automerge-low-risk")
WRITE_MODES = {"pr-only", "automerge-low-risk"}
AUTO_FIXERS = {"macos-metadata-ignore", "python-cache-ignore"}
REPOSITORY_RE = re.compile(r"^AtlasReaper311/[A-Za-z0-9._-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
APPROVAL_MARKER_RE = re.compile(r"<!-- atlas-gardener-approval:([A-Za-z0-9_-]+) -->")


def read_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read valid {label}: {error}") from error
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be a JSON object")
    return value


def object_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        raise ContractError(f"{label} is missing fields: {', '.join(missing)}")
    if unknown:
        raise ContractError(f"{label} has unknown fields: {', '.join(unknown)}")


def validate_policy(policy: dict[str, Any], coverage: dict[str, Any]) -> dict[str, Any]:
    if policy.get("schema_version") != POLICY_SCHEMA:
        raise ContractError("unsupported automation policy schema")
    if policy.get("authority") != "AtlasReaper311/atlas-infra":
        raise ContractError("automation policy authority mismatch")
    if policy.get("default_mode") != "disabled":
        raise ContractError("automation policy must default to disabled")
    if policy.get("allowed_modes") != list(MODES):
        raise ContractError("automation policy contains an unknown mode")
    if policy.get("mode_variable") != "ATLAS_GARDENER_MODE":
        raise ContractError("automation mode variable mismatch")
    if policy.get("write_gate_variable") != "ATLAS_GARDENER_WRITE_GATE":
        raise ContractError("automation write-gate variable mismatch")
    if policy.get("write_gate_enabled_value") != "enabled":
        raise ContractError("automation write gate must require the exact value enabled")
    bundle_policy = policy.get("finding_bundle")
    if not isinstance(bundle_policy, dict):
        raise ContractError("finding bundle policy is missing")
    if bundle_policy.get("producer") != "AtlasReaper311/atlas-dep-audit":
        raise ContractError("finding producer mismatch")
    if bundle_policy.get("workflow") != ".github/workflows/audit.yml":
        raise ContractError("finding producer workflow mismatch")
    if bundle_policy.get("public_only") is not True:
        raise ContractError("public controller requires a public-only finding bundle")
    if bundle_policy.get("require_attestation") is not True:
        raise ContractError("finding bundle attestation cannot be disabled")
    repository_policy = policy.get("repository_eligibility")
    if repository_policy != {
        "lifecycles": ["active", "production"],
        "scopes": ["internal", "public"],
        "provenance": ["original"],
        "require_verified_public_coverage": True,
        "private_repository_policy": "source-owned-separate-approval",
    }:
        raise ContractError("repository eligibility is broader than the public v1 boundary")
    fixers = policy.get("fixers")
    if not isinstance(fixers, dict) or set(fixers) != {
        "macos-metadata-ignore",
        "python-cache-ignore",
        "workflow-timeout",
        "workflow-permissions",
        "action-pin-plan",
    }:
        raise ContractError("automation fixer policy is incomplete")
    for fixer_id, fixer in fixers.items():
        if not isinstance(fixer, dict):
            raise ContractError(f"automation fixer policy is malformed: {fixer_id}")
        automatic = fixer.get("automatic_merge") is True
        if fixer_id in AUTO_FIXERS:
            if not automatic or fixer.get("risk_class") != "low":
                raise ContractError(f"automatic fixer lost its low-risk boundary: {fixer_id}")
            if fixer.get("automatic_merge_paths") != [".gitignore"]:
                raise ContractError(f"automatic fixer is not .gitignore-only: {fixer_id}")
        elif automatic or fixer.get("risk_class") != "review-required":
            raise ContractError(f"review-only fixer became automatically mergeable: {fixer_id}")
    limits = policy.get("automatic_merge_limits")
    if not isinstance(limits, dict):
        raise ContractError("automatic merge limits are missing")
    if limits.get("maximum_changed_files") != 1 or not 1 <= limits.get("maximum_changed_lines", 0) <= 2:
        raise ContractError("automatic merge file or line bounds changed")
    if limits.get("allowed_file_modes") != ["100644"]:
        raise ContractError("automatic merge file-mode boundary changed")
    for required in (
        "additions_only",
        "forbid_binary",
        "forbid_symlink",
        "forbid_generated_output",
        "require_exact_base_sha",
        "require_exact_head_sha",
        "require_unchanged_patch_digest",
        "require_required_checks",
    ):
        if limits.get(required) is not True:
            raise ContractError(f"automatic merge no longer requires {required}")
    if limits.get("merge_method") != "squash":
        raise ContractError("automatic merge method must remain squash")
    if coverage.get("schema_version") != "atlas-gardener/github-app-coverage/v1":
        raise ContractError("unsupported public coverage policy")
    if coverage.get("installation_mode") != "selected-repositories":
        raise ContractError("GitHub App installation must remain selected-repository")
    if coverage.get("permissions") != {
        "metadata": "read",
        "contents": "write",
        "pull_requests": "write",
    }:
        raise ContractError("GitHub App permission boundary changed")
    repositories = [coverage.get("canary", {}).get("repository")]
    if coverage.get("canary", {}).get("status") != "verified":
        raise ContractError("Gardener canary is not verified")
    for batch in coverage.get("batches", []):
        if not isinstance(batch, dict) or batch.get("status") != "verified":
            raise ContractError("public coverage contains an unverified batch")
        repositories.extend(batch.get("repositories", []))
    if len(repositories) != 20 or len(set(repositories)) != 20:
        raise ContractError("public coverage must contain 20 unique repositories")
    if policy.get("public_coverage_source_fingerprint") != coverage.get("source_fingerprint"):
        raise ContractError("automation policy is stale against public coverage")
    return policy


def resolve_mode(policy: dict[str, Any], environment: dict[str, str] | None = None) -> tuple[str, bool]:
    values = environment if environment is not None else os.environ
    mode = values.get(policy["mode_variable"], policy["default_mode"]).strip()
    if mode not in MODES:
        raise SafetyRefusal(f"unknown Atlas Gardener mode: {mode!r}")
    write_gate = values.get(policy["write_gate_variable"], "").strip()
    enabled = write_gate == policy["write_gate_enabled_value"]
    if mode in WRITE_MODES and not enabled:
        raise SafetyRefusal("Atlas Gardener write mode requires the independent write gate")
    return mode, enabled


def validate_bundle(
    bundle: dict[str, Any],
    *,
    policy: dict[str, Any],
    contracts: ContractSet,
    now: datetime | None = None,
) -> dict[str, Any]:
    expected = {
        "schema_version",
        "producer",
        "source_workflow",
        "source_run_id",
        "source_run_attempt",
        "source_commit",
        "authority_commit",
        "policy_digest",
        "generated_at",
        "expires_at",
        "public_only",
        "source_report_digest",
        "repository_snapshots",
        "findings",
        "bundle_digest",
    }
    _exact_keys(bundle, expected, "Finding bundle")
    if bundle["schema_version"] != BUNDLE_SCHEMA:
        raise ContractError("unsupported Finding bundle schema")
    bundle_policy = policy["finding_bundle"]
    if bundle["producer"] != bundle_policy["producer"]:
        raise ContractError("Finding bundle producer mismatch")
    if bundle["source_workflow"] != bundle_policy["workflow"]:
        raise ContractError("Finding bundle workflow mismatch")
    if bundle["public_only"] is not True:
        raise ContractError("private Finding data cannot enter the public controller")
    if not SHA_RE.fullmatch(str(bundle["source_commit"])) or not SHA_RE.fullmatch(str(bundle["authority_commit"])):
        raise ContractError("Finding bundle commit identity is invalid")
    if bundle["policy_digest"] != object_digest(policy):
        raise ContractError("Finding bundle policy digest changed")
    current = now or datetime.now(timezone.utc)
    try:
        generated = datetime.fromisoformat(str(bundle["generated_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(bundle["expires_at"]).replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError("Finding bundle timestamp is invalid") from error
    if generated.tzinfo is None or expires.tzinfo is None:
        raise ContractError("Finding bundle timestamps require timezones")
    if generated > current + timedelta(minutes=5):
        raise SafetyRefusal("Finding bundle claims a future generation time")
    if current > expires:
        raise SafetyRefusal("Finding bundle is stale")
    if current - generated > timedelta(hours=int(bundle_policy["maximum_age_hours"])):
        raise SafetyRefusal("Finding bundle exceeds the maximum accepted age")
    findings = bundle["findings"]
    if not isinstance(findings, list) or len(findings) > int(bundle_policy["maximum_findings"]):
        raise ContractError("Finding bundle count exceeds the policy bound")
    validated = [contracts.validate_finding(item) for item in findings]
    fingerprints = [item["fingerprint"] for item in validated]
    if fingerprints != sorted(set(fingerprints)):
        raise ContractError("Finding bundle fingerprints must be unique and sorted")
    snapshots = bundle["repository_snapshots"]
    if not isinstance(snapshots, list):
        raise ContractError("Finding bundle repository snapshots must be an array")
    snapshot_names: list[str] = []
    for snapshot in snapshots:
        if not isinstance(snapshot, dict) or set(snapshot) != {"repository", "base_branch", "base_sha"}:
            raise ContractError("Finding bundle repository snapshot is malformed")
        repository = snapshot["repository"]
        if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
            raise ContractError("Finding bundle repository identity is invalid")
        if not SHA_RE.fullmatch(str(snapshot["base_sha"])):
            raise ContractError("Finding bundle base commit is invalid")
        snapshot_names.append(repository)
    if snapshot_names != sorted(set(snapshot_names)):
        raise ContractError("Finding bundle repository snapshots must be unique and sorted")
    material = dict(bundle)
    material.pop("bundle_digest")
    if bundle["bundle_digest"] != object_digest(material):
        raise ContractError("Finding bundle digest does not match canonical content")
    return bundle


def coverage_classifications(coverage: dict[str, Any], registry: dict[str, Any]) -> dict[str, dict[str, str]]:
    covered = {coverage["canary"]["repository"]}
    for batch in coverage["batches"]:
        covered.update(batch["repositories"])
    result: dict[str, dict[str, str]] = {}
    for entry in registry.get("repositories", []):
        if not isinstance(entry, dict) or entry.get("repository") not in covered:
            continue
        result[entry["repository"]] = {
            "lifecycle": entry["lifecycle"],
            "scope": entry["scope"],
            "provenance": entry["provenance"],
        }
    if set(result) != covered:
        raise SafetyRefusal("verified coverage and authoritative registry disagree")
    return result


def remediation_key(
    *, repository: str, rule_id: str, finding_fingerprint: str, fixer_id: str, fixer_version: str, base_sha: str
) -> str:
    return object_digest(
        {
            "repository": repository,
            "rule_id": rule_id,
            "finding_fingerprint": finding_fingerprint,
            "fixer_id": fixer_id,
            "fixer_version": fixer_version,
            "base_sha": base_sha,
        }
    )


def _changed_lines(before: str, after: str) -> tuple[list[str], list[str]]:
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    removed = [line for line in before_lines if line not in after_lines]
    added = [line for line in after_lines if line not in before_lines]
    return added, removed


def automatic_merge_eligible(plan: dict[str, Any], policy: dict[str, Any]) -> tuple[bool, str]:
    fixer_id = plan["fixer"]["id"]
    fixer_policy = policy["fixers"].get(fixer_id)
    if not isinstance(fixer_policy, dict) or fixer_policy.get("automatic_merge") is not True:
        return False, "fixer-review-required"
    files = plan.get("files", [])
    limits = policy["automatic_merge_limits"]
    if len(files) != 1 or len(files) > limits["maximum_changed_files"]:
        return False, "changed-file-limit"
    item = files[0]
    if item.get("path") != ".gitignore" or item.get("mode") != "100644":
        return False, "path-or-mode-refusal"
    if item.get("action") not in {"create", "replace"}:
        return False, "deletion-refusal"
    after = item.get("after_text")
    if not isinstance(after, str) or "\x00" in after:
        return False, "binary-or-encoding-refusal"
    before = ""
    if item.get("action") == "replace":
        before_text = item.get("before_text")
        if before_text is not None and not isinstance(before_text, str):
            return False, "preimage-refusal"
        before = before_text or ""
    allowed_lines = set(fixer_policy["automatic_merge_added_lines"])
    added, removed = _changed_lines(before, after)
    if removed:
        return False, "additions-only-refusal"
    if not added or len(added) > limits["maximum_changed_lines"]:
        return False, "changed-line-limit"
    if any(line not in allowed_lines for line in added):
        return False, "unexpected-line-refusal"
    return True, "eligible"


def build_approval(
    *,
    policy: dict[str, Any],
    coverage: dict[str, Any],
    bundle: dict[str, Any],
    finding: dict[str, Any],
    proposal: dict[str, Any],
    plan: dict[str, Any],
    expected_head_sha: str,
    mode: str,
    source_run: dict[str, Any],
    controller_run: dict[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    issued = now or datetime.now(timezone.utc)
    files = [
        {
            "path": item["path"],
            "mode": item["mode"],
            "before_sha256": item["before_sha256"],
            "after_sha256": item["after_sha256"],
        }
        for item in plan["files"]
    ]
    key = remediation_key(
        repository=plan["repository"],
        rule_id=finding["rule_id"],
        finding_fingerprint=finding["fingerprint"],
        fixer_id=plan["fixer"]["id"],
        fixer_version=plan["fixer"]["version"],
        base_sha=plan["base_sha"],
    )
    approval: dict[str, Any] = {
        "schema_version": APPROVAL_SCHEMA,
        "approval_id": "approval:sha256:" + "0" * 64,
        "remediation_key": key,
        "policy_digest": object_digest(policy),
        "coverage_digest": object_digest(coverage),
        "bundle_digest": bundle["bundle_digest"],
        "finding_fingerprint": finding["fingerprint"],
        "proposal_id": proposal["proposal_id"],
        "plan_digest": plan["plan_digest"],
        "repository": plan["repository"],
        "classification": plan["classification"],
        "classification_fingerprint": plan["classification_fingerprint"],
        "rule_id": finding["rule_id"],
        "fixer": plan["fixer"],
        "base_branch": plan["base_branch"],
        "base_sha": plan["base_sha"],
        "expected_head_sha": expected_head_sha,
        "files": files,
        "patch_digest": plan["patch_digest"],
        "risk_class": "low" if plan["fixer"]["id"] in AUTO_FIXERS else "review-required",
        "mode": mode,
        "source_run": source_run,
        "controller_run": controller_run,
        "issued_at": issued.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "expires_at": (issued + timedelta(hours=int(policy["approval_ttl_hours"])))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    material = dict(approval)
    material.pop("approval_id")
    approval["approval_id"] = "approval:" + object_digest(material)
    return approval


def approval_marker(approval: dict[str, Any]) -> str:
    encoded = base64.urlsafe_b64encode(canonical_json(approval).encode("utf-8")).rstrip(b"=").decode("ascii")
    return f"<!-- atlas-gardener-approval:{encoded} -->"


def parse_approval_marker(body: str) -> dict[str, Any]:
    matches = APPROVAL_MARKER_RE.findall(body)
    if len(matches) != 1:
        raise SafetyRefusal("pull request must contain exactly one Gardener approval marker")
    encoded = matches[0]
    padding = "=" * (-len(encoded) % 4)
    try:
        value = json.loads(base64.urlsafe_b64decode(encoded + padding).decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise SafetyRefusal("Gardener approval marker is malformed") from error
    if not isinstance(value, dict) or value.get("schema_version") != APPROVAL_SCHEMA:
        raise SafetyRefusal("Gardener approval marker has an unsupported schema")
    return value


def controller_run_identity() -> dict[str, Any]:
    required = {
        "repository": os.environ.get("GITHUB_REPOSITORY", "AtlasReaper311/atlas-gardener"),
        "workflow": os.environ.get("GITHUB_WORKFLOW_REF", "").split("@", 1)[0].split("/", 2)[-1],
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")),
        "commit": os.environ.get("GITHUB_SHA", "0" * 40),
    }
    workflow = required["workflow"]
    if workflow and not workflow.startswith(".github/workflows/"):
        required["workflow"] = ".github/workflows/" + workflow.rsplit("/", 1)[-1]
    if not SHA_RE.fullmatch(str(required["commit"])):
        raise SafetyRefusal("controller workflow commit identity is unavailable")
    return required


def new_evidence(*, mode: str, policy: dict[str, Any], coverage: dict[str, Any], bundle: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "schema_version": EVIDENCE_SCHEMA,
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")),
        "mode": mode,
        "policy_digest": object_digest(policy),
        "coverage_digest": object_digest(coverage),
        "bundle_digest": bundle.get("bundle_digest") if bundle else None,
        "finding_fingerprints": [],
        "proposals": [],
        "plans": [],
        "repositories_skipped": [],
        "refusals": [],
        "pull_requests": [],
        "ci": [],
        "merge_outcomes": [],
        "tokens": [],
        "notifications": [],
    }
