"""GitHub App draft-PR adapter for reviewed Gardener proposals.

The adapter has two deliberately separate phases:

1. Build an offline, deterministic remote PR plan from an already reviewed
   RemediationProposal and an exact clean local checkout.
2. Optionally apply that exact plan with a short-lived GitHub App installation
   token supplied by an approved external token broker.

The module never mints App credentials, never reads a private key, never merges
or approves a pull request, never changes repository settings or secrets, and
never calls provider APIs outside the explicit endpoint allowlist below.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from atlas_gardener.contracts import ContractSet, read_json, sha256_value
from atlas_gardener.errors import GardenerError, SafetyRefusal
from atlas_gardener.fixers import build_plan
from atlas_gardener.models import RepositoryClassification
from atlas_gardener.safety import (
    classification_for,
    ensure_clean_worktree,
    ensure_remediation_allowed,
    safe_relative_path,
)

PLAN_SCHEMA = "atlas-gardener/github-app-pr-plan/v1"
RESULT_SCHEMA = "atlas-gardener/github-app-pr-result/v1"
TOKEN_ENV = "ATLAS_GARDENER_INSTALLATION_TOKEN"
_REPOSITORY_RE = re.compile(r"^AtlasReaper311/[A-Za-z0-9._-]+$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX256_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROPOSAL_ID_RE = re.compile(r"^proposal:sha256:[0-9a-f]{64}$")
_FIXER_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_BRANCH_RE = re.compile(r"^gardener/[a-z0-9][a-z0-9._/-]{0,120}$")
_BASE_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,120}$")
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_PLAN_BYTES = 1_048_576
_MAX_FILE_BYTES = 262_144
_ALLOWED_FILE_MODES = {"100644", "100755"}
_FORBIDDEN_WORKFLOW_PREFIX = ".github/workflows/"
_SENSITIVE_PATH_PARTS = {
    ".aws",
    ".git",
    ".ssh",
    "credentials",
    "private-key",
    "private_key",
    "secrets",
}
_CREDENTIAL_SUFFIXES = (".pem", ".key", ".p12", ".pfx")


class GitHubTransport(Protocol):
    """Small injectable HTTP seam used by the adapter and unit tests."""

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> dict[str, Any] | None: ...


def _allowed_api_operation(method: str, path: str, allow_not_found: bool) -> bool:
    repository = r"/repos/AtlasReaper311/[A-Za-z0-9._-]+"
    operations = {
        ("GET", rf"^{repository}/git/ref/heads/[A-Za-z0-9%._~-]+$"),
        ("GET", rf"^{repository}/git/commits/[0-9a-f]{{40}}$"),
        ("POST", rf"^{repository}/git/blobs$"),
        ("POST", rf"^{repository}/git/trees$"),
        ("POST", rf"^{repository}/git/commits$"),
        ("POST", rf"^{repository}/git/refs$"),
        ("POST", rf"^{repository}/pulls$"),
    }
    matched = any(
        method == allowed_method and re.fullmatch(pattern, path)
        for allowed_method, pattern in operations
    )
    if not matched:
        return False
    if allow_not_found:
        return method == "GET" and "/git/ref/heads/" in path
    return True


class RestTransport:
    """Minimal GitHub REST transport with a strict endpoint allowlist."""

    def __init__(self, api_base: str = "https://api.github.com") -> None:
        self.api_base = api_base.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> dict[str, Any] | None:
        method = method.upper()
        if not _allowed_api_operation(method, path, allow_not_found):
            raise GardenerError(
                f"GitHub App adapter refused an endpoint outside its allowlist: {method} {path}"
            )
        data = None
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "AtlasReaper311/atlas-gardener",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            )
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.api_base + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            if allow_not_found and error.code == 404:
                return None
            raise GardenerError(
                f"GitHub App request failed: {method} {path} returned HTTP {error.code}"
            ) from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise GardenerError(
                f"GitHub App request failed: {method} {path} was unavailable"
            ) from error
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise GardenerError(
                f"GitHub App request failed: {method} {path} exceeded the response bound"
            )
        if not raw:
            return {}
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise GardenerError(
                f"GitHub App request failed: {method} {path} returned invalid JSON"
            ) from error
        if not isinstance(value, dict):
            raise GardenerError(
                f"GitHub App request failed: {method} {path} returned a non-object"
            )
        return value


def _git(repository: Path, *args: str, allow_failure: bool = False) -> str | None:
    completed = subprocess.run(
        ["git", *args],
        cwd=repository,
        check=False,
        text=True,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0:
        if allow_failure:
            return None
        detail = completed.stderr.strip() or completed.stdout.strip() or "git failed"
        raise SafetyRefusal(detail)
    return completed.stdout.strip()


def _remote_repository(repository: Path) -> str:
    value = _git(repository, "remote", "get-url", "origin")
    assert value is not None
    patterns = (
        re.compile(r"^https://github\.com/(AtlasReaper311/[A-Za-z0-9._-]+?)(?:\.git)?$"),
        re.compile(r"^git@github\.com:(AtlasReaper311/[A-Za-z0-9._-]+?)(?:\.git)?$"),
    )
    for pattern in patterns:
        match = pattern.fullmatch(value)
        if match:
            return match.group(1)
    raise SafetyRefusal(
        "origin must point exactly at an AtlasReaper311 GitHub repository"
    )


def _branch_name(proposal: dict[str, Any]) -> str:
    proposal_id = str(proposal["proposal_id"])
    digest = proposal_id.removeprefix("proposal:sha256:")
    fixer = re.sub(r"[^a-z0-9._-]+", "-", str(proposal["fixer"]["id"]).lower())
    branch = f"gardener/{fixer}-{digest[:12]}"
    _validate_branch(branch)
    return branch


def _validate_branch(branch: str) -> None:
    if not _BRANCH_RE.fullmatch(branch):
        raise SafetyRefusal("Gardener branch name is outside the approved namespace")
    if any(token in branch for token in ("..", "//", "@{", "\\")):
        raise SafetyRefusal("Gardener branch name contains a refused git-ref sequence")
    if branch.endswith(("/", ".")):
        raise SafetyRefusal("Gardener branch name has an invalid suffix")


def _validate_base_branch(branch: str) -> None:
    if not _BASE_BRANCH_RE.fullmatch(branch):
        raise SafetyRefusal("invalid base branch in GitHub App PR plan")
    if branch.startswith("-") or any(
        token in branch for token in ("..", "//", "@{", "\\")
    ):
        raise SafetyRefusal("refused base branch in GitHub App PR plan")
    if branch.endswith(("/", ".")):
        raise SafetyRefusal("base branch has an invalid suffix")


def _validate_plan_path(relative: str) -> None:
    if not isinstance(relative, str) or not relative or len(relative) > 240:
        raise SafetyRefusal("GitHub App PR plan contains an invalid path")
    if relative.startswith(("/", "../")) or "/../" in relative or "\\" in relative:
        raise SafetyRefusal(f"unsafe plan path refused: {relative}")
    lowered_parts = {part.lower() for part in Path(relative).parts}
    if lowered_parts & _SENSITIVE_PATH_PARTS:
        raise SafetyRefusal(f"sensitive path refused for GitHub App PR: {relative}")
    if any(part.startswith(".env") for part in lowered_parts):
        raise SafetyRefusal(f"environment file refused for GitHub App PR: {relative}")
    if Path(relative).name.lower().endswith(_CREDENTIAL_SUFFIXES):
        raise SafetyRefusal(f"credential-like file refused for GitHub App PR: {relative}")
    if relative.lower().startswith(_FORBIDDEN_WORKFLOW_PREFIX):
        raise SafetyRefusal(
            "workflow-file proposals require a separate permission-gated adapter version"
        )


def _safe_plan_path(repository: Path, relative: str) -> None:
    _validate_plan_path(relative)
    path = safe_relative_path(repository, relative, allow_missing=True)
    if path.is_symlink():
        raise SafetyRefusal(f"symlink output refused for GitHub App PR: {relative}")


def _sha256_bytes(value: bytes | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value).hexdigest()


def _base_file_metadata(
    repository: Path, base_sha: str, path: str, before: bytes | None
) -> tuple[str | None, str]:
    if before is None:
        return None, "100644"
    value = _git(repository, "ls-tree", base_sha, "--", path)
    if value is None or not value:
        raise SafetyRefusal(f"could not resolve exact base blob for {path}")
    metadata, separator, returned_path = value.partition("\t")
    if not separator or returned_path != path:
        raise SafetyRefusal(f"could not resolve exact base blob for {path}")
    parts = metadata.split()
    if len(parts) != 3 or parts[1] != "blob":
        raise SafetyRefusal(f"base path is not a normal file: {path}")
    mode, _, blob_sha = parts
    if mode not in _ALLOWED_FILE_MODES or not _SHA_RE.fullmatch(blob_sha):
        raise SafetyRefusal(f"base file mode or blob identity is unsupported: {path}")
    return blob_sha, mode


def _classification_value(
    classification: RepositoryClassification,
) -> dict[str, str]:
    return {
        "lifecycle": classification.lifecycle,
        "scope": classification.scope,
        "provenance": classification.provenance,
    }


def _regenerate_reviewed_plan(
    *,
    proposal_path: Path,
    repository: Path,
    contracts: ContractSet,
    pins_file: Path | None,
) -> tuple[dict[str, Any], Any, RepositoryClassification]:
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
    )
    if change_plan.files_affected != proposal["files_affected"]:
        raise SafetyRefusal("regenerated files differ from the reviewed proposal")
    if change_plan.patch_digest != proposal["patch_digest"]:
        raise SafetyRefusal("regenerated patch digest differs from the reviewed proposal")
    return proposal, change_plan, classification


def build_pr_plan(
    *,
    proposal_path: Path,
    repository: Path,
    contracts: ContractSet,
    base_branch: str = "main",
    pins_file: Path | None = None,
) -> dict[str, Any]:
    """Build an exact, offline remote-PR plan from a reviewed proposal."""

    _validate_base_branch(base_branch)
    proposal, change_plan, classification = _regenerate_reviewed_plan(
        proposal_path=proposal_path,
        repository=repository,
        contracts=contracts,
        pins_file=pins_file,
    )
    repository = repository.resolve(strict=True)
    remote_repository = _remote_repository(repository)
    if remote_repository != f"AtlasReaper311/{repository.name}":
        raise SafetyRefusal("local directory name and GitHub origin repository disagree")

    current_branch = _git(repository, "branch", "--show-current")
    if current_branch != base_branch:
        raise SafetyRefusal(
            f"GitHub App plan requires local branch {base_branch!r}; found {current_branch!r}"
        )
    base_sha = _git(repository, "rev-parse", "HEAD")
    if base_sha is None or not _SHA_RE.fullmatch(base_sha):
        raise SafetyRefusal("could not resolve exact local base commit")

    files: list[dict[str, Any]] = []
    for change in sorted(change_plan.changes, key=lambda item: item.path):
        _safe_plan_path(repository, change.path)
        if change.after is not None and len(change.after) > _MAX_FILE_BYTES:
            raise SafetyRefusal(f"file output exceeds the GitHub App bound: {change.path}")
        if change.after is not None and b"\x00" in change.after:
            raise SafetyRefusal(f"binary output refused for GitHub App PR: {change.path}")
        try:
            after_text = change.after.decode("utf-8") if change.after is not None else None
        except UnicodeDecodeError as error:
            raise SafetyRefusal(
                f"non-UTF-8 output refused for GitHub App PR: {change.path}"
            ) from error
        expected_blob_sha, mode = _base_file_metadata(
            repository, base_sha, change.path, change.before
        )
        files.append(
            {
                "path": change.path,
                "action": change.action,
                "mode": mode,
                "expected_blob_sha": expected_blob_sha,
                "before_sha256": _sha256_bytes(change.before),
                "after_sha256": _sha256_bytes(change.after),
                "after_text": after_text,
            }
        )

    classification_value = _classification_value(classification)
    plan: dict[str, Any] = {
        "schema_version": PLAN_SCHEMA,
        "plan_digest": "sha256:" + "0" * 64,
        "proposal_id": proposal["proposal_id"],
        "finding_fingerprint": proposal["finding_fingerprint"],
        "patch_digest": proposal["patch_digest"],
        "fixer": proposal["fixer"],
        "risk_class": proposal["risk_class"],
        "repository": remote_repository,
        "classification": classification_value,
        "classification_fingerprint": sha256_value(classification_value),
        "base_branch": base_branch,
        "base_sha": base_sha,
        "branch": _branch_name(proposal),
        "commit_message": f"chore: apply reviewed gardener proposal {proposal['fixer']['id']}",
        "pr_title": f"chore: gardener remediation {proposal['fixer']['id']}",
        "files": files,
        "validation_plan": proposal["validation_plan"],
        "rollback_plan": proposal["rollback_plan"],
        "expires_at": proposal["expires_at"],
        "permissions_required": {
            "metadata": "read",
            "contents": "write",
            "pull_requests": "write",
        },
        "stop_after": "draft-pull-request",
    }
    plan["plan_digest"] = _plan_digest(plan)
    return validate_pr_plan(plan)


def _plan_digest(plan: dict[str, Any]) -> str:
    material = dict(plan)
    material.pop("plan_digest", None)
    return sha256_value(material)


def _validate_text(value: Any, *, label: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise SafetyRefusal(f"GitHub App PR plan {label} is invalid")
    return value


def validate_pr_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Validate plan integrity and every apply-time safety invariant offline."""

    if not isinstance(plan, dict) or plan.get("schema_version") != PLAN_SCHEMA:
        raise SafetyRefusal("unsupported GitHub App PR plan schema")
    encoded = json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) > _MAX_PLAN_BYTES:
        raise SafetyRefusal("GitHub App PR plan exceeds the bounded plan size")

    expected_keys = {
        "schema_version",
        "plan_digest",
        "proposal_id",
        "finding_fingerprint",
        "patch_digest",
        "fixer",
        "risk_class",
        "repository",
        "classification",
        "classification_fingerprint",
        "base_branch",
        "base_sha",
        "branch",
        "commit_message",
        "pr_title",
        "files",
        "validation_plan",
        "rollback_plan",
        "expires_at",
        "permissions_required",
        "stop_after",
    }
    if set(plan) != expected_keys:
        raise SafetyRefusal("GitHub App PR plan contains missing or unexpected fields")

    repository = plan.get("repository")
    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository):
        raise SafetyRefusal("GitHub App PR plan targets a non-Atlas repository")
    if not isinstance(plan.get("proposal_id"), str) or not _PROPOSAL_ID_RE.fullmatch(
        plan["proposal_id"]
    ):
        raise SafetyRefusal("invalid proposal identity in GitHub App PR plan")
    for field in ("finding_fingerprint", "patch_digest", "classification_fingerprint"):
        if not isinstance(plan.get(field), str) or not _DIGEST_RE.fullmatch(plan[field]):
            raise SafetyRefusal(f"invalid {field.replace('_', ' ')} in GitHub App PR plan")

    fixer = plan.get("fixer")
    if not isinstance(fixer, dict) or set(fixer) != {"id", "version"}:
        raise SafetyRefusal("GitHub App PR plan fixer is invalid")
    if not isinstance(fixer["id"], str) or not _FIXER_ID_RE.fullmatch(fixer["id"]):
        raise SafetyRefusal("GitHub App PR plan fixer ID is invalid")
    if not isinstance(fixer["version"], str) or not _SEMVER_RE.fullmatch(
        fixer["version"]
    ):
        raise SafetyRefusal("GitHub App PR plan fixer version is invalid")
    if plan.get("risk_class") not in {"low", "medium", "high"}:
        raise SafetyRefusal("GitHub App PR plan risk class is invalid")

    classification = plan.get("classification")
    if not isinstance(classification, dict) or set(classification) != {
        "lifecycle",
        "scope",
        "provenance",
    }:
        raise SafetyRefusal("GitHub App PR plan classification is invalid")
    for key in ("lifecycle", "scope", "provenance"):
        _validate_text(classification.get(key), label=f"classification {key}", minimum=1, maximum=64)
    if plan["classification_fingerprint"] != sha256_value(classification):
        raise SafetyRefusal("GitHub App PR plan classification fingerprint is invalid")
    ensure_remediation_allowed(
        repository.rsplit("/", 1)[-1],
        RepositoryClassification(
            classification["lifecycle"],
            classification["scope"],
            classification["provenance"],
        ),
    )

    base_branch = plan.get("base_branch")
    if not isinstance(base_branch, str):
        raise SafetyRefusal("missing base branch in GitHub App PR plan")
    _validate_base_branch(base_branch)
    base_sha = plan.get("base_sha")
    if not isinstance(base_sha, str) or not _SHA_RE.fullmatch(base_sha):
        raise SafetyRefusal("invalid base SHA in GitHub App PR plan")
    branch = plan.get("branch")
    if not isinstance(branch, str):
        raise SafetyRefusal("missing Gardener branch name")
    _validate_branch(branch)
    _validate_text(plan.get("commit_message"), label="commit message", minimum=1, maximum=200)
    _validate_text(plan.get("pr_title"), label="pull request title", minimum=1, maximum=200)
    if "\n" in plan["commit_message"] or "\n" in plan["pr_title"]:
        raise SafetyRefusal("GitHub App PR plan title fields must be single-line")
    if plan.get("stop_after") != "draft-pull-request":
        raise SafetyRefusal("GitHub App PR plan must stop after the draft pull request")
    if plan.get("permissions_required") != {
        "metadata": "read",
        "contents": "write",
        "pull_requests": "write",
    }:
        raise SafetyRefusal("GitHub App PR plan requests unexpected permissions")

    files = plan.get("files")
    if not isinstance(files, list) or not files or len(files) > 5:
        raise SafetyRefusal("GitHub App PR plan must contain one to five files")
    if files != sorted(files, key=lambda item: item.get("path", "") if isinstance(item, dict) else ""):
        raise SafetyRefusal("GitHub App PR plan files must use canonical path ordering")
    paths: set[str] = set()
    for file in files:
        if not isinstance(file, dict) or set(file) != {
            "path",
            "action",
            "mode",
            "expected_blob_sha",
            "before_sha256",
            "after_sha256",
            "after_text",
        }:
            raise SafetyRefusal("GitHub App PR plan file entry is invalid")
        path = file.get("path")
        if not isinstance(path, str) or path in paths:
            raise SafetyRefusal("GitHub App PR plan contains a duplicate or invalid path")
        _validate_plan_path(path)
        paths.add(path)
        action = file.get("action")
        if action not in {"create", "replace", "delete"}:
            raise SafetyRefusal(f"unsupported GitHub App file action: {action!r}")
        mode = file.get("mode")
        if mode not in _ALLOWED_FILE_MODES:
            raise SafetyRefusal(f"unsupported GitHub App file mode for {path}")
        expected_blob_sha = file.get("expected_blob_sha")
        before_sha256 = file.get("before_sha256")
        if action == "create":
            if expected_blob_sha is not None or before_sha256 is not None:
                raise SafetyRefusal("create action must not carry base-file identity")
        else:
            if not isinstance(expected_blob_sha, str) or not _SHA_RE.fullmatch(
                expected_blob_sha
            ):
                raise SafetyRefusal("replace/delete action requires the exact base blob SHA")
            if not isinstance(before_sha256, str) or not _HEX256_RE.fullmatch(before_sha256):
                raise SafetyRefusal("replace/delete action requires the exact preimage digest")
        after_text = file.get("after_text")
        after_sha256 = file.get("after_sha256")
        if action == "delete":
            if after_text is not None or after_sha256 is not None:
                raise SafetyRefusal("delete action must not carry postimage content")
        else:
            if not isinstance(after_text, str):
                raise SafetyRefusal("create/replace action requires UTF-8 after_text")
            after_bytes = after_text.encode("utf-8")
            if len(after_bytes) > _MAX_FILE_BYTES:
                raise SafetyRefusal(f"file output exceeds the GitHub App bound: {path}")
            expected_after = hashlib.sha256(after_bytes).hexdigest()
            if after_sha256 != expected_after:
                raise SafetyRefusal(f"after_text digest mismatch for {path}")

    validation_plan = plan.get("validation_plan")
    if not isinstance(validation_plan, list) or not 1 <= len(validation_plan) <= 20:
        raise SafetyRefusal("GitHub App PR plan validation mapping is unavailable")
    for check in validation_plan:
        if not isinstance(check, dict) or set(check) != {"check_id", "command", "expected"}:
            raise SafetyRefusal("GitHub App PR plan validation entry is invalid")
        _validate_text(check["check_id"], label="validation check ID", minimum=1, maximum=64)
        _validate_text(check["command"], label="validation command", minimum=1, maximum=240)
        _validate_text(check["expected"], label="validation expectation", minimum=1, maximum=240)

    rollback_plan = plan.get("rollback_plan")
    if not isinstance(rollback_plan, list) or not 1 <= len(rollback_plan) <= 10:
        raise SafetyRefusal("GitHub App PR plan rollback instructions are unavailable")
    for instruction in rollback_plan:
        _validate_text(instruction, label="rollback instruction", minimum=1, maximum=300)

    expires = plan.get("expires_at")
    if not isinstance(expires, str):
        raise SafetyRefusal("GitHub App PR plan has no expiry")
    try:
        parsed_expiry = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError as error:
        raise SafetyRefusal("GitHub App PR plan expiry is invalid") from error
    if parsed_expiry.tzinfo is None:
        raise SafetyRefusal("GitHub App PR plan expiry must include a timezone")

    digest = plan.get("plan_digest")
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise SafetyRefusal("invalid GitHub App PR plan digest")
    if digest != _plan_digest(plan):
        raise SafetyRefusal("GitHub App PR plan digest does not match canonical content")
    return plan


def verify_apply_repository(plan: dict[str, Any], repository: Path) -> dict[str, str]:
    """Re-check local target identity and classification immediately before apply."""

    plan = validate_pr_plan(plan)
    repository = repository.resolve(strict=True)
    if _remote_repository(repository) != plan["repository"]:
        raise SafetyRefusal("apply repository does not match the reviewed GitHub target")
    if repository.name != plan["repository"].rsplit("/", 1)[-1]:
        raise SafetyRefusal("apply repository directory identity does not match the plan")
    current_branch = _git(repository, "branch", "--show-current")
    if current_branch != plan["base_branch"]:
        raise SafetyRefusal("local base branch changed since the reviewed plan")
    current_sha = _git(repository, "rev-parse", "HEAD")
    if current_sha != plan["base_sha"]:
        raise SafetyRefusal("local base commit changed since the reviewed plan")
    ensure_clean_worktree(repository, fixer_id=plan["fixer"]["id"])
    current = classification_for(repository.name, repository)
    ensure_remediation_allowed(repository.name, current)
    current_value = _classification_value(current)
    if current_value != plan["classification"]:
        raise SafetyRefusal("target classification changed since the reviewed plan")
    if sha256_value(current_value) != plan["classification_fingerprint"]:
        raise SafetyRefusal("target classification fingerprint changed since review")
    return current_value


def _repo_path(plan: dict[str, Any], suffix: str) -> str:
    return f"/repos/{plan['repository']}{suffix}"


def _ref_suffix(branch: str) -> str:
    return urllib.parse.quote(branch, safe="")


def _pr_body(plan: dict[str, Any]) -> str:
    files = "\n".join(
        f"- `{item['path']}` ({item['action']}, mode `{item['mode']}`)"
        for item in plan["files"]
    )
    checks = "\n".join(
        f"- `{item['check_id']}`: `{item['command']}` -> {item['expected']}"
        for item in plan["validation_plan"]
    )
    rollback = "\n".join(f"- {item}" for item in plan["rollback_plan"])
    fixer = plan["fixer"]
    return (
        "## Reviewed Gardener proposal\n\n"
        f"Finding fingerprint: `{plan['finding_fingerprint']}`\n\n"
        f"Fixer: `{fixer['id']}@{fixer['version']}`\n\n"
        f"Proposal: `{plan['proposal_id']}`\n\n"
        f"Plan digest: `{plan['plan_digest']}`\n\n"
        f"Patch digest: `{plan['patch_digest']}`\n\n"
        f"Risk: `{plan['risk_class']}`\n\n"
        f"Expires: `{plan['expires_at']}`\n\n"
        "### Exact files\n\n"
        f"{files}\n\n"
        "### Repository-owned validation\n\n"
        f"{checks}\n\n"
        "### Rollback\n\n"
        f"{rollback}\n\n"
        "### Safety boundary\n\n"
        "Gardener created one exact reviewed commit and opened this draft pull request. "
        "It did not approve or merge the PR, deploy, dispatch a workflow, change repository "
        "settings or secrets, or mutate any non-GitHub provider."
    )


def plan_summary(plan: dict[str, Any]) -> dict[str, Any]:
    """Return a reviewable summary without repeating file contents or credentials."""

    plan = validate_pr_plan(plan)
    return {
        "schema_version": "atlas-gardener/github-app-pr-summary/v1",
        "plan_digest": plan["plan_digest"],
        "proposal_id": plan["proposal_id"],
        "finding_fingerprint": plan["finding_fingerprint"],
        "fixer": plan["fixer"],
        "risk_class": plan["risk_class"],
        "repository": plan["repository"],
        "classification_fingerprint": plan["classification_fingerprint"],
        "base_branch": plan["base_branch"],
        "base_sha": plan["base_sha"],
        "branch": plan["branch"],
        "files": [
            {
                "path": item["path"],
                "action": item["action"],
                "mode": item["mode"],
                "before_sha256": item["before_sha256"],
                "after_sha256": item["after_sha256"],
            }
            for item in plan["files"]
        ],
        "permissions_required": plan["permissions_required"],
        "network_access": False,
        "provider_mutation": False,
        "stop_after": plan["stop_after"],
        "expires_at": plan["expires_at"],
    }


def _required_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise GardenerError(f"GitHub did not return a valid {label} SHA")
    return value


def _remote_base_sha(
    client: GitHubTransport, plan: dict[str, Any], token: str
) -> str | None:
    base_ref = client.request(
        "GET",
        _repo_path(plan, f"/git/ref/heads/{_ref_suffix(plan['base_branch'])}"),
        token=token,
    )
    return base_ref.get("object", {}).get("sha") if isinstance(base_ref, dict) else None


def apply_pr_plan(
    plan: dict[str, Any],
    *,
    approved_plan_digest: str,
    token: str,
    current_classification: dict[str, str],
    transport: GitHubTransport | None = None,
) -> dict[str, Any]:
    """Create one exact commit and one draft PR from an approved plan, then stop."""

    plan = validate_pr_plan(plan)
    if approved_plan_digest != plan["plan_digest"]:
        raise SafetyRefusal("approved plan digest does not match the reviewed PR plan")
    if current_classification != plan["classification"]:
        raise SafetyRefusal("target classification changed since the reviewed plan")
    if sha256_value(current_classification) != plan["classification_fingerprint"]:
        raise SafetyRefusal("target classification fingerprint changed since review")
    expires = datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
    if expires < datetime.now(timezone.utc):
        raise SafetyRefusal("GitHub App PR plan has expired")
    if not token or len(token) < 20 or any(character.isspace() for character in token):
        raise SafetyRefusal("short-lived GitHub App installation token is missing")

    client = transport or RestTransport()
    if _remote_base_sha(client, plan, token) != plan["base_sha"]:
        raise SafetyRefusal(
            "remote base branch changed since the reviewed GitHub App PR plan"
        )

    existing = client.request(
        "GET",
        _repo_path(plan, f"/git/ref/heads/{_ref_suffix(plan['branch'])}"),
        token=token,
        allow_not_found=True,
    )
    if existing is not None:
        raise SafetyRefusal("reviewed Gardener branch already exists remotely")

    base_commit = client.request(
        "GET",
        _repo_path(plan, f"/git/commits/{plan['base_sha']}"),
        token=token,
    )
    base_tree_sha = _required_sha(
        base_commit.get("tree", {}).get("sha") if isinstance(base_commit, dict) else None,
        "base tree",
    )

    tree_entries: list[dict[str, Any]] = []
    for file in plan["files"]:
        if file["action"] == "delete":
            blob_sha = None
        else:
            blob = client.request(
                "POST",
                _repo_path(plan, "/git/blobs"),
                token=token,
                payload={"content": file["after_text"], "encoding": "utf-8"},
            )
            blob_sha = _required_sha(
                blob.get("sha") if isinstance(blob, dict) else None,
                f"blob for {file['path']}",
            )
        tree_entries.append(
            {
                "path": file["path"],
                "mode": file["mode"],
                "type": "blob",
                "sha": blob_sha,
            }
        )

    tree = client.request(
        "POST",
        _repo_path(plan, "/git/trees"),
        token=token,
        payload={"base_tree": base_tree_sha, "tree": tree_entries},
    )
    tree_sha = _required_sha(tree.get("sha") if isinstance(tree, dict) else None, "tree")
    commit = client.request(
        "POST",
        _repo_path(plan, "/git/commits"),
        token=token,
        payload={
            "message": plan["commit_message"],
            "tree": tree_sha,
            "parents": [plan["base_sha"]],
        },
    )
    commit_sha = _required_sha(
        commit.get("sha") if isinstance(commit, dict) else None, "commit"
    )

    if _remote_base_sha(client, plan, token) != plan["base_sha"]:
        raise SafetyRefusal(
            "remote base branch changed while preparing the reviewed GitHub App commit"
        )

    client.request(
        "POST",
        _repo_path(plan, "/git/refs"),
        token=token,
        payload={"ref": f"refs/heads/{plan['branch']}", "sha": commit_sha},
    )
    pull = client.request(
        "POST",
        _repo_path(plan, "/pulls"),
        token=token,
        payload={
            "title": plan["pr_title"],
            "body": _pr_body(plan),
            "head": plan["branch"],
            "base": plan["base_branch"],
            "draft": True,
            "maintainer_can_modify": True,
        },
    )
    if not isinstance(pull, dict) or pull.get("draft") is not True:
        raise GardenerError("GitHub did not confirm creation of a draft pull request")
    return {
        "schema_version": RESULT_SCHEMA,
        "plan_digest": plan["plan_digest"],
        "repository": plan["repository"],
        "base_sha": plan["base_sha"],
        "commit_sha": commit_sha,
        "branch": plan["branch"],
        "files_committed": [item["path"] for item in plan["files"]],
        "draft_pull_request": {
            "number": pull.get("number"),
            "url": pull.get("html_url"),
            "draft": True,
        },
        "native_validation": "repository-owned pull-request checks triggered; adapter does not approve or merge",
        "stopped": True,
    }


def installation_token_from_environment() -> str:
    """Read the ephemeral token without exposing its value in output."""

    token = os.environ.get(TOKEN_ENV, "")
    if not token:
        raise SafetyRefusal(
            f"{TOKEN_ENV} is not set; obtain a short-lived installation token through the approved external broker"
        )
    return token
