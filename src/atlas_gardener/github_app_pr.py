"""GitHub App draft-PR adapter for reviewed Gardener proposals.

The adapter has two deliberately separate phases:

1. Build an offline, deterministic remote PR plan from an already reviewed
   RemediationProposal and an exact clean local checkout.
2. Optionally apply that exact plan with a short-lived GitHub App installation
   token supplied by an approved external token broker.

The module never mints App credentials, never reads a private key, never merges
or approves a pull request, never changes repository settings or secrets, and
never calls provider APIs outside the small endpoint allowlist below.
"""

from __future__ import annotations

import base64
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
_BLOB_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_BRANCH_RE = re.compile(r"^gardener/[a-z0-9][a-z0-9._/-]{0,120}$")
_SENSITIVE_PATH_PARTS = {
    ".env",
    ".aws",
    ".ssh",
    "credentials",
    "secrets",
    "private-key",
    "private_key",
}


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


class RestTransport:
    """Minimal GitHub REST transport that never logs the bearer token."""

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
        if not path.startswith("/repos/AtlasReaper311/"):
            raise GardenerError("GitHub App adapter refused a non-Atlas API path")
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
                raw = response.read()
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


def _safe_plan_path(repository: Path, relative: str) -> None:
    path = safe_relative_path(repository, relative, allow_missing=True)
    lowered_parts = {part.lower() for part in Path(relative).parts}
    if lowered_parts & _SENSITIVE_PATH_PARTS:
        raise SafetyRefusal(f"sensitive path refused for GitHub App PR: {relative}")
    if path.name.lower().endswith((".pem", ".key", ".p12", ".pfx")):
        raise SafetyRefusal(f"credential-like file refused for GitHub App PR: {relative}")


def _sha256_bytes(value: bytes | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value).hexdigest()


def _blob_sha(repository: Path, base_sha: str, path: str, before: bytes | None) -> str | None:
    if before is None:
        return None
    value = _git(repository, "rev-parse", f"{base_sha}:{path}")
    if value is None or not _BLOB_SHA_RE.fullmatch(value):
        raise SafetyRefusal(f"could not resolve exact base blob for {path}")
    return value


def _regenerate_reviewed_plan(
    *,
    proposal_path: Path,
    repository: Path,
    contracts: ContractSet,
    pins_file: Path | None,
) -> tuple[dict[str, Any], Any]:
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
    return proposal, change_plan


def build_pr_plan(
    *,
    proposal_path: Path,
    repository: Path,
    contracts: ContractSet,
    base_branch: str = "main",
    pins_file: Path | None = None,
) -> dict[str, Any]:
    """Build an exact, offline remote-PR plan from a reviewed proposal."""
    proposal, change_plan = _regenerate_reviewed_plan(
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
    for change in change_plan.changes:
        _safe_plan_path(repository, change.path)
        if change.after is not None and b"\x00" in change.after:
            raise SafetyRefusal(f"binary output refused for GitHub App PR: {change.path}")
        try:
            after_text = change.after.decode("utf-8") if change.after is not None else None
        except UnicodeDecodeError as error:
            raise SafetyRefusal(
                f"non-UTF-8 output refused for GitHub App PR: {change.path}"
            ) from error
        files.append(
            {
                "path": change.path,
                "action": change.action,
                "expected_blob_sha": _blob_sha(
                    repository, base_sha, change.path, change.before
                ),
                "before_sha256": _sha256_bytes(change.before),
                "after_sha256": _sha256_bytes(change.after),
                "after_text": after_text,
            }
        )

    plan: dict[str, Any] = {
        "schema_version": PLAN_SCHEMA,
        "plan_digest": "sha256:" + "0" * 64,
        "proposal_id": proposal["proposal_id"],
        "finding_fingerprint": proposal["finding_fingerprint"],
        "patch_digest": proposal["patch_digest"],
        "repository": remote_repository,
        "base_branch": base_branch,
        "base_sha": base_sha,
        "branch": _branch_name(proposal),
        "commit_message": "chore: apply reviewed gardener proposal",
        "pr_title": f"chore: gardener remediation {proposal['fixer']['id']}",
        "files": files,
        "validation_plan": proposal["validation_plan"],
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


def validate_pr_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Validate plan integrity without network access."""
    if not isinstance(plan, dict) or plan.get("schema_version") != PLAN_SCHEMA:
        raise SafetyRefusal("unsupported GitHub App PR plan schema")
    repository = plan.get("repository")
    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository):
        raise SafetyRefusal("GitHub App PR plan targets a non-Atlas repository")
    base_branch = plan.get("base_branch")
    if not isinstance(base_branch, str) or not re.fullmatch(
        r"[A-Za-z0-9._/-]{1,120}", base_branch
    ):
        raise SafetyRefusal("invalid base branch in GitHub App PR plan")
    if base_branch.startswith("-") or ".." in base_branch or "//" in base_branch:
        raise SafetyRefusal("refused base branch in GitHub App PR plan")
    base_sha = plan.get("base_sha")
    if not isinstance(base_sha, str) or not _SHA_RE.fullmatch(base_sha):
        raise SafetyRefusal("invalid base SHA in GitHub App PR plan")
    branch = plan.get("branch")
    if not isinstance(branch, str):
        raise SafetyRefusal("missing Gardener branch name")
    _validate_branch(branch)
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
    paths: set[str] = set()
    for file in files:
        if not isinstance(file, dict):
            raise SafetyRefusal("GitHub App PR plan file entry is invalid")
        path = file.get("path")
        if not isinstance(path, str) or path in paths:
            raise SafetyRefusal("GitHub App PR plan contains a duplicate or invalid path")
        paths.add(path)
        if path.startswith(("/", "../")) or "/../" in path or "\\" in path:
            raise SafetyRefusal(f"unsafe plan path refused: {path}")
        action = file.get("action")
        if action not in {"create", "replace", "delete"}:
            raise SafetyRefusal(f"unsupported GitHub App file action: {action!r}")
        expected_blob_sha = file.get("expected_blob_sha")
        if action == "create" and expected_blob_sha is not None:
            raise SafetyRefusal("create action must not carry an existing blob SHA")
        if action in {"replace", "delete"} and (
            not isinstance(expected_blob_sha, str)
            or not _BLOB_SHA_RE.fullmatch(expected_blob_sha)
        ):
            raise SafetyRefusal("replace/delete action requires the exact base blob SHA")
        after_text = file.get("after_text")
        if action == "delete" and after_text is not None:
            raise SafetyRefusal("delete action must not carry after_text")
        if action != "delete" and not isinstance(after_text, str):
            raise SafetyRefusal("create/replace action requires UTF-8 after_text")
        if action != "delete":
            expected_after = hashlib.sha256(after_text.encode("utf-8")).hexdigest()
            if file.get("after_sha256") != expected_after:
                raise SafetyRefusal(f"after_text digest mismatch for {path}")

    digest = plan.get("plan_digest")
    expected_digest = _plan_digest(plan)
    if digest != expected_digest:
        raise SafetyRefusal("GitHub App PR plan digest does not match canonical content")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise SafetyRefusal("invalid GitHub App PR plan digest")

    expires = plan.get("expires_at")
    if not isinstance(expires, str):
        raise SafetyRefusal("GitHub App PR plan has no expiry")
    try:
        datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError as error:
        raise SafetyRefusal("GitHub App PR plan expiry is invalid") from error
    return plan


def _repo_path(plan: dict[str, Any], suffix: str) -> str:
    return f"/repos/{plan['repository']}{suffix}"


def _ref_suffix(branch: str) -> str:
    return urllib.parse.quote(branch, safe="")


def _file_suffix(path: str) -> str:
    return urllib.parse.quote(path, safe="/")


def _pr_body(plan: dict[str, Any]) -> str:
    files = "\n".join(f"- `{item['path']}` ({item['action']})" for item in plan["files"])
    checks = "\n".join(
        f"- `{item['command']}`: {item['expected']}"
        for item in plan.get("validation_plan", [])
        if isinstance(item, dict)
    )
    return (
        "## Reviewed Gardener proposal\n\n"
        f"Proposal: `{plan['proposal_id']}`\n\n"
        f"Plan digest: `{plan['plan_digest']}`\n\n"
        f"Patch digest: `{plan['patch_digest']}`\n\n"
        "### Exact files\n\n"
        f"{files}\n\n"
        "### Repository-owned validation\n\n"
        f"{checks or '- Native pull-request checks must complete before human review.'}\n\n"
        "### Safety boundary\n\n"
        "This adapter stops after opening this draft pull request. It does not approve or merge the PR, deploy, change repository settings or secrets, or mutate any non-GitHub provider."
    )


def plan_summary(plan: dict[str, Any]) -> dict[str, Any]:
    """Return a reviewable summary without repeating file contents or credentials."""
    return {
        "schema_version": "atlas-gardener/github-app-pr-summary/v1",
        "plan_digest": plan["plan_digest"],
        "proposal_id": plan["proposal_id"],
        "repository": plan["repository"],
        "base_branch": plan["base_branch"],
        "base_sha": plan["base_sha"],
        "branch": plan["branch"],
        "files": [
            {
                "path": item["path"],
                "action": item["action"],
                "before_sha256": item["before_sha256"],
                "after_sha256": item["after_sha256"],
            }
            for item in plan["files"]
        ],
        "permissions_required": plan["permissions_required"],
        "network_access": False,
        "provider_mutation": False,
        "stop_after": plan["stop_after"],
    }


def apply_pr_plan(
    plan: dict[str, Any],
    *,
    approved_plan_digest: str,
    token: str,
    transport: GitHubTransport | None = None,
) -> dict[str, Any]:
    """Open exactly one draft PR from an approved plan, then stop."""
    plan = validate_pr_plan(plan)
    if approved_plan_digest != plan["plan_digest"]:
        raise SafetyRefusal("approved plan digest does not match the reviewed PR plan")
    expires = datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
    if expires < datetime.now(timezone.utc):
        raise SafetyRefusal("GitHub App PR plan has expired")
    if not token or len(token) < 20:
        raise SafetyRefusal("short-lived GitHub App installation token is missing")

    client = transport or RestTransport()
    base_ref = client.request(
        "GET",
        _repo_path(plan, f"/git/ref/heads/{_ref_suffix(plan['base_branch'])}"),
        token=token,
    )
    remote_base = base_ref.get("object", {}).get("sha") if isinstance(base_ref, dict) else None
    if remote_base != plan["base_sha"]:
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

    client.request(
        "POST",
        _repo_path(plan, "/git/refs"),
        token=token,
        payload={"ref": f"refs/heads/{plan['branch']}", "sha": plan["base_sha"]},
    )

    committed_files: list[str] = []
    for file in plan["files"]:
        suffix = f"/contents/{_file_suffix(file['path'])}"
        payload: dict[str, Any] = {
            "message": plan["commit_message"],
            "branch": plan["branch"],
        }
        if file["action"] == "delete":
            payload["sha"] = file["expected_blob_sha"]
            client.request("DELETE", _repo_path(plan, suffix), token=token, payload=payload)
        else:
            payload["content"] = base64.b64encode(file["after_text"].encode("utf-8")).decode("ascii")
            if file["expected_blob_sha"] is not None:
                payload["sha"] = file["expected_blob_sha"]
            client.request("PUT", _repo_path(plan, suffix), token=token, payload=payload)
        committed_files.append(file["path"])

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
        "branch": plan["branch"],
        "files_committed": committed_files,
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
