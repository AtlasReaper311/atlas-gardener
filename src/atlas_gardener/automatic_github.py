"""Idempotent GitHub publisher for policy-bound automatic Gardener pull requests."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Protocol

from atlas_gardener.automation import approval_marker, parse_approval_marker
from atlas_gardener.errors import GardenerError, SafetyRefusal
from atlas_gardener.github_app_pr import _pr_body, validate_pr_plan

MAX_RESPONSE_BYTES = 1_048_576
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ControllerTransport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> Any: ...


class RestControllerTransport:
    """GitHub REST transport with the exact PR creation and lookup operation set."""

    def __init__(self, api_base: str = "https://api.github.com") -> None:
        self.api_base = api_base.rstrip("/")

    @staticmethod
    def _allowed(method: str, path: str, allow_not_found: bool) -> bool:
        repository = r"/repos/AtlasReaper311/[A-Za-z0-9._-]+"
        patterns = {
            ("GET", rf"^{repository}/git/ref/heads/[A-Za-z0-9%._~-]+$"),
            ("GET", rf"^{repository}/git/commits/[0-9a-f]{{40}}$"),
            ("GET", rf"^{repository}/pulls\?state=all&head=AtlasReaper311%3A[A-Za-z0-9%._~-]+&base=[A-Za-z0-9%._~-]+&per_page=100$"),
            ("POST", rf"^{repository}/git/blobs$"),
            ("POST", rf"^{repository}/git/trees$"),
            ("POST", rf"^{repository}/git/commits$"),
            ("POST", rf"^{repository}/git/refs$"),
            ("POST", rf"^{repository}/pulls$"),
        }
        matched = any(method == allowed and re.fullmatch(pattern, path) for allowed, pattern in patterns)
        if not matched:
            return False
        if allow_not_found:
            return method == "GET" and "/git/ref/heads/" in path
        return True

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> Any:
        method = method.upper()
        if not self._allowed(method, path, allow_not_found):
            raise GardenerError(f"automatic GitHub publisher refused endpoint: {method} {path}")
        if len(token) < 20 or any(character.isspace() for character in token):
            raise SafetyRefusal("short-lived repository installation token is unavailable")
        data = None
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "AtlasReaper311/atlas-gardener",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.api_base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            if allow_not_found and error.code == 404:
                return None
            raise GardenerError(f"automatic GitHub publisher returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise GardenerError("automatic GitHub publisher was unavailable") from error
        if len(raw) > MAX_RESPONSE_BYTES:
            raise GardenerError("automatic GitHub publisher response exceeded the bound")
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise GardenerError("automatic GitHub publisher returned invalid JSON") from error


def _repo_path(plan: dict[str, Any], suffix: str) -> str:
    return f"/repos/{plan['repository']}{suffix}"


def _quoted(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _required_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        raise GardenerError(f"GitHub did not return a valid {label} SHA")
    return value


def _remote_base_sha(client: ControllerTransport, plan: dict[str, Any], token: str) -> str | None:
    value = client.request(
        "GET",
        _repo_path(plan, f"/git/ref/heads/{_quoted(plan['base_branch'])}"),
        token=token,
    )
    return value.get("object", {}).get("sha") if isinstance(value, dict) else None


def find_existing(
    *,
    plan: dict[str, Any],
    remediation_key: str,
    token: str,
    transport: ControllerTransport | None = None,
) -> dict[str, Any] | None:
    plan = validate_pr_plan(plan)
    client = transport or RestControllerTransport()
    query = (
        f"/pulls?state=all&head=AtlasReaper311%3A{_quoted(plan['branch'])}"
        f"&base={_quoted(plan['base_branch'])}&per_page=100"
    )
    pulls = client.request("GET", _repo_path(plan, query), token=token)
    if not isinstance(pulls, list):
        raise GardenerError("GitHub did not return a pull-request list")
    matches: list[dict[str, Any]] = []
    for pull in pulls:
        if not isinstance(pull, dict):
            continue
        body = pull.get("body") or ""
        try:
            approval = parse_approval_marker(body)
        except SafetyRefusal:
            continue
        if approval.get("remediation_key") == remediation_key:
            matches.append(pull)
    if len(matches) > 1:
        raise SafetyRefusal("multiple pull requests claim the same Gardener remediation key")
    return matches[0] if matches else None


def prepare_commit(
    *,
    plan: dict[str, Any],
    token: str,
    transport: ControllerTransport | None = None,
) -> dict[str, Any]:
    """Create unreferenced Git objects after exact base and branch checks."""

    plan = validate_pr_plan(plan)
    expires = datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
    if expires < datetime.now(timezone.utc):
        raise SafetyRefusal("GitHub App PR plan has expired")
    client = transport or RestControllerTransport()
    if _remote_base_sha(client, plan, token) != plan["base_sha"]:
        raise SafetyRefusal("remote base branch changed since the reviewed plan")
    branch = client.request(
        "GET",
        _repo_path(plan, f"/git/ref/heads/{_quoted(plan['branch'])}"),
        token=token,
        allow_not_found=True,
    )
    if branch is not None:
        raise SafetyRefusal("Gardener branch exists without a matching idempotent pull request")
    base_commit = client.request(
        "GET",
        _repo_path(plan, f"/git/commits/{plan['base_sha']}"),
        token=token,
    )
    base_tree_sha = _required_sha(
        base_commit.get("tree", {}).get("sha") if isinstance(base_commit, dict) else None,
        "base tree",
    )
    entries: list[dict[str, Any]] = []
    for item in plan["files"]:
        if item["action"] == "delete":
            blob_sha = None
        else:
            blob = client.request(
                "POST",
                _repo_path(plan, "/git/blobs"),
                token=token,
                payload={"content": item["after_text"], "encoding": "utf-8"},
            )
            blob_sha = _required_sha(blob.get("sha") if isinstance(blob, dict) else None, f"blob for {item['path']}")
        entries.append({"path": item["path"], "mode": item["mode"], "type": "blob", "sha": blob_sha})
    tree = client.request(
        "POST",
        _repo_path(plan, "/git/trees"),
        token=token,
        payload={"base_tree": base_tree_sha, "tree": entries},
    )
    tree_sha = _required_sha(tree.get("sha") if isinstance(tree, dict) else None, "tree")
    commit = client.request(
        "POST",
        _repo_path(plan, "/git/commits"),
        token=token,
        payload={"message": plan["commit_message"], "tree": tree_sha, "parents": [plan["base_sha"]]},
    )
    commit_sha = _required_sha(commit.get("sha") if isinstance(commit, dict) else None, "commit")
    return {
        "schema_version": "atlas-gardener/prepared-commit/v1",
        "plan_digest": plan["plan_digest"],
        "repository": plan["repository"],
        "base_sha": plan["base_sha"],
        "branch": plan["branch"],
        "commit_sha": commit_sha,
        "tree_sha": tree_sha,
    }


def publish_prepared(
    *,
    plan: dict[str, Any],
    prepared: dict[str, Any],
    approval: dict[str, Any],
    token: str,
    ready: bool,
    transport: ControllerTransport | None = None,
) -> dict[str, Any]:
    """Publish the exact prepared commit and one pull request after final approval binding."""

    plan = validate_pr_plan(plan)
    if prepared != {
        "schema_version": "atlas-gardener/prepared-commit/v1",
        "plan_digest": plan["plan_digest"],
        "repository": plan["repository"],
        "base_sha": plan["base_sha"],
        "branch": plan["branch"],
        "commit_sha": prepared.get("commit_sha"),
        "tree_sha": prepared.get("tree_sha"),
    }:
        raise SafetyRefusal("prepared commit no longer matches the reviewed plan")
    commit_sha = _required_sha(prepared.get("commit_sha"), "prepared commit")
    _required_sha(prepared.get("tree_sha"), "prepared tree")
    if approval.get("plan_digest") != plan["plan_digest"]:
        raise SafetyRefusal("automation approval plan digest mismatch")
    if approval.get("expected_head_sha") != commit_sha:
        raise SafetyRefusal("automation approval does not bind the prepared commit")
    if approval.get("base_sha") != plan["base_sha"] or approval.get("patch_digest") != plan["patch_digest"]:
        raise SafetyRefusal("automation approval base or patch digest mismatch")
    client = transport or RestControllerTransport()
    if _remote_base_sha(client, plan, token) != plan["base_sha"]:
        raise SafetyRefusal("remote base branch changed while preparing the Gardener pull request")
    branch = client.request(
        "GET",
        _repo_path(plan, f"/git/ref/heads/{_quoted(plan['branch'])}"),
        token=token,
        allow_not_found=True,
    )
    if branch is not None:
        raise SafetyRefusal("Gardener branch appeared before publication")
    client.request(
        "POST",
        _repo_path(plan, "/git/refs"),
        token=token,
        payload={"ref": f"refs/heads/{plan['branch']}", "sha": commit_sha},
    )
    body = (
        _pr_body(plan)
        + "\n\n### Automatic controller\n\n"
        + f"Remediation key: `{approval['remediation_key']}`\n\n"
        + f"Approval: `{approval['approval_id']}`\n\n"
        + f"Controller mode: `{approval['mode']}`\n\n"
        + approval_marker(approval)
    )
    pull = client.request(
        "POST",
        _repo_path(plan, "/pulls"),
        token=token,
        payload={
            "title": plan["pr_title"],
            "body": body,
            "head": plan["branch"],
            "base": plan["base_branch"],
            "draft": not ready,
            "maintainer_can_modify": True,
        },
    )
    if not isinstance(pull, dict) or pull.get("draft") is not (not ready):
        raise GardenerError("GitHub did not confirm the requested pull-request state")
    return {
        "schema_version": "atlas-gardener/automatic-pr-result/v1",
        "repository": plan["repository"],
        "remediation_key": approval["remediation_key"],
        "approval_id": approval["approval_id"],
        "plan_digest": plan["plan_digest"],
        "base_sha": plan["base_sha"],
        "commit_sha": commit_sha,
        "branch": plan["branch"],
        "pull_request": {
            "number": pull.get("number"),
            "url": pull.get("html_url"),
            "draft": not ready,
        },
        "target_gate_requested": ready,
    }
