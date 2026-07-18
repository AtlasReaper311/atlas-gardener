"""Guarded local executor for a reviewed Atlas Dependabot rollout plan."""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from atlas_gardener.errors import GardenerError, SafetyRefusal
from atlas_gardener.safety import ensure_clean_worktree, safe_relative_path


BRANCH_NAME = "chore/dependabot-rollout"
EXCLUDED_REPOSITORIES = {
    "AtlasReaper311/atlas-cv",
    "AtlasReaper311/atlas-dep-audit",
    "AtlasReaper311/simple-proxy",
}
FORBIDDEN_TEXT = (
    chr(0x2014),
    "lever" + "aged",
    "util" + "ised",
    "ro" + "bust",
    "sea" + "mless",
)
TEXT_POLICY = re.compile("|".join(re.escape(value) for value in FORBIDDEN_TEXT), re.IGNORECASE)
MAX_ROLLOUT_FILES = 50
MAX_ROLLOUT_LINES = 2000

# Exact reviewed replacements only. Unknown action pins remain unchanged and are
# surfaced by Dependabot after the github-actions ecosystem is enabled.
ACTION_REPLACEMENTS = {
    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683": (
        "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "v7.0.0, Node 24",
    ),
    "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5": (
        "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "v7.0.0, Node 24",
    ),
    "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020": (
        "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
        "v7.0.0, Node 24",
    ),
    "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065": (
        "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        "v6.3.0, Node 24",
    ),
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02": (
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "v7.0.1, Node 24",
    ),
}


@dataclass(frozen=True)
class RepositoryChange:
    repository: str
    path: Path
    default_branch: str
    files: dict[str, str]


def _read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise GardenerError(f"JSON object required: {path}")
    return value


def validate_plan(path: Path, approved_digest: str | None = None) -> dict:
    """Validate the immutable plan envelope and optional owner-approved digest."""

    plan = _read_json(path)
    if plan.get("schema_version") != "atlas-dependabot/rollout-plan/v1":
        raise SafetyRefusal("unsupported Dependabot rollout plan schema")
    recorded = plan.get("plan_digest")
    if not isinstance(recorded, str) or not re.fullmatch(r"[0-9a-f]{64}", recorded):
        raise SafetyRefusal("plan digest is missing or malformed")
    stable = dict(plan)
    stable.pop("plan_digest", None)
    actual = hashlib.sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if actual != recorded:
        raise SafetyRefusal("plan digest does not match plan contents")
    if approved_digest is not None and recorded != approved_digest:
        raise SafetyRefusal("live plan digest differs from the owner-approved digest")
    if plan.get("github_only") or plan.get("registry_only"):
        raise SafetyRefusal("estate reconciliation contains mismatches")
    repositories = plan.get("repositories")
    if not isinstance(repositories, list):
        raise SafetyRefusal("plan repositories must be a list")
    return plan


def _replace_action_line(line: str) -> str:
    for old, (new, comment) in ACTION_REPLACEMENTS.items():
        if old not in line:
            continue
        prefix = line.split(old, 1)[0]
        return f"{prefix}{new} # {comment}\n"
    return line


def _node24_workflow_changes(repository: Path) -> dict[str, str]:
    changes: dict[str, str] = {}
    workflow_root = repository / ".github" / "workflows"
    if not workflow_root.is_dir():
        return changes
    for path in sorted(workflow_root.iterdir()):
        if path.suffix not in {".yml", ".yaml"} or not path.is_file():
            continue
        original = path.read_text(encoding="utf-8")
        updated = "".join(_replace_action_line(line) for line in original.splitlines(True))
        if updated != original:
            changes[path.relative_to(repository).as_posix()] = updated
    return changes


def _planned_files(plan_root: Path, repository: str, names: object) -> dict[str, str]:
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise SafetyRefusal(f"planned files are malformed for {repository}")
    repo_name = repository.split("/", 1)[1]
    files: dict[str, str] = {}
    for relative in names:
        source = safe_relative_path(plan_root / repo_name, relative, allow_missing=False)
        if not source.is_file():
            raise SafetyRefusal(f"planned file is missing: {source}")
        files[relative] = source.read_text(encoding="utf-8")
    return files


def build_changes(plan: dict, plan_root: Path, estate_root: Path) -> list[RepositoryChange]:
    """Build deterministic local changes without mutating a repository."""

    results: list[RepositoryChange] = []
    for entry in plan["repositories"]:
        repository = entry.get("repository")
        if not isinstance(repository, str):
            raise SafetyRefusal("plan repository name is malformed")
        if repository in EXCLUDED_REPOSITORIES:
            continue
        if entry.get("action") != "propose":
            continue
        repo_name = repository.split("/", 1)[1]
        target = estate_root / repo_name
        if not (target / ".git").exists():
            raise SafetyRefusal(f"local clone is missing: {target}")
        ensure_clean_worktree(target, fixer_id="dependabot-rollout")
        default_branch = entry.get("default_branch")
        if not isinstance(default_branch, str) or not default_branch:
            raise SafetyRefusal(f"default branch is missing for {repository}")
        files = _planned_files(plan_root, repository, entry.get("files", []))
        files.update(_node24_workflow_changes(target))
        files = {
            relative: content
            for relative, content in sorted(files.items())
            if not (target / relative).is_file()
            or (target / relative).read_text(encoding="utf-8") != content
        }
        if files:
            changed_lines = sum(content.count("\n") + 1 for content in files.values())
            if len(files) > MAX_ROLLOUT_FILES or changed_lines > MAX_ROLLOUT_LINES:
                raise SafetyRefusal(f"rollout change exceeds bounds for {repository}")
            results.append(RepositoryChange(repository, target, default_branch, files))
    return results


def render_diff(change: RepositoryChange) -> str:
    """Render the complete proposed text diff for owner review."""

    chunks: list[str] = []
    for relative, updated in change.files.items():
        path = change.path / relative
        original = path.read_text(encoding="utf-8") if path.is_file() else ""
        chunks.extend(
            difflib.unified_diff(
                original.splitlines(True),
                updated.splitlines(True),
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
            )
        )
    return "".join(chunks)


def _git(repository: Path, arguments: Sequence[str], *, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise GardenerError(f"git {' '.join(arguments)} failed: {detail}")
    return result.stdout.strip()


def _write_files(change: RepositoryChange) -> None:
    for relative, content in change.files.items():
        if TEXT_POLICY.search(content):
            raise SafetyRefusal(f"text policy violation in {change.repository}:{relative}")
        path = safe_relative_path(change.path, relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _token_git_environment(token: str) -> dict[str, str]:
    encoded = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {encoded}",
        }
    )
    return env


def verify_live_heads(changes: Sequence[RepositoryChange], token: str) -> None:
    """Refuse the entire apply run before writes when a live default branch drifted."""

    env = _token_git_environment(token)
    for change in changes:
        local_sha = _git(change.path, ["rev-parse", "HEAD"])
        ref = f"refs/heads/{change.default_branch}"
        output = _git(
            change.path,
            ["ls-remote", f"https://github.com/{change.repository}.git", ref],
            env=env,
        )
        fields = output.split()
        if len(fields) != 2 or fields[1] != ref:
            raise SafetyRefusal(f"cannot confirm live default branch for {change.repository}")
        if fields[0] != local_sha:
            raise SafetyRefusal(
                f"live default branch drifted for {change.repository}; update the clone and regenerate the plan"
            )
        rollout_ref = f"refs/heads/{BRANCH_NAME}"
        existing = _git(
            change.path,
            ["ls-remote", f"https://github.com/{change.repository}.git", rollout_ref],
            env=env,
        )
        if existing:
            raise SafetyRefusal(f"remote rollout branch already exists for {change.repository}")


def _open_draft_pr(change: RepositoryChange, token: str) -> str:
    gh = shutil.which("gh")
    if gh is None:
        raise GardenerError("gh is required to open draft pull requests")
    body = (
        "## Summary\n\n"
        "- add reviewed Dependabot version-currency coverage\n"
        "- group minor and patch updates while leaving major updates individual\n"
        "- move known GitHub Actions from Node 20 releases to reviewed Node 24 releases\n\n"
        "## Safety\n\n"
        "Auto-merge remains disabled unless repository checks, settings, and the explicit variable allow it. "
        "This pull request does not deploy, merge, or alter repository settings.\n"
    )
    env = os.environ.copy()
    env["GH_TOKEN"] = token
    result = subprocess.run(
        [
            gh,
            "pr",
            "create",
            "--repo",
            change.repository,
            "--base",
            change.default_branch,
            "--head",
            BRANCH_NAME,
            "--draft",
            "--title",
            "chore: configure Dependabot and move actions to Node 24",
            "--body",
            body,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    if result.returncode != 0:
        raise GardenerError(f"pull request creation failed: {result.stderr.strip()}")
    return result.stdout.strip()


def apply_change(change: RepositoryChange, token: str) -> str:
    """Create one local branch, commit, push, and draft PR without merging."""

    branch = _git(change.path, ["branch", "--show-current"])
    if branch != change.default_branch:
        raise SafetyRefusal(
            f"{change.repository} must be on {change.default_branch!r}; found {branch!r}"
        )
    if _git(change.path, ["branch", "--list", BRANCH_NAME]):
        raise SafetyRefusal(f"local branch already exists: {change.repository}:{BRANCH_NAME}")
    _git(change.path, ["switch", "-c", BRANCH_NAME])
    try:
        _write_files(change)
        _git(change.path, ["diff", "--check"])
        _git(change.path, ["add", "--", *change.files.keys()])
        _git(
            change.path,
            ["commit", "-m", "chore: configure Dependabot and move actions to Node 24"],
        )
        push_env = _token_git_environment(token)
        _git(
            change.path,
            [
                "push",
                "--set-upstream",
                f"https://github.com/{change.repository}.git",
                BRANCH_NAME,
            ],
            env=push_env,
        )
        return _open_draft_pr(change, token)
    except Exception:
        raise


def execute_rollout(
    *,
    plan_path: Path,
    plan_root: Path,
    estate_root: Path,
    apply: bool,
    approved_digest: str | None,
    confirm: Callable[[str], str] = input,
) -> dict:
    """Dry-run or execute the reviewed plan with one confirmation per repository."""

    plan = validate_plan(plan_path, approved_digest if apply else None)
    changes = build_changes(plan, plan_root, estate_root)
    token = os.environ.get("ATLAS_DEPENDABOT_WRITE_TOKEN", "") if apply else ""
    if apply and not token:
        raise SafetyRefusal("ATLAS_DEPENDABOT_WRITE_TOKEN is required for --apply")
    if apply:
        verify_live_heads(changes, token)
    results: list[dict[str, str]] = []
    for change in changes:
        print(f"\n## {change.repository}")
        print("Files: " + ", ".join(change.files))
        print(render_diff(change), end="")
        if not apply:
            results.append({"repository": change.repository, "result": "planned"})
            continue
        answer = confirm(f"Apply {change.repository}? [y/N] ").strip().lower()
        if answer != "y":
            results.append({"repository": change.repository, "result": "declined"})
            continue
        url = apply_change(change, token)
        print(f"Draft pull request: {url}")
        results.append({"repository": change.repository, "result": "opened", "url": url})
    return {
        "schema_version": "atlas-gardener/dependabot-rollout-result/v1",
        "plan_digest": plan["plan_digest"],
        "mode": "apply" if apply else "dry-run",
        "repositories": results,
    }
