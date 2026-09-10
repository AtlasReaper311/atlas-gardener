"""The five allowlisted, deterministic Atlas Gardener MVP fixers."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable

from atlas_gardener.changes import ChangePlan, FileChange
from atlas_gardener.errors import ContractError, SafetyRefusal
from atlas_gardener.safety import read_text_file, safe_relative_path

FIXER_VERSION = "0.1.0"
WORKFLOW_SUFFIXES = {".yml", ".yaml"}

RULE_FIXERS: dict[str, str] = {
    "action-pin-plan": "action-pin-plan",
    "ds-store-present": "macos-metadata-ignore",
    "macos-metadata-ignore": "macos-metadata-ignore",
    "missing-action-pin": "action-pin-plan",
    "missing-workflow-permissions": "workflow-permissions",
    "missing-workflow-timeout": "workflow-timeout",
    "python-cache-ignore": "python-cache-ignore",
    "python-cache-present": "python-cache-ignore",
    "unpinned-action": "action-pin-plan",
    "workflow-permissions": "workflow-permissions",
    "workflow-timeout": "workflow-timeout",
}


def fixer_for_finding(finding: dict[str, Any]) -> str:
    """Map only explicit, allowlisted rule identifiers to a fixer."""

    fixer_id = RULE_FIXERS.get(finding["rule_id"])
    if fixer_id is None:
        raise SafetyRefusal(
            f"Finding rule {finding['rule_id']!r} has no allowlisted deterministic fixer"
        )
    return fixer_id


def build_plan(
    fixer_id: str,
    repository: Path,
    *,
    finding: dict[str, Any] | None = None,
    files: list[str] | None = None,
    pins_file: Path | None = None,
) -> ChangePlan:
    """Build one bounded plan for one fixer without mutating the repository."""

    builders: dict[str, Callable[..., ChangePlan]] = {
        "action-pin-plan": _action_pin_plan,
        "macos-metadata-ignore": _macos_metadata_plan,
        "python-cache-ignore": _python_cache_plan,
        "workflow-permissions": _workflow_permissions_plan,
        "workflow-timeout": _workflow_timeout_plan,
    }
    builder = builders.get(fixer_id)
    if builder is None:
        raise SafetyRefusal(f"proposal fixer is not allowlisted: {fixer_id}")
    targets = _target_workflows(repository, finding=finding, files=files)
    if fixer_id == "action-pin-plan":
        return builder(repository, targets=targets, pins_file=pins_file)
    if fixer_id in {"workflow-permissions", "workflow-timeout"}:
        return builder(repository, targets=targets)
    return builder(repository)


def _target_workflows(
    repository: Path,
    *,
    finding: dict[str, Any] | None,
    files: list[str] | None,
) -> list[str]:
    if files is not None:
        candidates = [path for path in files if path != ".gitignore"]
    elif finding is not None:
        candidates = [_location_path(finding["location"])]
    else:
        candidates = []
    result: list[str] = []
    for candidate in candidates:
        path = Path(candidate)
        if (
            len(path.parts) < 3
            or path.parts[0:2] != (".github", "workflows")
            or path.suffix not in WORKFLOW_SUFFIXES
        ):
            continue
        safe_relative_path(repository, candidate, allow_missing=False)
        result.append(candidate)
    return sorted(set(result))


def _location_path(location: str) -> str:
    match = re.fullmatch(r"(.+):[1-9][0-9]*", location)
    return match.group(1) if match else location


def _iter_repository_files(repository: Path) -> list[Path]:
    result: list[Path] = []
    for root, directories, files in os.walk(repository, followlinks=False):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory != ".git" and not (Path(root) / directory).is_symlink()
        )
        for filename in sorted(files):
            result.append(Path(root) / filename)
    return result


def _gitignore_change(repository: Path, rules: tuple[str, ...]) -> FileChange | None:
    relative = ".gitignore"
    path = safe_relative_path(repository, relative, allow_missing=True)
    before = path.read_bytes() if path.exists() else None
    if before is not None:
        if b"\x00" in before:
            raise SafetyRefusal("binary .gitignore is not eligible for remediation")
        try:
            text = before.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SafetyRefusal(
                "non-UTF-8 .gitignore is not eligible for remediation"
            ) from error
    else:
        text = ""
    active_rules = {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    missing = [rule for rule in rules if rule not in active_rules]
    if not missing:
        return None
    updated = text
    if updated and not updated.endswith("\n"):
        updated += "\n"
    if updated and not updated.endswith("\n\n"):
        updated += "\n"
    updated += "\n".join(missing) + "\n"
    return FileChange(relative, before, updated.encode("utf-8"))


def _macos_metadata_plan(repository: Path) -> ChangePlan:
    changes: list[FileChange] = []
    ignore = _gitignore_change(repository, (".DS_Store",))
    if ignore is not None:
        changes.append(ignore)
    for path in _iter_repository_files(repository):
        if path.name != ".DS_Store":
            continue
        relative = path.relative_to(repository).as_posix()
        safe_relative_path(repository, relative, allow_missing=False)
        changes.append(
            FileChange(relative, path.read_bytes(), None, allow_binary_delete=True)
        )
    return ChangePlan.create("macos-metadata-ignore", changes)


def _python_cache_plan(repository: Path) -> ChangePlan:
    changes: list[FileChange] = []
    ignore = _gitignore_change(repository, ("__pycache__/", "*.py[cod]"))
    if ignore is not None:
        changes.append(ignore)
    for path in _iter_repository_files(repository):
        relative_path = path.relative_to(repository)
        is_cache = "__pycache__" in relative_path.parts or path.suffix in {
            ".pyc",
            ".pyo",
            ".pyd",
        }
        if not is_cache:
            continue
        relative = relative_path.as_posix()
        safe_relative_path(repository, relative, allow_missing=False)
        changes.append(
            FileChange(relative, path.read_bytes(), None, allow_binary_delete=True)
        )
    return ChangePlan.create("python-cache-ignore", changes)


def _require_workflow_targets(targets: list[str]) -> None:
    if not targets:
        raise SafetyRefusal(
            "Finding does not identify an eligible .github/workflows YAML file"
        )


def _workflow_timeout_plan(repository: Path, *, targets: list[str]) -> ChangePlan:
    _require_workflow_targets(targets)
    changes: list[FileChange] = []
    for relative in targets:
        _, before, text = read_text_file(repository, relative)
        updated = _add_missing_timeouts(text, relative)
        if updated != text:
            changes.append(FileChange(relative, before, updated.encode("utf-8")))
    return ChangePlan.create("workflow-timeout", changes)


def _add_missing_timeouts(text: str, relative: str) -> str:
    lines = text.splitlines(keepends=True)
    jobs_indexes = [
        index
        for index, line in enumerate(lines)
        if re.fullmatch(r"jobs:\s*(?:#.*)?\n?", line)
    ]
    if len(jobs_indexes) != 1:
        raise SafetyRefusal(
            f"workflow must contain one simple top-level jobs block: {relative}"
        )
    jobs_start = jobs_indexes[0]
    jobs_end = len(lines)
    for index in range(jobs_start + 1, len(lines)):
        line = lines[index]
        if line.strip() and not line.lstrip().startswith("#") and _indent(line) == 0:
            jobs_end = index
            break
    job_starts = [
        index
        for index in range(jobs_start + 1, jobs_end)
        if re.fullmatch(r" {2}[A-Za-z0-9_-]+:\s*(?:#.*)?\n?", lines[index])
    ]
    if not job_starts:
        raise SafetyRefusal(f"workflow has no safely parseable jobs: {relative}")

    insertions: list[int] = []
    for position, start in enumerate(job_starts):
        end = job_starts[position + 1] if position + 1 < len(job_starts) else jobs_end
        body = lines[start + 1 : end]
        if any(re.match(r" {4}timeout-minutes:\s*", line) for line in body):
            continue
        if any(re.match(r" {4}uses:\s*", line) for line in body):
            raise SafetyRefusal(
                f"reusable workflow job without timeout cannot be changed safely: {relative}"
            )
        runs_on = [
            start + 1 + offset
            for offset, line in enumerate(body)
            if re.match(r" {4}runs-on:\s*\S", line)
        ]
        if len(runs_on) != 1:
            raise SafetyRefusal(
                f"job without one simple runs-on value cannot receive a timeout: {relative}"
            )
        insertions.append(runs_on[0] + 1)
    for index in reversed(insertions):
        lines.insert(index, "    timeout-minutes: 15\n")
    return "".join(lines)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _workflow_permissions_plan(repository: Path, *, targets: list[str]) -> ChangePlan:
    _require_workflow_targets(targets)
    changes: list[FileChange] = []
    for relative in targets:
        _, before, text = read_text_file(repository, relative)
        updated = _add_read_permissions(text, relative)
        if updated != text:
            changes.append(FileChange(relative, before, updated.encode("utf-8")))
    return ChangePlan.create("workflow-permissions", changes)


def _add_read_permissions(text: str, relative: str) -> str:
    if re.search(r"(?m)^permissions:\s*", text):
        raise SafetyRefusal(
            f"workflow already declares top-level permissions: {relative}"
        )
    if re.search(r"(?m)^\s+permissions:\s*", text):
        raise SafetyRefusal(f"job-level permissions require human review: {relative}")
    _ensure_read_only_workflow(text, relative)
    lines = text.splitlines(keepends=True)
    name_indexes = [
        index for index, line in enumerate(lines) if re.match(r"^name:\s*\S", line)
    ]
    if len(name_indexes) > 1:
        raise SafetyRefusal(f"workflow has multiple top-level names: {relative}")
    insert_at = name_indexes[0] + 1 if name_indexes else 0
    block = ["\n", "permissions:\n", "  contents: read\n"]
    if insert_at < len(lines) and lines[insert_at].strip():
        block.append("\n")
    lines[insert_at:insert_at] = block
    return "".join(lines)


def _ensure_read_only_workflow(text: str, relative: str) -> None:
    lower = text.lower()
    forbidden_patterns = {
        "deployment": r"\bdeploy(?:ment|ments|ing)?\b|wrangler\s+deploy",
        "release": r"\brelease(?:s|d|ing)?\b|softprops/action-gh-release",
        "package publishing": r"\bpublish(?:ing|ed)?\b|docker\s+push|twine\s+upload",
        "issue or pull request writing": r"\bgh\s+(?:issue|pr)\b|issues:\s*write|pull-requests:\s*write",
        "environment mutation": r"(?m)^\s*environment:\s*|environments?:\s*write",
        "arbitrary network access": r"\b(?:curl|wget)\b|api\.github\.com",
        "secret access": r"\$\{\{\s*secrets\.",
        "privileged pull request trigger": r"\bpull_request_target\b",
    }
    for reason, pattern in forbidden_patterns.items():
        if re.search(pattern, lower):
            raise SafetyRefusal(
                f"workflow permissions refused due to {reason}: {relative}"
            )
    allowed_actions = {
        "actions/cache",
        "actions/checkout",
        "actions/download-artifact",
        "actions/setup-node",
        "actions/setup-python",
        "actions/upload-artifact",
    }
    for action in re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s#@]+)@[^\s#]+", text):
        if action.startswith("./"):
            continue
        if action.lower() not in allowed_actions:
            raise SafetyRefusal(
                f"workflow action {action!r} is not in the read-only permissions allowlist"
            )


def _load_pins(path: Path | None) -> dict[str, str]:
    if path is None:
        raise SafetyRefusal(
            "action SHA resolution is deferred: no approved local pins file was supplied"
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(
            f"cannot read approved local pins file {path}: {error}"
        ) from error
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != "atlas-gardener/action-pins/v1"
    ):
        raise ContractError("pins file must use atlas-gardener/action-pins/v1")
    pins = payload.get("pins")
    if not isinstance(pins, dict) or not pins:
        raise ContractError("pins file must contain a non-empty pins object")
    validated: dict[str, str] = {}
    for reference, sha in pins.items():
        if not isinstance(reference, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+", reference
        ):
            raise ContractError(f"invalid action pin reference: {reference!r}")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ContractError(
                f"pin for {reference} must be a full lowercase 40-character SHA"
            )
        validated[reference] = sha
    return validated


def _action_pin_plan(
    repository: Path,
    *,
    targets: list[str],
    pins_file: Path | None,
) -> ChangePlan:
    _require_workflow_targets(targets)
    pins = _load_pins(pins_file)
    changes: list[FileChange] = []
    missing: set[str] = set()
    pattern = re.compile(
        r"^(?P<prefix>\s*-?\s*uses:\s*)(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
        r"@(?P<ref>[^\s#]+)(?:\s*#.*)?(?P<newline>\n?)$"
    )
    for relative in targets:
        _, before, text = read_text_file(repository, relative)
        lines = text.splitlines(keepends=True)
        changed = False
        for index, line in enumerate(lines):
            match = pattern.match(line)
            if match is None:
                continue
            ref = match.group("ref")
            if re.fullmatch(r"[0-9a-f]{40}", ref):
                continue
            reference = f"{match.group('action')}@{ref}"
            sha = pins.get(reference)
            if sha is None:
                missing.add(reference)
                continue
            lines[index] = (
                f"{match.group('prefix')}{match.group('action')}@{sha} # {ref}"
                f"{match.group('newline')}"
            )
            changed = True
        if changed:
            changes.append(FileChange(relative, before, "".join(lines).encode("utf-8")))
    if missing:
        raise SafetyRefusal(
            "network SHA resolution is deferred; approved local pins are missing for: "
            + ", ".join(sorted(missing))
        )
    return ChangePlan.create("action-pin-plan", changes)
