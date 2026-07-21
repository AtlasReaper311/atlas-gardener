"""Repository, path, worktree, and content safety policy."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.models import RepositoryClassification

MAX_CHANGED_FILES = 5
MAX_CHANGED_LINES = 200
FIXTURE_MARKER = ".atlas-gardener-fixture"
FORBIDDEN_LIFECYCLES = {"deprecated", "archived"}
PRIVATE_GOVERNANCE = Path(".atlas/governance.json")
PUBLIC_REGISTRY = Path("policy/estate-registry.json")
ATLAS_OWNER = "AtlasReaper311"


def is_fixture_repository(repository: Path) -> bool:
    """Return whether a local repository is explicitly marked as a disposable fixture."""

    return (repository / FIXTURE_MARKER).is_file()


def _read_json_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise SafetyRefusal(f"cannot read valid {label}") from None
    if not isinstance(value, dict):
        raise SafetyRefusal(f"{label} must be a JSON object")
    return value


def _private_source_classification(
    repository_name: str,
    repository: Path,
) -> RepositoryClassification | None:
    governance_path = repository / PRIVATE_GOVERNANCE
    if not governance_path.is_file():
        return None

    governance = _read_json_object(
        governance_path,
        label="source-owned private governance",
    )
    expected_repository = f"{ATLAS_OWNER}/{repository_name}"
    required = {
        "schema_version",
        "repository",
        "visibility",
        "estate_membership",
        "lifecycle",
        "provenance",
        "public_projection",
    }
    missing = sorted(required - set(governance))
    if missing:
        raise SafetyRefusal(
            "source-owned private governance is missing required classification fields"
        )
    if governance.get("schema_version") != "atlas-repository-governance/v1":
        raise SafetyRefusal("unsupported source-owned private governance schema")
    if governance.get("repository") != expected_repository:
        raise SafetyRefusal("source-owned private governance repository identity mismatch")
    if governance.get("visibility") != "private":
        raise SafetyRefusal("source-owned private governance must declare visibility=private")
    if governance.get("estate_membership") != "internal":
        raise SafetyRefusal(
            "source-owned private governance must declare estate_membership=internal"
        )
    if governance.get("public_projection") is not False:
        raise SafetyRefusal(
            "source-owned private governance must declare public_projection=false"
        )

    lifecycle = governance.get("lifecycle")
    provenance = governance.get("provenance")
    if not isinstance(lifecycle, str) or not lifecycle:
        raise SafetyRefusal("source-owned private governance lifecycle is malformed")
    if not isinstance(provenance, str) or not provenance:
        raise SafetyRefusal("source-owned private governance provenance is malformed")
    return RepositoryClassification(lifecycle, "internal", provenance)


def _atlas_infra_root(repository: Path) -> Path | None:
    configured = os.environ.get("ATLAS_GARDENER_INFRA_ROOT", "").strip()
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).expanduser())
    if repository.name == "atlas-infra":
        candidates.append(repository)
    candidates.append(repository.parent / "atlas-infra")

    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if (resolved / PUBLIC_REGISTRY).is_file():
            return resolved
    return None


def _public_runtime_classification(
    repository_name: str,
    repository: Path,
) -> RepositoryClassification | None:
    infra_root = _atlas_infra_root(repository)
    if infra_root is None:
        return None

    registry = _read_json_object(
        infra_root / PUBLIC_REGISTRY,
        label="public runtime registry",
    )
    repositories = registry.get("repositories")
    if not isinstance(repositories, list):
        raise SafetyRefusal("public runtime registry repositories collection is malformed")

    expected_repository = f"{ATLAS_OWNER}/{repository_name}"
    matches = [
        entry
        for entry in repositories
        if isinstance(entry, dict) and entry.get("repository") == expected_repository
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise SafetyRefusal("public runtime registry contains duplicate repository identity")

    entry = matches[0]
    lifecycle = entry.get("lifecycle")
    scope = entry.get("scope")
    provenance = entry.get("provenance")
    if not all(isinstance(value, str) and value for value in (lifecycle, scope, provenance)):
        raise SafetyRefusal("public runtime registry classification is malformed")
    return RepositoryClassification(lifecycle, scope, provenance)


def classification_for(
    repository_name: str,
    repository: Path,
    *,
    override: RepositoryClassification | None = None,
) -> RepositoryClassification:
    """Resolve current classification from source-owned or public authoritative state."""

    if override is not None:
        return override
    if is_fixture_repository(repository):
        return RepositoryClassification("active", "internal", "original")

    private = _private_source_classification(repository_name, repository)
    if private is not None:
        return private

    public = _public_runtime_classification(repository_name, repository)
    if public is not None:
        return public

    raise SafetyRefusal(
        "repository classification is unavailable from source-owned private governance "
        "or the authoritative public runtime registry; real targets fail closed"
    )


def ensure_remediation_allowed(
    repository_name: str,
    classification: RepositoryClassification,
) -> None:
    """Refuse lifecycle and provenance classes excluded by the approved plan."""

    del repository_name
    if classification.lifecycle in FORBIDDEN_LIFECYCLES:
        raise SafetyRefusal(
            f"repository lifecycle {classification.lifecycle!r} is excluded from remediation"
        )
    if classification.provenance == "external-derived":
        raise SafetyRefusal(
            "external-derived repositories are excluded from remediation"
        )


def safe_relative_path(
    repository: Path, relative: str, *, allow_missing: bool = True
) -> Path:
    """Resolve a repository-relative path and reject traversal or escaping symlinks."""

    if not relative or os.path.isabs(relative):
        raise SafetyRefusal(f"path must be repository-relative: {relative!r}")
    components = Path(relative).parts
    if ".." in components:
        raise SafetyRefusal(f"path traversal is forbidden: {relative!r}")
    root = repository.resolve(strict=True)
    candidate = repository / relative
    try:
        resolved = candidate.resolve(strict=not allow_missing)
    except FileNotFoundError as error:
        raise SafetyRefusal(f"path does not exist: {relative}") from error
    if resolved != root and root not in resolved.parents:
        raise SafetyRefusal(
            f"path or symlink escapes the target repository: {relative}"
        )
    return candidate


def read_text_file(repository: Path, relative: str) -> tuple[Path, bytes, str]:
    """Read a safe UTF-8 text file and refuse binary content."""

    path = safe_relative_path(repository, relative, allow_missing=False)
    if path.is_symlink():
        resolved = path.resolve(strict=True)
        root = repository.resolve()
        if resolved != root and root not in resolved.parents:
            raise SafetyRefusal(f"symlink escapes the target repository: {relative}")
    data = path.read_bytes()
    if b"\x00" in data:
        raise SafetyRefusal(
            f"binary files are not eligible for remediation: {relative}"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SafetyRefusal(
            f"non-UTF-8 files are not eligible for remediation: {relative}"
        ) from error
    return path, data, text


def git_status_paths(repository: Path) -> list[str]:
    """Return worktree changes using a fixed Git invocation, never Finding content."""

    if not (repository / ".git").exists():
        return []
    result = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain=v1", "-z"],
        check=False,
        capture_output=True,
        text=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise SafetyRefusal("cannot verify target worktree cleanliness")
    entries = [
        entry for entry in result.stdout.decode("utf-8", "strict").split("\0") if entry
    ]
    paths: list[str] = []
    for entry in entries:
        path = entry[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        paths.append(path)
    return sorted(paths)


def ensure_clean_worktree(repository: Path, *, fixer_id: str) -> None:
    """Refuse dirty real worktrees, with the narrow metadata-only exception."""

    if is_fixture_repository(repository):
        return
    if not (repository / ".git").exists():
        raise SafetyRefusal("a real target must be a Git worktree")
    dirty = git_status_paths(repository)
    if not dirty:
        return
    if fixer_id == "macos-metadata-ignore" and all(
        Path(path).name == ".DS_Store" for path in dirty
    ):
        return
    raise SafetyRefusal("dirty real worktree refused: " + ", ".join(dirty))


def current_branch(repository: Path) -> str | None:
    """Return the current local branch through a fixed, read-only Git call."""

    if not (repository / ".git").exists():
        return None
    result = subprocess.run(
        ["git", "-C", str(repository), "branch", "--show-current"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise SafetyRefusal("cannot determine target branch")
    return result.stdout.strip() or None


def ensure_apply_target(repository: Path, *, allow_local_target: bool) -> None:
    """Allow writes only to fixtures or explicitly approved local non-main branches."""

    fixture = is_fixture_repository(repository)
    if not fixture and not allow_local_target:
        raise SafetyRefusal(
            "apply is local-fixture-only unless --allow-local-target is explicitly passed"
        )
    branch = current_branch(repository)
    if branch == "main":
        raise SafetyRefusal("direct edits on the main branch are forbidden")
    if not fixture and branch is None:
        raise SafetyRefusal(
            "a real local apply target must be on a named non-main branch"
        )
