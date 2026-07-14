"""Hard-coded repository, path, worktree, and content safety policy."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.models import RepositoryClassification

MAX_CHANGED_FILES = 5
MAX_CHANGED_LINES = 200
FIXTURE_MARKER = ".atlas-gardener-fixture"
FORBIDDEN_LIFECYCLES = {"deprecated", "archived"}

# Approved Phase 0 classifications. Unknown real repositories fail closed.
ESTATE_CLASSIFICATIONS: dict[str, RepositoryClassification] = {
    "atlas-api-index": RepositoryClassification("production", "public", "original"),
    "atlas-api-public": RepositoryClassification("production", "public", "original"),
    "atlas-article-gen": RepositoryClassification("active", "internal", "original"),
    "atlas-badges": RepositoryClassification("active", "public", "original"),
    "atlas-blackbox": RepositoryClassification("production", "public", "original"),
    "atlas-bootstrap": RepositoryClassification("active", "internal", "original"),
    "atlas-corpus": RepositoryClassification("production", "public", "original"),
    "atlas-daily-digest": RepositoryClassification(
        "production", "internal", "original"
    ),
    "atlas-dep-audit": RepositoryClassification("active", "internal", "original"),
    "atlas-doc-viewer": RepositoryClassification("active", "public", "original"),
    "atlas-dora": RepositoryClassification("production", "public", "original"),
    "atlas-infra": RepositoryClassification("active", "internal", "original"),
    "atlas-journey-watch": RepositoryClassification("active", "internal", "original"),
    "atlas-kit-python-rag": RepositoryClassification("active", "public", "original"),
    "atlas-notify": RepositoryClassification("production", "internal", "original"),
    "atlas-postmortem": RepositoryClassification("production", "internal", "original"),
    "atlas-quota-watch": RepositoryClassification("production", "public", "original"),
    "atlas-scheduler": RepositoryClassification("production", "internal", "original"),
    "atlas-systems": RepositoryClassification("production", "public", "original"),
    "atlas-vault": RepositoryClassification("active", "internal", "original"),
    "AtlasReaper311": RepositoryClassification("active", "public", "original"),
    "deploy-watch": RepositoryClassification("production", "internal", "original"),
    "github-pulse": RepositoryClassification("production", "public", "original"),
    "ollama-rag-kit": RepositoryClassification("active", "public", "original"),
    "ramone-edge": RepositoryClassification("production", "internal", "original"),
    "ramone-memory": RepositoryClassification("active", "internal", "original"),
    "ramone-voice-trigger": RepositoryClassification(
        "production", "internal", "original"
    ),
    "simple-proxy": RepositoryClassification(
        "deprecated", "internal", "external-derived"
    ),
    "site-pulse": RepositoryClassification("production", "public", "original"),
    "specular-sentinel": RepositoryClassification("production", "internal", "original"),
    "specular-sonify": RepositoryClassification("production", "public", "original"),
    "specular-telemetry": RepositoryClassification("production", "public", "original"),
    "status": RepositoryClassification("production", "public", "original"),
    "worker-meta-kit": RepositoryClassification("active", "public", "original"),
}


def is_fixture_repository(repository: Path) -> bool:
    """Return whether a local repository is explicitly marked as a disposable fixture."""

    return (repository / FIXTURE_MARKER).is_file()


def classification_for(
    repository_name: str,
    repository: Path,
    *,
    override: RepositoryClassification | None = None,
) -> RepositoryClassification:
    """Return an approved classification or refuse an unknown real repository."""

    if override is not None:
        return override
    if repository_name in ESTATE_CLASSIFICATIONS:
        return ESTATE_CLASSIFICATIONS[repository_name]
    if is_fixture_repository(repository):
        return RepositoryClassification("active", "internal", "original")
    raise SafetyRefusal(
        f"repository classification is unknown for {repository_name}; real targets fail closed"
    )


def ensure_remediation_allowed(
    repository_name: str,
    classification: RepositoryClassification,
) -> None:
    """Refuse lifecycle and provenance classes excluded by the approved plan."""

    if repository_name == "simple-proxy":
        raise SafetyRefusal(
            "simple-proxy is completely excluded: deprecated, internal, and external-derived"
        )
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
