#!/usr/bin/env python3
"""Build exact target-file evidence from checked-out Gardener PR commits."""
from __future__ import annotations

import argparse
import difflib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 1024 * 1024


class EvidenceError(RuntimeError):
    """Raised when exact target evidence cannot be built safely."""


def _run_git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise EvidenceError(detail[:240])
    return result.stdout.strip()


def _load_pr(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read pull request JSON: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError("pull request JSON must be an object")
    return value


def _commit(root: Path) -> str:
    value = _run_git(root, "rev-parse", "HEAD")
    if len(value) != 40:
        raise EvidenceError("checked-out target commit is invalid")
    return value


def _entry(root: Path, commit: str) -> tuple[str, str] | None:
    output = _run_git(root, "ls-tree", commit, "--", ".gitignore")
    if not output:
        return None
    fields = output.split(None, 3)
    if len(fields) != 4 or fields[3] != ".gitignore":
        raise EvidenceError("target .gitignore tree entry is invalid")
    mode, object_type, object_sha, _ = fields
    if mode != "100644" or object_type != "blob" or len(object_sha) != 40:
        raise EvidenceError("target .gitignore must be one regular 100644 blob")
    return mode, object_sha


def _read_file(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise EvidenceError(f"{label} is missing") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"{label} is not a regular file")
    if metadata.st_size > MAX_FILE_BYTES:
        raise EvidenceError(f"{label} exceeds the one MiB evidence bound")
    try:
        return path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read {label}: {error}") from error


def _decode_lines(value: bytes, label: str) -> list[str]:
    try:
        return value.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise EvidenceError(f"{label} is not UTF-8 text") from error


def build_evidence(
    *,
    pr: dict[str, Any],
    base_root: Path,
    head_root: Path,
    files_output: Path,
    base_output: Path,
    head_output: Path,
) -> str:
    base_sha = str(pr.get("baseRefOid") or "")
    head_sha = str(pr.get("headRefOid") or "")
    if _commit(base_root) != base_sha:
        raise EvidenceError("checked-out base commit does not match the pull request")
    if _commit(head_root) != head_sha:
        raise EvidenceError("checked-out head commit does not match the pull request")

    base_entry = _entry(base_root, base_sha)
    head_entry = _entry(head_root, head_sha)
    if head_entry is None:
        raise EvidenceError("pull request head .gitignore is missing")

    head_bytes = _read_file(head_root / ".gitignore", "head .gitignore")
    head_output.write_bytes(head_bytes)

    base_bytes: bytes | None = None
    base_file_value = ""
    if base_entry is not None:
        base_bytes = _read_file(base_root / ".gitignore", "base .gitignore")
        base_output.write_bytes(base_bytes)
        base_file_value = str(base_output)
    elif base_output.exists():
        base_output.unlink()

    before_lines = _decode_lines(base_bytes or b"", "base .gitignore")
    after_lines = _decode_lines(head_bytes, "head .gitignore")
    patch_lines = list(
        difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile="a/.gitignore",
            tofile="b/.gitignore",
            lineterm="",
        )
    )
    if not patch_lines:
        raise EvidenceError("pull request .gitignore has no content change")

    additions = sum(
        1
        for line in patch_lines
        if line.startswith("+") and not line.startswith("+++")
    )
    deletions = sum(
        1
        for line in patch_lines
        if line.startswith("-") and not line.startswith("---")
    )
    files = [
        {
            "filename": ".gitignore",
            "status": "modified" if base_entry is not None else "added",
            "additions": additions,
            "deletions": deletions,
            "changes": additions + deletions,
            "patch": "\n".join(patch_lines),
        }
    ]
    files_output.write_text(
        json.dumps(files, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return base_file_value


def _write_refusal(path: Path, *, pr: dict[str, Any], reason: str) -> None:
    result = {
        "schema_version": "atlas-gardener/automerge-gate-result/v1",
        "eligible": False,
        "state": "refused",
        "reason": reason[:240],
        "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
        "pull_request": pr.get("number"),
        "head_sha": pr.get("headRefOid"),
        "required_checks": [],
    }
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr", required=True, type=Path)
    parser.add_argument("--base-root", required=True, type=Path)
    parser.add_argument("--head-root", required=True, type=Path)
    parser.add_argument("--files-output", required=True, type=Path)
    parser.add_argument("--base-output", required=True, type=Path)
    parser.add_argument("--head-output", required=True, type=Path)
    parser.add_argument("--gate-result-output", required=True, type=Path)
    args = parser.parse_args()

    pr: dict[str, Any] = {}
    try:
        pr = _load_pr(args.pr)
        base_file = build_evidence(
            pr=pr,
            base_root=args.base_root,
            head_root=args.head_root,
            files_output=args.files_output,
            base_output=args.base_output,
            head_output=args.head_output,
        )
    except (EvidenceError, OSError, ValueError) as error:
        _write_refusal(args.gate_result_output, pr=pr, reason=str(error))
        print(f"Gardener evidence capture refused: {error}", file=sys.stderr)
        return 2

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as handle:
            handle.write(f"base_file={base_file}\n")
    print(
        json.dumps(
            {
                "base_file": base_file,
                "files_output": str(args.files_output),
                "head_file": str(args.head_output),
                "state": "captured",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
