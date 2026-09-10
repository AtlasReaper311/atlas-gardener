"""Deterministic ADR-0015 dependency and container remediation fixers."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from atlas_gardener.changes import ChangePlan, FileChange
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.safety import read_text_file, safe_relative_path

_SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_REQUIREMENT_RE = re.compile(
    r"^(?P<leading>\s*)(?P<name>[A-Za-z0-9_.-]+)(?P<extras>\[[^]]+\])?"
    r"(?P<operator>\s*==\s*)(?P<version>[^\s;#]+)(?P<suffix>.*?)(?P<newline>\r?\n)?$"
)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _semver(value: Any) -> tuple[int, int, int]:
    match = _SEMVER_RE.fullmatch(str(value or ""))
    if match is None:
        raise SafetyRefusal("dependency candidate requires a strict three-part version")
    return tuple(int(part) for part in match.groups())


def _normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _candidate(candidate: dict[str, Any] | None, kind: str) -> dict[str, Any]:
    if not isinstance(candidate, dict) or candidate.get("kind") != kind:
        raise SafetyRefusal(f"{kind} fixer requires matching structured remediation input")
    return candidate


def _dependency_candidate(candidate: dict[str, Any] | None, ecosystem: str) -> dict[str, Any]:
    value = _candidate(candidate, "dependency-update")
    if value.get("ecosystem") != ecosystem or value.get("direct") is not True:
        raise SafetyRefusal("dependency candidate ecosystem or direct-dependency proof mismatches fixer")
    current = _semver(value.get("current_version"))
    target = _semver(value.get("target_version"))
    if target <= current or target[0] != current[0]:
        raise SafetyRefusal("dependency candidate must be a strictly newer same-major version")
    expected_class = "patch" if target[:2] == current[:2] else "minor"
    if value.get("update_class") != expected_class:
        raise SafetyRefusal("dependency candidate update class does not match its versions")
    identifiers = value.get("vulnerability_ids")
    if not isinstance(identifiers, list) or not identifiers:
        raise SafetyRefusal("dependency candidate must identify at least one vulnerability")
    return value


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SafetyRefusal(f"cannot read deterministic {label}") from error
    if not isinstance(value, dict):
        raise SafetyRefusal(f"{label} must be a JSON object")
    return value


def python_security_plan(repository: Path, candidate: dict[str, Any] | None) -> ChangePlan:
    value = _dependency_candidate(candidate, "PyPI")
    relative = str(value.get("source_file") or "")
    if Path(relative).name != "requirements.txt":
        raise SafetyRefusal("Python security fixer is limited to requirements.txt")
    _, before, text = read_text_file(repository, relative)
    dependency = str(value["dependency"])
    current = str(value["current_version"])
    target = str(value["target_version"])
    lines = text.splitlines(keepends=True)
    matches: list[int] = []
    for index, line in enumerate(lines):
        match = _REQUIREMENT_RE.fullmatch(line)
        if match is None:
            continue
        if _normalized_name(match.group("name")) != _normalized_name(dependency):
            continue
        if match.group("version") != current:
            continue
        matches.append(index)
    if len(matches) != 1:
        raise SafetyRefusal("requirements dependency preimage is absent or ambiguous")
    index = matches[0]
    match = _REQUIREMENT_RE.fullmatch(lines[index])
    assert match is not None
    lines[index] = (
        match.group("leading")
        + match.group("name")
        + (match.group("extras") or "")
        + match.group("operator")
        + target
        + match.group("suffix")
        + (match.group("newline") or "")
    )
    after = "".join(lines).encode("utf-8")
    return ChangePlan.create(
        "python-security-pin",
        [FileChange(relative, before, after)],
    )


def container_digest_plan(repository: Path, candidate: dict[str, Any] | None) -> ChangePlan:
    value = _candidate(candidate, "container-digest-pin")
    relative = str(value.get("source_file") or "")
    if not re.fullmatch(r"(?:[A-Za-z0-9._-]+/)*Dockerfile[A-Za-z0-9._-]*", relative):
        raise SafetyRefusal("container digest fixer is limited to Dockerfile paths")
    current = str(value.get("current_reference") or "")
    digest = str(value.get("target_digest") or "")
    if not current or "@" in current or not _DIGEST_RE.fullmatch(digest):
        raise SafetyRefusal("container digest candidate reference or digest is malformed")
    _, before, text = read_text_file(repository, relative)
    lines = text.splitlines(keepends=True)
    matches: list[tuple[int, re.Match[str]]] = []
    pattern = re.compile(
        rf"^(?P<prefix>\s*FROM\s+){re.escape(current)}(?P<trailing>\s*)(?P<newline>\r?\n)?$",
        re.IGNORECASE,
    )
    for index, line in enumerate(lines):
        match = pattern.fullmatch(line)
        if match is not None:
            matches.append((index, match))
    if len(matches) != 1:
        raise SafetyRefusal("Dockerfile base-image preimage is absent, staged, or ambiguous")
    index, match = matches[0]
    lines[index] = (
        match.group("prefix")
        + current
        + "@"
        + digest
        + match.group("trailing")
        + (match.group("newline") or "")
    )
    return ChangePlan.create(
        "container-digest-pin",
        [FileChange(relative, before, "".join(lines).encode("utf-8"))],
    )


def _npm_direct_declaration(package: dict[str, Any], dependency: str, current: str) -> str:
    matches: list[str] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        values = package.get(section)
        if isinstance(values, dict) and dependency in values:
            matches.append(str(values[dependency]))
    if len(matches) != 1:
        raise SafetyRefusal("npm dependency is absent, transitive, or ambiguously declared")
    spec = matches[0]
    if spec not in {current, f"^{current}", f"~{current}"}:
        raise SafetyRefusal("npm direct dependency uses an unsupported version specification")
    return spec


def _replace_json_dependency_line(text: str, dependency: str, current_spec: str, target: str) -> str:
    pattern = re.compile(
        rf'^(?P<prefix>\s*"{re.escape(dependency)}"\s*:\s*")'
        rf'{re.escape(current_spec)}(?P<suffix>"\s*,?\s*)(?P<newline>\r?\n)?$'
    )
    lines = text.splitlines(keepends=True)
    matches = [(index, pattern.fullmatch(line)) for index, line in enumerate(lines)]
    matches = [(index, match) for index, match in matches if match is not None]
    if len(matches) != 1:
        raise SafetyRefusal("npm package.json declaration is not uniquely line-addressable")
    index, match = matches[0]
    assert match is not None
    lines[index] = (
        match.group("prefix")
        + target
        + match.group("suffix")
        + (match.group("newline") or "")
    )
    return "".join(lines)


def _npm_environment(home: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_ignore_scripts": "true",
        "npm_config_package_lock": "true",
        "npm_config_registry": "https://registry.npmjs.org/",
        "npm_config_update_notifier": "false",
    }


def npm_security_plan(repository: Path, candidate: dict[str, Any] | None) -> ChangePlan:
    value = _dependency_candidate(candidate, "npm")
    package_relative = str(value.get("source_file") or "")
    if Path(package_relative).name != "package.json":
        raise SafetyRefusal("npm security fixer is limited to package.json plus package-lock.json")
    package_path, package_before, package_text = read_text_file(repository, package_relative)
    lock_relative = (Path(package_relative).parent / "package-lock.json").as_posix()
    _, lock_before, _ = read_text_file(repository, lock_relative)
    package = _read_json(package_path, "package.json")
    dependency = str(value["dependency"])
    current = str(value["current_version"])
    target = str(value["target_version"])
    current_spec = _npm_direct_declaration(package, dependency, current)
    package_after_text = _replace_json_dependency_line(
        package_text, dependency, current_spec, target
    )
    package_after = package_after_text.encode("utf-8")

    lock = json.loads(lock_before.decode("utf-8"))
    packages = lock.get("packages") if isinstance(lock, dict) else None
    current_entry = packages.get(f"node_modules/{dependency}") if isinstance(packages, dict) else None
    if not isinstance(current_entry, dict) or str(current_entry.get("version") or "") != current:
        raise SafetyRefusal("npm lockfile preimage does not match the audited direct version")

    with tempfile.TemporaryDirectory(prefix="atlas-gardener-npm-") as directory:
        root = Path(directory)
        (root / "package.json").write_bytes(package_after)
        (root / "package-lock.json").write_bytes(lock_before)
        try:
            completed = subprocess.run(
                [
                    "npm",
                    "install",
                    "--package-lock-only",
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
                env=_npm_environment(root),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            raise SafetyRefusal("npm lockfile regeneration is unavailable or timed out") from error
        if completed.returncode != 0:
            raise SafetyRefusal("npm lockfile regeneration failed for the bounded candidate")
        if (root / "package.json").read_bytes() != package_after:
            raise SafetyRefusal("npm unexpectedly rewrote package.json during lockfile regeneration")
        lock_after = (root / "package-lock.json").read_bytes()
        if b"\x00" in lock_after:
            raise SafetyRefusal("npm produced a binary lockfile")
        try:
            generated = json.loads(lock_after.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise SafetyRefusal("npm produced an invalid package-lock.json") from error
        generated_packages = generated.get("packages") if isinstance(generated, dict) else None
        generated_entry = (
            generated_packages.get(f"node_modules/{dependency}")
            if isinstance(generated_packages, dict)
            else None
        )
        if not isinstance(generated_entry, dict) or str(generated_entry.get("version") or "") != target:
            raise SafetyRefusal("npm did not resolve the candidate dependency to the exact target version")

    changes = [FileChange(package_relative, package_before, package_after)]
    if lock_after != lock_before:
        changes.append(FileChange(lock_relative, lock_before, lock_after))
    else:
        raise SafetyRefusal("npm candidate produced no lockfile change")
    return ChangePlan.create("npm-security-update", changes)
