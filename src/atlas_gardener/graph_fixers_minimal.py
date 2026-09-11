"""Minimal ADR-0016 lockfile overlay for transitive-only graph remediation.

The legacy graph fixer still performs all authority, preimage, npm resolution,
digest, and vulnerability checks. This wrapper changes only the deterministic
lockfile material supplied by the pinned npm runner when the candidate contains
transitive operations and no direct graph operation.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from atlas_gardener import graph_fixers as legacy
from atlas_gardener.errors import SafetyRefusal


def _npm_json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def _load_json_bytes(value: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(value.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SafetyRefusal(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise SafetyRefusal(f"{label} must be a JSON object")
    return payload


def _transitive_paths(candidate: dict[str, Any] | None) -> list[str] | None:
    if not isinstance(candidate, dict):
        return None
    direct = candidate.get("direct_updates")
    transitive = candidate.get("transitive_updates")
    if not isinstance(direct, list) or direct:
        return None
    if not isinstance(transitive, list) or not transitive:
        return None
    paths: list[str] = []
    for operation in transitive:
        if not isinstance(operation, dict):
            return None
        package_path = str(operation.get("package_path") or "")
        if not package_path.startswith("node_modules/"):
            return None
        paths.append(package_path)
    if len(set(paths)) != len(paths):
        return None
    return sorted(paths)


def npm_graph_plan(repository: Path, candidate: dict[str, Any] | None):
    paths = _transitive_paths(candidate)
    if paths is None:
        return legacy.npm_graph_plan(repository, candidate)

    original_runner = legacy._run_pinned_npm

    def minimal_runner(root: Path, names: list[str]) -> None:
        lock_path = root / "package-lock.json"
        manifest_path = root / "package.json"
        lock_before = lock_path.read_bytes()
        manifest_before = manifest_path.read_bytes()
        original = _load_json_bytes(lock_before, "audited package-lock.json")
        if original.get("lockfileVersion") != 3 or "dependencies" in original:
            raise SafetyRefusal(
                "transitive-only minimal remediation requires a modern lockfileVersion 3 graph"
            )
        if _npm_json_bytes(original) != lock_before:
            raise SafetyRefusal(
                "transitive-only minimal remediation requires canonical npm JSON formatting"
            )

        original_runner(root, names)
        if manifest_path.read_bytes() != manifest_before:
            raise SafetyRefusal(
                "pinned npm unexpectedly rewrote package.json during transitive remediation"
            )
        generated = _load_json_bytes(lock_path.read_bytes(), "generated package-lock.json")
        generated_packages = generated.get("packages")
        minimal = _load_json_bytes(lock_before, "audited package-lock.json")
        minimal_packages = minimal.get("packages")
        if not isinstance(generated_packages, dict) or not isinstance(minimal_packages, dict):
            raise SafetyRefusal("npm graph lockfile packages map is unavailable")
        for package_path in paths:
            entry = generated_packages.get(package_path)
            if not isinstance(entry, dict):
                raise SafetyRefusal(
                    f"{package_path}: npm did not preserve the admitted transitive node"
                )
            minimal_packages[package_path] = entry
        lock_path.write_bytes(_npm_json_bytes(minimal))

    legacy._run_pinned_npm = minimal_runner
    try:
        return legacy.npm_graph_plan(repository, candidate)
    finally:
        legacy._run_pinned_npm = original_runner


NPM_VERSION = legacy.NPM_VERSION
