"""Deterministic ADR-0016 npm graph remediation fixer."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from atlas_gardener.changes import ChangePlan, FileChange
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.safety import read_text_file

NPM_VERSION = "10.9.3"
_SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_SUPPORTED_SPEC_RE = re.compile(r"^(?P<prefix>[~^]?)(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$")


def _semver(value: Any) -> tuple[int, int, int]:
    match = _SEMVER_RE.fullmatch(str(value or ""))
    if match is None:
        raise SafetyRefusal("npm graph candidate requires strict three-part versions")
    return tuple(int(part) for part in match.groups())


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _read_json_bytes(value: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(value.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SafetyRefusal(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise SafetyRefusal(f"{label} must be a JSON object")
    return payload


def _package_name(path: str, entry: dict[str, Any]) -> str | None:
    if entry.get("name"):
        return str(entry["name"])
    marker = "node_modules/"
    if marker not in path:
        return None
    tail = path.rsplit(marker, 1)[1]
    parts = tail.split("/")
    if tail.startswith("@") and len(parts) >= 2:
        return "/".join(parts[:2])
    return parts[0]


def _candidate_child_paths(parent_path: str, dependency: str) -> list[str]:
    child = f"node_modules/{dependency}"
    if not parent_path:
        return [child]
    candidates = [f"{parent_path}/node_modules/{dependency}"]
    parts = parent_path.split("/")
    while "node_modules" in parts:
        index = len(parts) - 1 - parts[::-1].index("node_modules")
        prefix = "/".join(parts[:index])
        candidate = f"{prefix + '/' if prefix else ''}node_modules/{dependency}"
        if candidate not in candidates:
            candidates.append(candidate)
        parts = parts[:index]
    if child not in candidates:
        candidates.append(child)
    return candidates


def _resolve_child(packages: dict[str, Any], parent_path: str, dependency: str) -> str | None:
    for candidate in _candidate_child_paths(parent_path, dependency):
        if isinstance(packages.get(candidate), dict):
            return candidate
    return None


def _parents(packages: dict[str, Any], child_path: str) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for parent_path, entry in packages.items():
        if not parent_path or not isinstance(parent_path, str) or not isinstance(entry, dict):
            continue
        dependencies = entry.get("dependencies")
        if not isinstance(dependencies, dict):
            continue
        for dependency, specifier in dependencies.items():
            if _resolve_child(packages, parent_path, str(dependency)) == child_path:
                result.append({"package_path": parent_path, "specifier": str(specifier)})
    return sorted(result, key=lambda item: (item["package_path"], item["specifier"]))


def _spec_accepts(specifier: str, target: tuple[int, int, int]) -> bool:
    match = _SUPPORTED_SPEC_RE.fullmatch(specifier.strip())
    if match is not None:
        lower = _semver(match.group("version"))
        prefix = match.group("prefix")
        if prefix == "":
            return target == lower
        if prefix == "~":
            return target >= lower and target[0] == lower[0] and target[1] == lower[1]
        if prefix == "^":
            if lower[0] > 0:
                return target >= lower and target[0] == lower[0]
            if lower[1] > 0:
                return target >= lower and target[:2] == lower[:2]
            return target >= lower and target == lower
    tokens = specifier.split()
    if len(tokens) in {1, 2} and all(re.fullmatch(r"(?:>=|>|<=|<)[0-9]+\.[0-9]+\.[0-9]+", token) for token in tokens):
        for token in tokens:
            bound = _semver(token[2:] if token[:2] in {">=", "<="} else token[1:])
            if token.startswith(">=") and target < bound:
                return False
            if token.startswith(">") and not token.startswith(">=") and target <= bound:
                return False
            if token.startswith("<=") and target > bound:
                return False
            if token.startswith("<") and not token.startswith("<=") and target >= bound:
                return False
        return True
    return False


def _declaration(package: dict[str, Any], dependency: str) -> tuple[str, str] | None:
    matches: list[tuple[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        values = package.get(section)
        if isinstance(values, dict) and dependency in values:
            matches.append((section, str(values[dependency])))
    if len(matches) > 1:
        raise SafetyRefusal("npm graph direct declaration is ambiguous")
    return matches[0] if matches else None


def _replace_spec(text: str, dependency: str, current_spec: str, target_spec: str) -> str:
    pattern = re.compile(
        rf'^(?P<prefix>\s*"{re.escape(dependency)}"\s*:\s*")'
        rf'{re.escape(current_spec)}(?P<suffix>"\s*,?\s*)(?P<newline>\r?\n)?$'
    )
    lines = text.splitlines(keepends=True)
    matches = [(index, pattern.fullmatch(line)) for index, line in enumerate(lines)]
    matches = [(index, match) for index, match in matches if match is not None]
    if len(matches) != 1:
        raise SafetyRefusal("npm graph manifest declaration is not uniquely line-addressable")
    index, match = matches[0]
    assert match is not None
    lines[index] = match.group("prefix") + target_spec + match.group("suffix") + (match.group("newline") or "")
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


def _run_pinned_npm(root: Path, update_names: list[str]) -> None:
    commands = [[
        "npx", "--yes", f"npm@{NPM_VERSION}", "--", "install",
        "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
    ]]
    if update_names:
        commands.append([
            "npx", "--yes", f"npm@{NPM_VERSION}", "--", "update", *sorted(set(update_names)),
            "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
        ])
    for command in commands:
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=180,
                env=_npm_environment(root),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            raise SafetyRefusal("pinned npm graph regeneration is unavailable or timed out") from error
        if completed.returncode != 0:
            raise SafetyRefusal("pinned npm graph regeneration failed")


def _lock_purls(lock: dict[str, Any]) -> list[str]:
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise SafetyRefusal("npm graph lockfile packages map is unavailable")
    from urllib.parse import quote
    values: list[str] = []
    for path, entry in packages.items():
        if not path or not isinstance(path, str) or not isinstance(entry, dict):
            continue
        name = _package_name(path, entry)
        version = str(entry.get("version") or "")
        if name and version:
            values.append(f"pkg:npm/{quote(name, safe='/')}@{version}")
    return values


def _osv_batch(queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps({"queries": queries}).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "atlas-gardener/adr0016"},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            payload = json.load(response)
    except OSError as error:
        raise SafetyRefusal("bounded OSV post-regeneration check failed") from error
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or len(results) != len(queries):
        raise SafetyRefusal("bounded OSV post-regeneration response is malformed")
    return results


def _active_vulnerability_ids(lock: dict[str, Any]) -> set[str]:
    purls = _lock_purls(lock)
    found: set[str] = set()
    for offset in range(0, len(purls), 500):
        base_queries = [{"package": {"purl": purl}} for purl in purls[offset: offset + 500]]
        pending = list(enumerate(base_queries))
        tokens: dict[int, str] = {}
        while pending:
            queries = []
            indexes = []
            for index, query in pending:
                value = dict(query)
                if index in tokens:
                    value["page_token"] = tokens[index]
                queries.append(value)
                indexes.append(index)
            page = _osv_batch(queries)
            pending = []
            for index, query, result in zip(indexes, queries, page, strict=True):
                vulns = result.get("vulns", []) if isinstance(result, dict) else []
                if not isinstance(vulns, list):
                    raise SafetyRefusal("bounded OSV vulnerability collection is malformed")
                for item in vulns:
                    if isinstance(item, dict) and isinstance(item.get("id"), str):
                        found.add(item["id"])
                token = result.get("next_page_token") if isinstance(result, dict) else None
                if token:
                    marker = str(token)
                    if tokens.get(index) == marker:
                        raise SafetyRefusal("bounded OSV pagination repeated a token")
                    tokens[index] = marker
                    pending.append((index, base_queries[index]))
    return found


def npm_graph_plan(repository: Path, candidate: dict[str, Any] | None) -> ChangePlan:
    if not isinstance(candidate, dict) or candidate.get("kind") != "npm-lock-security-remediation":
        raise SafetyRefusal("npm graph fixer requires matching structured remediation input")
    if candidate.get("npm_version") != NPM_VERSION:
        raise SafetyRefusal("npm graph candidate toolchain version is not the accepted pin")
    manifest_relative = str(candidate.get("manifest_file") or "")
    lock_relative = str(candidate.get("lockfile_file") or "")
    manifest_path = Path(manifest_relative)
    lock_path = Path(lock_relative)
    if manifest_path.name != "package.json" or lock_path.name != "package-lock.json" or manifest_path.parent != lock_path.parent:
        raise SafetyRefusal("npm graph candidate must bind one matching manifest/lock pair")

    _, manifest_before, manifest_text = read_text_file(repository, manifest_relative)
    _, lock_before, _ = read_text_file(repository, lock_relative)
    package = _read_json_bytes(manifest_before, "package.json")
    lock = _read_json_bytes(lock_before, "package-lock.json")
    if lock.get("lockfileVersion") != 3:
        raise SafetyRefusal("npm graph fixer requires lockfileVersion 3")
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise SafetyRefusal("npm graph lockfile packages map is unavailable")

    direct_updates = candidate.get("direct_updates")
    transitive_updates = candidate.get("transitive_updates")
    vulnerability_ids = candidate.get("vulnerability_ids")
    if not isinstance(direct_updates, list) or not isinstance(transitive_updates, list) or not (direct_updates or transitive_updates):
        raise SafetyRefusal("npm graph candidate has no bounded operation")
    if not isinstance(vulnerability_ids, list) or not vulnerability_ids:
        raise SafetyRefusal("npm graph candidate has no vulnerability postcondition")

    manifest_after_text = manifest_text
    update_names: set[str] = set()
    seen_direct: set[str] = set()
    for operation in direct_updates:
        if not isinstance(operation, dict):
            raise SafetyRefusal("npm graph direct operation is malformed")
        dependency = str(operation.get("dependency") or "")
        if not dependency or dependency in seen_direct:
            raise SafetyRefusal("npm graph direct operation identity is absent or duplicated")
        seen_direct.add(dependency)
        declaration = _declaration(package, dependency)
        expected = (str(operation.get("section") or ""), str(operation.get("current_spec") or ""))
        if declaration != expected:
            raise SafetyRefusal("npm graph direct declaration preimage mismatch")
        current = _semver(operation.get("current_version"))
        target = _semver(operation.get("target_version"))
        if target <= current or target[0] != current[0]:
            raise SafetyRefusal("npm graph direct target is not newer same-major")
        entry = packages.get(f"node_modules/{dependency}")
        if not isinstance(entry, dict) or str(entry.get("version") or "") != operation.get("current_version"):
            raise SafetyRefusal("npm graph direct lock preimage mismatch")
        current_spec = str(operation.get("current_spec") or "")
        target_spec = str(operation.get("target_spec") or "")
        if _SUPPORTED_SPEC_RE.fullmatch(current_spec) is None or _SUPPORTED_SPEC_RE.fullmatch(target_spec) is None:
            raise SafetyRefusal("npm graph direct version specification is unsupported")
        if current_spec != target_spec:
            manifest_after_text = _replace_spec(manifest_after_text, dependency, current_spec, target_spec)
        update_names.add(dependency)

    seen_transitive: set[str] = set()
    for operation in transitive_updates:
        if not isinstance(operation, dict):
            raise SafetyRefusal("npm graph transitive operation is malformed")
        package_path = str(operation.get("package_path") or "")
        if not package_path or package_path in seen_transitive:
            raise SafetyRefusal("npm graph transitive operation path is absent or duplicated")
        seen_transitive.add(package_path)
        dependency = str(operation.get("dependency") or "")
        entry = packages.get(package_path)
        if not isinstance(entry, dict) or _package_name(package_path, entry) != dependency or str(entry.get("version") or "") != operation.get("current_version"):
            raise SafetyRefusal("npm graph transitive lock preimage mismatch")
        current = _semver(operation.get("current_version"))
        target = _semver(operation.get("target_version"))
        if target <= current or target[0] != current[0]:
            raise SafetyRefusal("npm graph transitive target is not newer same-major")
        expected_parents = _parents(packages, package_path)
        if operation.get("parents") != expected_parents or not expected_parents:
            raise SafetyRefusal("npm graph parent constraint evidence mismatches exact lock graph")
        if not all(_spec_accepts(item["specifier"], target) for item in expected_parents):
            raise SafetyRefusal("npm graph transitive target violates a parent constraint")
        update_names.add(dependency)

    manifest_after_expected = manifest_after_text.encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="atlas-gardener-adr0016-") as directory:
        root = Path(directory)
        (root / "package.json").write_bytes(manifest_after_expected)
        (root / "package-lock.json").write_bytes(lock_before)
        _run_pinned_npm(root, sorted(update_names))
        manifest_after = (root / "package.json").read_bytes()
        lock_after = (root / "package-lock.json").read_bytes()
        if manifest_after != manifest_after_expected:
            raise SafetyRefusal("pinned npm unexpectedly rewrote package.json")
        if _sha256(manifest_after) != candidate.get("target_manifest_sha256") or _sha256(lock_after) != candidate.get("target_lockfile_sha256"):
            raise SafetyRefusal("npm graph regeneration disagrees with producer target digests")
        generated_lock = _read_json_bytes(lock_after, "generated package-lock.json")
        generated_packages = generated_lock.get("packages")
        if generated_lock.get("lockfileVersion") != 3 or not isinstance(generated_packages, dict):
            raise SafetyRefusal("pinned npm generated an unsupported lockfile")
        for operation in direct_updates:
            entry = generated_packages.get(f"node_modules/{operation['dependency']}")
            if not isinstance(entry, dict) or str(entry.get("version") or "") != operation["target_version"]:
                raise SafetyRefusal("npm graph direct target postcondition failed")
        for operation in transitive_updates:
            entry = generated_packages.get(operation["package_path"])
            if not isinstance(entry, dict) or str(entry.get("version") or "") != operation["target_version"]:
                raise SafetyRefusal("npm graph transitive target postcondition failed")
        active = _active_vulnerability_ids(generated_lock)
        remaining = sorted(set(str(value) for value in vulnerability_ids) & active)
        if remaining:
            raise SafetyRefusal("npm graph vulnerability postcondition failed")

    changes: list[FileChange] = []
    if manifest_after != manifest_before:
        changes.append(FileChange(manifest_relative, manifest_before, manifest_after))
    if lock_after != lock_before:
        changes.append(FileChange(lock_relative, lock_before, lock_after))
    if not changes:
        raise SafetyRefusal("npm graph candidate produced no source change")
    return ChangePlan.create("npm-lock-security-remediation", changes)
