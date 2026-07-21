"""Shared standard-library test helpers."""

from __future__ import annotations

import json
import os
import importlib.util
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from atlas_gardener.contracts import ContractSet, selected_fields_digest
from atlas_gardener.safety import FIXTURE_MARKER

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_ROOT = Path(
    os.environ.get(
        "ATLAS_GARDENER_CONTRACTS",
        ROOT.parent / "atlas-infra" / "contracts" / "v1",
    )
)


def contracts() -> ContractSet:
    return ContractSet(CONTRACTS_ROOT)


def canonical_contract_validator():
    """Load the authoritative atlas-infra validator under a private module name."""

    path = CONTRACTS_ROOT.parents[1] / "scripts" / "control_plane_contracts.py"
    spec = importlib.util.spec_from_file_location(
        "atlas_infra_control_plane_contracts", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load canonical validator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def current_fixture_detected_at() -> str:
    """Return a non-future fixture time that remains inside the proposal expiry window."""

    detected = datetime.now(timezone.utc) - timedelta(minutes=1)
    return detected.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_finding(
    contract_set: ContractSet,
    *,
    repository: str,
    rule_id: str,
    location: str,
    eligible: bool = True,
    summary: str = "A deterministic fixture finding requires remediation.",
    detected_at: str | None = None,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "schema_version": "atlas-control-plane/finding/v1",
        "source": {
            "producer": "atlas-dep-audit",
            "check_id": rule_id,
            "producer_version": "1.0.0",
        },
        "subject": {"repository": f"AtlasReaper311/{repository}"},
        "category": "policy",
        "severity": "warning",
        "rule_id": rule_id,
        "location": location,
        "evidence": {
            "summary": summary,
            "references": [
                f"https://github.com/AtlasReaper311/{repository}/actions/runs/100"
            ],
            "redacted": True,
        },
        "detected_at": detected_at or current_fixture_detected_at(),
        "fingerprint": "sha256:" + "0" * 64,
        "remediation": {
            "eligible": eligible,
            "reason": "An allowlisted deterministic fixer is available."
            if eligible
            else "Owner review is required.",
        },
    }
    finding["fingerprint"] = selected_fields_digest(
        finding, contract_set.rules["finding"]
    )
    return contract_set.validate_finding(finding)


def make_fixture_repository(parent: Path, name: str = "fixture-repo") -> Path:
    repository = parent / name
    repository.mkdir()
    (repository / FIXTURE_MARKER).write_text(
        "disposable test repository\n", encoding="utf-8"
    )
    return repository


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def init_dirty_repository(repository: Path) -> None:
    subprocess.run(
        ["git", "init", "-b", "feat/test", str(repository)],
        check=True,
        capture_output=True,
        text=True,
    )
    (repository / "dirty.txt").write_text("dirty\n", encoding="utf-8")
