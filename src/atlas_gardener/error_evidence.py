"""Write bounded controller error evidence without importing controller code."""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _positive_int(value: str, default: int) -> int:
    try:
        parsed = int(value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def _previous_digest(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    digest = value.get("evidence_digest")
    return digest if isinstance(digest, str) and DIGEST_RE.fullmatch(digest) else None


def write_controller_error_evidence(
    output_path: Path,
    error: BaseException,
    *,
    previous_evidence_path: Path | None = None,
) -> dict[str, Any]:
    """Write one secret-free error artifact and return its payload."""

    mode = os.environ.get("ATLAS_GARDENER_MODE", "disabled").strip() or "disabled"
    write_gate = os.environ.get("ATLAS_GARDENER_WRITE_GATE", "").strip()
    evidence: dict[str, Any] = {
        "schema_version": "atlas-gardener/controller-error-evidence/v1",
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "run_attempt": _positive_int(os.environ.get("GITHUB_RUN_ATTEMPT", "1"), 1),
        "mode": mode[:64],
        "write_gate_enabled": write_gate == "enabled",
        "status": "controller-error",
        "error_type": type(error).__name__[:80],
        "reason": str(error)[:500] or "controller failed without an error message",
        "previous_evidence_digest": _previous_digest(previous_evidence_path),
        "observed_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    evidence["evidence_digest"] = "sha256:" + hashlib.sha256(
        _canonical_bytes(evidence)
    ).hexdigest()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return evidence
