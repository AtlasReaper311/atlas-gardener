"""Machine-readable target-gate status markers for controller reconciliation."""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from typing import Any

from atlas_gardener.automation import parse_approval_marker
from atlas_gardener.contracts import canonical_json
from atlas_gardener.errors import SafetyRefusal

GATE_STATUS_SCHEMA = "atlas-gardener/target-gate-status/v1"
_GATE_MARKER_RE = re.compile(
    r"<!-- atlas-gardener-gate:([A-Za-z0-9_-]+) -->"
)
_ALLOWED_STATES = {"eligible", "refused"}


def build_gate_status(
    *,
    body: str,
    head_sha: str,
    state: str,
    reason: str,
    required_checks: list[str],
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    if state not in _ALLOWED_STATES:
        raise SafetyRefusal(f"unsupported target-gate state: {state}")
    approval = parse_approval_marker(body)
    if head_sha != approval.get("expected_head_sha"):
        raise SafetyRefusal("target-gate status head does not match the approval")
    checks = sorted(set(required_checks))
    if not checks or any(not isinstance(value, str) or not value for value in checks):
        raise SafetyRefusal("target-gate status requires named checks")
    bounded_reason = reason.strip()[:240] or "unspecified"
    current = observed_at or datetime.now(timezone.utc)
    return {
        "schema_version": GATE_STATUS_SCHEMA,
        "approval_id": approval["approval_id"],
        "remediation_key": approval["remediation_key"],
        "head_sha": head_sha,
        "state": state,
        "reason": bounded_reason,
        "required_checks": checks,
        "observed_at": current.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }


def gate_status_marker(status: dict[str, Any]) -> str:
    if status.get("schema_version") != GATE_STATUS_SCHEMA:
        raise SafetyRefusal("unsupported target-gate status schema")
    encoded = base64.urlsafe_b64encode(
        canonical_json(status).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    return f"<!-- atlas-gardener-gate:{encoded} -->"


def replace_gate_status_marker(body: str, status: dict[str, Any]) -> str:
    marker = gate_status_marker(status)
    if _GATE_MARKER_RE.search(body):
        return _GATE_MARKER_RE.sub(marker, body, count=1)
    suffix = "" if body.endswith("\n") else "\n"
    return body + suffix + "\n" + marker + "\n"


def parse_gate_status_marker(body: str) -> dict[str, Any] | None:
    matches = _GATE_MARKER_RE.findall(body)
    if not matches:
        return None
    if len(matches) != 1:
        raise SafetyRefusal("pull request contains multiple target-gate markers")
    encoded = matches[0]
    padding = "=" * (-len(encoded) % 4)
    try:
        value = json.loads(
            base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
        )
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise SafetyRefusal("target-gate marker is malformed") from error
    if not isinstance(value, dict) or value.get("schema_version") != GATE_STATUS_SCHEMA:
        raise SafetyRefusal("target-gate marker has an unsupported schema")
    if value.get("state") not in _ALLOWED_STATES:
        raise SafetyRefusal("target-gate marker has an unsupported state")
    approval = parse_approval_marker(body)
    if value.get("approval_id") != approval.get("approval_id"):
        raise SafetyRefusal("target-gate marker approval identity mismatch")
    if value.get("remediation_key") != approval.get("remediation_key"):
        raise SafetyRefusal("target-gate marker remediation identity mismatch")
    if value.get("head_sha") != approval.get("expected_head_sha"):
        raise SafetyRefusal("target-gate marker head identity mismatch")
    checks = value.get("required_checks")
    if not isinstance(checks, list) or checks != sorted(set(checks)) or not checks:
        raise SafetyRefusal("target-gate marker check list is invalid")
    return value
