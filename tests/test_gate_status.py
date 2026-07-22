from __future__ import annotations

import unittest
from datetime import datetime, timezone

from atlas_gardener.automation import approval_marker
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.gate_status import (
    build_gate_status,
    parse_gate_status_marker,
    replace_gate_status_marker,
)


class GateStatusTests(unittest.TestCase):
    def approval(self) -> dict:
        return {
            "schema_version": "atlas-control-plane/gardener-automation-approval/v1",
            "approval_id": "approval:sha256:" + "1" * 64,
            "remediation_key": "sha256:" + "2" * 64,
            "expected_head_sha": "3" * 40,
        }

    def test_gate_status_round_trip_and_replacement(self) -> None:
        body = "Reviewed plan\n\n" + approval_marker(self.approval()) + "\n"
        first = build_gate_status(
            body=body,
            head_sha="3" * 40,
            state="eligible",
            reason="checks passed",
            required_checks=["Estate policy", "CI", "CI"],
            observed_at=datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc),
        )
        updated = replace_gate_status_marker(body, first)
        self.assertEqual(first, parse_gate_status_marker(updated))
        self.assertEqual(["CI", "Estate policy"], first["required_checks"])

        second = build_gate_status(
            body=updated,
            head_sha="3" * 40,
            state="refused",
            reason="CI failed",
            required_checks=["CI", "Estate policy"],
            observed_at=datetime(2026, 7, 22, 12, 5, tzinfo=timezone.utc),
        )
        replaced = replace_gate_status_marker(updated, second)
        self.assertEqual(1, replaced.count("atlas-gardener-gate:"))
        self.assertEqual(second, parse_gate_status_marker(replaced))

    def test_gate_status_identity_mismatch_fails_closed(self) -> None:
        body = approval_marker(self.approval())
        with self.assertRaisesRegex(SafetyRefusal, "head does not match"):
            build_gate_status(
                body=body,
                head_sha="4" * 40,
                state="eligible",
                reason="checks passed",
                required_checks=["CI"],
            )

    def test_multiple_gate_markers_fail_closed(self) -> None:
        body = approval_marker(self.approval())
        status = build_gate_status(
            body=body,
            head_sha="3" * 40,
            state="eligible",
            reason="checks passed",
            required_checks=["CI"],
        )
        updated = replace_gate_status_marker(body, status)
        marker = updated.split("<!-- atlas-gardener-gate:", 1)[1]
        duplicate = updated + "\n<!-- atlas-gardener-gate:" + marker
        with self.assertRaisesRegex(SafetyRefusal, "multiple"):
            parse_gate_status_marker(duplicate)


if __name__ == "__main__":
    unittest.main()
