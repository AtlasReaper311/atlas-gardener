from __future__ import annotations

import copy
import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from atlas_gardener.automation import (
    approval_marker,
    automatic_merge_eligible,
    object_digest,
    parse_approval_marker,
    read_object,
    remediation_key,
    resolve_mode,
    validate_bundle,
    validate_policy,
)
from atlas_gardener.contracts import ContractSet
from atlas_gardener.errors import ContractError, SafetyRefusal


class AutomationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.infra = Path(os.environ["ATLAS_GARDENER_INFRA_ROOT"]).resolve()
        cls.policy = read_object(
            cls.infra / "policy/gardener-automation.json", label="automation policy"
        )
        cls.coverage = read_object(
            cls.infra / "policy/gardener-github-app-coverage.json",
            label="coverage policy",
        )
        cls.contracts = ContractSet(cls.infra / "contracts/v1")
        validate_policy(cls.policy, cls.coverage)

    def finding(self) -> dict:
        return copy.deepcopy(self.contracts.finding_schema["examples"][0])

    def bundle(self, *, now: datetime | None = None) -> dict:
        current = now or datetime.now(timezone.utc)
        finding = self.finding()
        value = {
            "schema_version": "atlas-control-plane/gardener-finding-bundle/v1",
            "producer": "AtlasReaper311/atlas-dep-audit",
            "source_workflow": ".github/workflows/audit.yml",
            "source_run_id": "100",
            "source_run_attempt": 1,
            "source_commit": "1" * 40,
            "authority_commit": "2" * 40,
            "policy_digest": object_digest(self.policy),
            "generated_at": current.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expires_at": (current + timedelta(hours=36))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "public_only": True,
            "source_report_digest": "sha256:" + "3" * 64,
            "repository_snapshots": [
                {
                    "repository": finding["subject"]["repository"],
                    "base_branch": "main",
                    "base_sha": "4" * 40,
                }
            ],
            "findings": [finding],
            "bundle_digest": "sha256:" + "0" * 64,
        }
        material = dict(value)
        material.pop("bundle_digest")
        value["bundle_digest"] = object_digest(material)
        return value

    def test_committed_policy_is_valid_and_default_disabled(self) -> None:
        policy = validate_policy(copy.deepcopy(self.policy), copy.deepcopy(self.coverage))
        self.assertEqual("disabled", policy["default_mode"])
        self.assertEqual(
            ("disabled", False),
            resolve_mode(policy, {}),
        )

    def test_unknown_mode_fails_closed(self) -> None:
        with self.assertRaisesRegex(SafetyRefusal, "unknown Atlas Gardener mode"):
            resolve_mode(self.policy, {"ATLAS_GARDENER_MODE": "unsafe"})

    def test_write_mode_requires_independent_gate(self) -> None:
        with self.assertRaisesRegex(SafetyRefusal, "independent write gate"):
            resolve_mode(
                self.policy,
                {
                    "ATLAS_GARDENER_MODE": "pr-only",
                    "ATLAS_GARDENER_WRITE_GATE": "disabled",
                },
            )
        self.assertEqual(
            ("pr-only", True),
            resolve_mode(
                self.policy,
                {
                    "ATLAS_GARDENER_MODE": "pr-only",
                    "ATLAS_GARDENER_WRITE_GATE": "enabled",
                },
            ),
        )

    def test_valid_bundle_replays_deterministically(self) -> None:
        current = datetime(2026, 7, 22, 10, 0, tzinfo=timezone.utc)
        bundle = self.bundle(now=current)
        first = validate_bundle(
            copy.deepcopy(bundle),
            policy=self.policy,
            contracts=self.contracts,
            now=current,
        )
        second = validate_bundle(
            copy.deepcopy(bundle),
            policy=self.policy,
            contracts=self.contracts,
            now=current,
        )
        self.assertEqual(first, second)

    def test_duplicate_finding_replay_fails_closed(self) -> None:
        current = datetime(2026, 7, 22, 10, 0, tzinfo=timezone.utc)
        bundle = self.bundle(now=current)
        bundle["findings"].append(copy.deepcopy(bundle["findings"][0]))
        material = dict(bundle)
        material.pop("bundle_digest")
        bundle["bundle_digest"] = object_digest(material)
        with self.assertRaisesRegex(ContractError, "unique and sorted"):
            validate_bundle(
                bundle,
                policy=self.policy,
                contracts=self.contracts,
                now=current,
            )

    def test_stale_bundle_fails_closed(self) -> None:
        generated = datetime(2026, 7, 20, 8, 0, tzinfo=timezone.utc)
        bundle = self.bundle(now=generated)
        with self.assertRaisesRegex(SafetyRefusal, "stale|maximum accepted age"):
            validate_bundle(
                bundle,
                policy=self.policy,
                contracts=self.contracts,
                now=generated + timedelta(hours=37),
            )

    def test_changed_policy_fails_closed(self) -> None:
        current = datetime(2026, 7, 22, 10, 0, tzinfo=timezone.utc)
        bundle = self.bundle(now=current)
        changed = copy.deepcopy(self.policy)
        changed["notification_cooldown_hours"] = 25
        with self.assertRaisesRegex(ContractError, "policy digest changed"):
            validate_bundle(
                bundle,
                policy=changed,
                contracts=self.contracts,
                now=current,
            )

    def test_low_risk_gitignore_addition_is_eligible(self) -> None:
        plan = {
            "fixer": {"id": "macos-metadata-ignore", "version": "0.1.0"},
            "files": [
                {
                    "path": ".gitignore",
                    "action": "replace",
                    "mode": "100644",
                    "before_text": "node_modules/\n",
                    "after_text": "node_modules/\n\n.DS_Store\n",
                }
            ],
        }
        self.assertEqual((True, "eligible"), automatic_merge_eligible(plan, self.policy))

    def test_binary_deletion_and_source_paths_are_refused(self) -> None:
        delete_plan = {
            "fixer": {"id": "python-cache-ignore", "version": "0.1.0"},
            "files": [
                {
                    "path": "__pycache__/module.pyc",
                    "action": "delete",
                    "mode": "100644",
                    "before_text": None,
                    "after_text": None,
                }
            ],
        }
        self.assertFalse(automatic_merge_eligible(delete_plan, self.policy)[0])
        source_plan = copy.deepcopy(delete_plan)
        source_plan["files"][0].update(
            {
                "path": "src/module.py",
                "action": "replace",
                "before_text": "x = 1\n",
                "after_text": "x = 2\n",
            }
        )
        self.assertFalse(automatic_merge_eligible(source_plan, self.policy)[0])

    def test_remediation_key_binds_base_state(self) -> None:
        common = {
            "repository": "AtlasReaper311/atlas-dora",
            "rule_id": "macos-metadata-ignore",
            "finding_fingerprint": "sha256:" + "1" * 64,
            "fixer_id": "macos-metadata-ignore",
            "fixer_version": "0.1.0",
        }
        first = remediation_key(**common, base_sha="2" * 40)
        second = remediation_key(**common, base_sha="3" * 40)
        self.assertNotEqual(first, second)

    def test_approval_marker_round_trip_and_tamper_refusal(self) -> None:
        approval = {
            "schema_version": "atlas-control-plane/gardener-automation-approval/v1",
            "approval_id": "approval:sha256:" + "1" * 64,
            "remediation_key": "sha256:" + "2" * 64,
        }
        marker = approval_marker(approval)
        self.assertEqual(approval, parse_approval_marker(marker))
        with self.assertRaisesRegex(SafetyRefusal, "exactly one"):
            parse_approval_marker(marker + "\n" + marker)


if __name__ == "__main__":
    unittest.main()
