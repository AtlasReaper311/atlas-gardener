from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from atlas_gardener.controller import run_controller
from atlas_gardener.errors import SafetyRefusal


class ControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.infra = Path(os.environ["ATLAS_GARDENER_INFRA_ROOT"]).resolve()

    def environment(
        self,
        mode: str,
        gate: str = "disabled",
        targets: str = "[]",
    ):
        return mock.patch.dict(
            os.environ,
            {
                "ATLAS_GARDENER_MODE": mode,
                "ATLAS_GARDENER_WRITE_GATE": gate,
                "ATLAS_GARDENER_WRITE_TARGETS_JSON": targets,
                "GITHUB_RUN_ID": "100",
                "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_REPOSITORY": "AtlasReaper311/atlas-gardener",
                "GITHUB_SHA": "1" * 40,
            },
            clear=False,
        )

    def test_disabled_mode_produces_evidence_without_credentials_or_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "evidence.json"
            with self.environment("disabled"):
                with mock.patch(
                    "atlas_gardener.controller.mint_repository_token"
                ) as mint:
                    result = run_controller(
                        infra_root=self.infra,
                        bundle_path=None,
                        output_path=output,
                        work_root=root / "work",
                        attestation_verified=False,
                    )
            mint.assert_not_called()
            self.assertEqual("disabled", result["mode"])
            self.assertFalse(result["write_gate_enabled"])
            self.assertEqual([], result["findings_observed"])
            self.assertEqual([], result["pull_requests"])
            self.assertEqual([], result["tokens"])
            self.assertTrue(output.is_file())
            self.assertEqual(result, json.loads(output.read_text(encoding="utf-8")))

    def test_write_mode_without_kill_switch_gate_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.environment("pr-only", "disabled"):
                with self.assertRaisesRegex(SafetyRefusal, "independent write gate"):
                    run_controller(
                        infra_root=self.infra,
                        bundle_path=None,
                        output_path=root / "evidence.json",
                        work_root=root / "work",
                        attestation_verified=False,
                    )

    def test_write_mode_without_explicit_targets_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.environment("pr-only", "enabled"):
                with self.assertRaisesRegex(SafetyRefusal, "cannot be empty"):
                    run_controller(
                        infra_root=self.infra,
                        bundle_path=None,
                        output_path=root / "evidence.json",
                        work_root=root / "work",
                        attestation_verified=False,
                    )

    def test_non_disabled_mode_requires_bundle_and_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.environment("observe"):
                with self.assertRaisesRegex(SafetyRefusal, "requires a Finding bundle"):
                    run_controller(
                        infra_root=self.infra,
                        bundle_path=None,
                        output_path=root / "evidence.json",
                        work_root=root / "work",
                        attestation_verified=False,
                    )
                bundle = root / "bundle.json"
                bundle.write_text("{}\n", encoding="utf-8")
                with self.assertRaisesRegex(SafetyRefusal, "attestation was not verified"):
                    run_controller(
                        infra_root=self.infra,
                        bundle_path=bundle,
                        output_path=root / "evidence.json",
                        work_root=root / "work",
                        attestation_verified=False,
                    )

    def test_unlisted_repository_is_skipped_before_checkout_or_token(self) -> None:
        authority = "a" * 40
        finding = {
            "fingerprint": "sha256:" + "b" * 64,
            "rule_id": "macos-metadata-ignore",
            "subject": {"repository": "AtlasReaper311/status"},
            "remediation": {
                "eligible": True,
                "reason": "Deterministic housekeeping fixer is allowlisted.",
            },
        }
        validated_bundle = {
            "bundle_digest": "sha256:" + "c" * 64,
            "authority_commit": authority,
            "producer": "AtlasReaper311/atlas-dep-audit",
            "source_workflow": ".github/workflows/audit.yml",
            "source_run_id": "200",
            "source_run_attempt": 1,
            "source_commit": "d" * 40,
            "repository_snapshots": [],
            "findings": [finding],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle.json"
            bundle.write_text("{}\n", encoding="utf-8")
            with self.environment(
                "pr-only",
                "enabled",
                '["AtlasReaper311/atlas-dora"]',
            ):
                with mock.patch(
                    "atlas_gardener.controller._git", return_value=authority
                ), mock.patch(
                    "atlas_gardener.controller.validate_bundle",
                    return_value=validated_bundle,
                ), mock.patch(
                    "atlas_gardener.controller.coverage_classifications",
                    return_value={},
                ), mock.patch(
                    "atlas_gardener.controller._checkout_target"
                ) as checkout, mock.patch(
                    "atlas_gardener.controller.mint_repository_token"
                ) as mint, mock.patch(
                    "atlas_gardener.controller.send_notification",
                    return_value={"status": "sent"},
                ):
                    result = run_controller(
                        infra_root=self.infra,
                        bundle_path=bundle,
                        output_path=root / "evidence.json",
                        work_root=root / "work",
                        attestation_verified=True,
                    )

            checkout.assert_not_called()
            mint.assert_not_called()
            self.assertEqual([], result["findings_observed"])
            self.assertEqual([], result["proposals"])
            self.assertEqual([], result["plans"])
            self.assertEqual([], result["pull_requests"])
            self.assertEqual([], result["tokens"])
            self.assertEqual(
                [
                    {
                        "finding_fingerprint": finding["fingerprint"],
                        "repository": "AtlasReaper311/status",
                        "reason": "repository is outside explicit write target scope",
                    }
                ],
                result["repositories_skipped"],
            )

    def test_ineligible_scheduled_findings_are_observations_not_refusals(self) -> None:
        authority = "a" * 40
        repository = "AtlasReaper311/atlas-dora"
        base_sha = "e" * 40
        findings = [
            {
                "fingerprint": "sha256:" + f"{index:064x}",
                "rule_id": "dependency-vulnerability",
                "subject": {"repository": repository},
                "remediation": {
                    "eligible": False,
                    "reason": (
                        "Dependency and lockfile changes are outside the initial "
                        "automatic-remediation policy."
                    ),
                },
            }
            for index in range(1, 16)
        ]
        validated_bundle = {
            "bundle_digest": "sha256:" + "c" * 64,
            "authority_commit": authority,
            "producer": "AtlasReaper311/atlas-dep-audit",
            "source_workflow": ".github/workflows/audit.yml",
            "source_run_id": "200",
            "source_run_attempt": 1,
            "source_commit": "d" * 40,
            "repository_snapshots": [
                {
                    "repository": repository,
                    "base_branch": "main",
                    "base_sha": base_sha,
                }
            ],
            "findings": findings,
        }
        classifications = {
            repository: {
                "lifecycle": "production",
                "scope": "public",
                "provenance": "original",
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle.json"
            bundle.write_text("{}\n", encoding="utf-8")
            with self.environment(
                "automerge-low-risk",
                "enabled",
                f'["{repository}"]',
            ):
                with mock.patch(
                    "atlas_gardener.controller._git", return_value=authority
                ), mock.patch(
                    "atlas_gardener.controller.validate_bundle",
                    return_value=validated_bundle,
                ), mock.patch(
                    "atlas_gardener.controller.coverage_classifications",
                    return_value=classifications,
                ), mock.patch(
                    "atlas_gardener.controller.fixer_for_finding"
                ) as fixer, mock.patch(
                    "atlas_gardener.controller._checkout_target"
                ) as checkout, mock.patch(
                    "atlas_gardener.controller.mint_repository_token"
                ) as mint, mock.patch(
                    "atlas_gardener.controller.send_notification",
                    return_value={"status": "sent"},
                ) as notify:
                    result = run_controller(
                        infra_root=self.infra,
                        bundle_path=bundle,
                        output_path=root / "evidence.json",
                        work_root=root / "work",
                        attestation_verified=True,
                    )

            fixer.assert_not_called()
            checkout.assert_not_called()
            mint.assert_not_called()
            self.assertEqual(15, len(result["finding_fingerprints"]))
            self.assertEqual(15, len(result["findings_observed"]))
            self.assertEqual([], result["refusals"])
            self.assertEqual([], result["plans"])
            self.assertEqual([], result["pull_requests"])
            payload = notify.call_args.args[0]
            self.assertEqual("info", payload["level"])
            self.assertEqual("finding_received", payload["fields"]["event"])
            self.assertEqual("15", payload["fields"]["findings"])
            self.assertEqual("0", payload["fields"]["actionable"])
            self.assertEqual("15", payload["fields"]["observations"])
            self.assertEqual("0", payload["fields"]["refusals"])
            self.assertIn("15 non-actionable observation(s)", payload["message"])
            self.assertIn("0 refusals", payload["message"])


if __name__ == "__main__":
    unittest.main()