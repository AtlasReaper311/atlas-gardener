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

    def environment(self, mode: str, gate: str = "disabled"):
        return mock.patch.dict(
            os.environ,
            {
                "ATLAS_GARDENER_MODE": mode,
                "ATLAS_GARDENER_WRITE_GATE": gate,
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


if __name__ == "__main__":
    unittest.main()
