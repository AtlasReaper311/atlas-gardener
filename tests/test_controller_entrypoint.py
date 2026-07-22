from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_automatic_controller.py"


class ControllerEntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.infra = Path(os.environ["ATLAS_GARDENER_TEST_INFRA_ROOT"]).resolve()

    def environment(self) -> dict[str, str]:
        return {
            **os.environ,
            "ATLAS_GARDENER_MODE": "disabled",
            "ATLAS_GARDENER_WRITE_GATE": "disabled",
            "GITHUB_RUN_ID": "9001",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": "AtlasReaper311/atlas-gardener",
            "GITHUB_SHA": "1" * 40,
        }

    def run_entrypoint(self, infra: Path, output: Path, work: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--infra-root",
                str(infra),
                "--output",
                str(output),
                "--work-root",
                str(work),
            ],
            cwd=ROOT,
            env=self.environment(),
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_disabled_entrypoint_produces_controller_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "controller-evidence" / "controller.json"
            completed = self.run_entrypoint(self.infra, output, root / "work")

            self.assertEqual(0, completed.returncode, completed.stderr)
            evidence = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual("atlas-gardener/controller-evidence/v1", evidence["schema_version"])
            self.assertEqual("disabled", evidence["mode"])
            self.assertFalse(evidence["write_gate_enabled"])
            self.assertEqual([], evidence["pull_requests"])
            self.assertEqual([], evidence["tokens"])

    def test_entrypoint_failure_still_produces_bounded_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "controller-evidence" / "controller.json"
            completed = self.run_entrypoint(root / "missing-infra", output, root / "work")

            self.assertEqual(2, completed.returncode)
            self.assertIn("failed closed", completed.stderr)
            evidence = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                "atlas-gardener/controller-error-evidence/v1",
                evidence["schema_version"],
            )
            self.assertEqual("controller-error", evidence["status"])
            self.assertEqual("disabled", evidence["mode"])
            self.assertLessEqual(len(evidence["reason"]), 500)
            self.assertRegex(evidence["evidence_digest"], r"^sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
