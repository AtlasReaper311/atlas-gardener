"""Allowlisted fixer proposal, refusal, deterministic, and idempotency tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from atlas_gardener.engine import apply_proposal, propose
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.fixers import build_plan

from tests.helpers import (
    canonical_contract_validator,
    contracts,
    make_finding,
    make_fixture_repository,
    write_json,
)

CHECKOUT_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


class FixerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contracts = contracts()

    def _proposal_path(self, root: Path, proposal: dict[str, object]) -> Path:
        path = root / "proposal.json"
        write_json(path, proposal)
        return path

    def test_ds_store_ignore_proposal_and_local_fixture_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_fixture_repository(root)
            (repository / ".DS_Store").write_bytes(b"\x00metadata")
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )

            proposal, plan, _ = propose(finding, repository, self.contracts)

            self.assertEqual([".DS_Store", ".gitignore"], proposal["files_affected"])
            self.assertEqual("macos-metadata-ignore", proposal["fixer"]["id"])
            proposal_path = self._proposal_path(root, proposal)
            result = apply_proposal(
                proposal_path, repository, self.contracts, apply=True
            )
            self.assertTrue(result["applied"])
            self.assertFalse((repository / ".DS_Store").exists())
            self.assertIn(".DS_Store", (repository / ".gitignore").read_text())
            self.assertEqual(plan.patch_digest, proposal["patch_digest"])
            with self.assertRaisesRegex(SafetyRefusal, "no deterministic change"):
                build_plan("macos-metadata-ignore", repository)

    def test_python_cache_ignore_proposal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_fixture_repository(root)
            cache = repository / "pkg" / "__pycache__" / "module.pyc"
            cache.parent.mkdir(parents=True)
            cache.write_bytes(b"\x00pyc")
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="python-cache-ignore",
                location="pkg/__pycache__/module.pyc",
            )

            proposal, _, _ = propose(finding, repository, self.contracts)
            proposal_path = self._proposal_path(root, proposal)
            apply_proposal(proposal_path, repository, self.contracts, apply=True)

            gitignore = (repository / ".gitignore").read_text(encoding="utf-8")
            self.assertIn("__pycache__/", gitignore)
            self.assertIn("*.py[cod]", gitignore)
            self.assertFalse(cache.exists())

    def test_workflow_timeout_adds_only_missing_job_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_fixture_repository(root)
            workflow = repository / ".github" / "workflows" / "ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "name: CI\n"
                "on: [push]\n"
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: python3 -m unittest\n"
                "  lint:\n"
                "    runs-on: ubuntu-latest\n"
                "    timeout-minutes: 5\n"
                "    steps:\n"
                "      - run: python3 -m compileall src\n",
                encoding="utf-8",
            )
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="workflow-timeout",
                location=".github/workflows/ci.yml:5",
            )

            proposal, _, _ = propose(finding, repository, self.contracts)
            apply_proposal(
                self._proposal_path(root, proposal),
                repository,
                self.contracts,
                apply=True,
            )

            updated = workflow.read_text(encoding="utf-8")
            self.assertEqual(1, updated.count("timeout-minutes: 15"))
            self.assertEqual(1, updated.count("timeout-minutes: 5"))
            with self.assertRaisesRegex(SafetyRefusal, "no deterministic change"):
                build_plan(
                    "workflow-timeout",
                    repository,
                    files=[".github/workflows/ci.yml"],
                )

    def test_workflow_permissions_safe_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_fixture_repository(root)
            workflow = repository / ".github" / "workflows" / "ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "name: CI\n"
                "on: [push]\n"
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                f"      - uses: actions/checkout@{CHECKOUT_SHA}\n"
                "      - run: python3 -m unittest\n",
                encoding="utf-8",
            )
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="workflow-permissions",
                location=".github/workflows/ci.yml",
            )

            proposal, _, _ = propose(finding, repository, self.contracts)
            apply_proposal(
                self._proposal_path(root, proposal),
                repository,
                self.contracts,
                apply=True,
            )

            updated = workflow.read_text(encoding="utf-8")
            self.assertIn("permissions:\n  contents: read", updated)

    def test_workflow_permissions_refuses_deployment_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = make_fixture_repository(Path(directory))
            workflow = repository / ".github" / "workflows" / "deploy.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "name: Deploy\non: [push]\njobs:\n  deploy:\n"
                "    runs-on: ubuntu-latest\n    steps:\n      - run: wrangler deploy\n",
                encoding="utf-8",
            )
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="workflow-permissions",
                location=".github/workflows/deploy.yml",
            )

            with self.assertRaisesRegex(SafetyRefusal, "deployment"):
                propose(finding, repository, self.contracts)

    def test_workflow_fixer_refuses_binary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = make_fixture_repository(Path(directory))
            workflow = repository / ".github" / "workflows" / "ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_bytes(b"jobs:\x00invalid")
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="workflow-timeout",
                location=".github/workflows/ci.yml",
            )

            with self.assertRaisesRegex(SafetyRefusal, "binary"):
                propose(finding, repository, self.contracts)

    def test_file_limit_refuses_large_metadata_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = make_fixture_repository(Path(directory))
            for index in range(5):
                metadata = repository / f"folder-{index}" / ".DS_Store"
                metadata.parent.mkdir()
                metadata.write_bytes(b"metadata")
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="macos-metadata-ignore",
                location="folder-0/.DS_Store",
            )

            with self.assertRaisesRegex(SafetyRefusal, "maximum is 5"):
                propose(finding, repository, self.contracts)

    def test_action_pin_uses_only_approved_local_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_fixture_repository(root)
            workflow = repository / ".github" / "workflows" / "ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "name: CI\non: [push]\njobs:\n  test:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )
            pins = root / "pins.json"
            write_json(
                pins,
                {
                    "schema_version": "atlas-gardener/action-pins/v1",
                    "pins": {"actions/checkout@v4": CHECKOUT_SHA},
                },
            )
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="action-pin-plan",
                location=".github/workflows/ci.yml:7",
            )

            proposal, _, _ = propose(
                finding, repository, self.contracts, pins_file=pins
            )
            apply_proposal(
                self._proposal_path(root, proposal),
                repository,
                self.contracts,
                apply=True,
                pins_file=pins,
            )

            self.assertIn(
                f"actions/checkout@{CHECKOUT_SHA} # v4",
                workflow.read_text(encoding="utf-8"),
            )

    def test_action_pin_refuses_without_local_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = make_fixture_repository(Path(directory))
            workflow = repository / ".github" / "workflows" / "ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "name: CI\non: [push]\njobs:\n  test:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="action-pin-plan",
                location=".github/workflows/ci.yml",
            )

            with self.assertRaisesRegex(SafetyRefusal, "resolution is deferred"):
                propose(finding, repository, self.contracts)

    def test_proposal_output_is_deterministic_and_schema_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = make_fixture_repository(Path(directory))
            (repository / ".DS_Store").write_bytes(b"metadata")
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )

            first, first_plan, first_evidence = propose(
                finding, repository, self.contracts
            )
            second, second_plan, second_evidence = propose(
                finding, repository, self.contracts
            )

            self.assertEqual(first, second)
            self.assertEqual(first_plan.patch_digest, second_plan.patch_digest)
            self.assertEqual(first_evidence, second_evidence)
            self.assertEqual(first, self.contracts.validate_proposal(first))
            canonical = canonical_contract_validator()
            self.assertEqual(
                [], canonical.validate_instance(first, self.contracts.proposal_schema)
            )
            self.assertEqual(
                [],
                canonical.semantic_errors(
                    "remediation-proposal.schema.json",
                    first,
                    self.contracts.fingerprint_rules,
                ),
            )


if __name__ == "__main__":
    unittest.main()
