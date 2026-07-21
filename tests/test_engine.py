"""Scan reporting and apply-mode safety integration tests."""

from __future__ import annotations

import tempfile
import subprocess
import unittest
from pathlib import Path

from atlas_gardener.engine import apply_proposal, propose, scan
from atlas_gardener.errors import SafetyRefusal

from tests.helpers import (
    contracts,
    init_dirty_repository,
    make_finding,
    make_fixture_repository,
    write_json,
)


class EngineIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contracts = contracts()

    def test_scan_deduplicates_and_preserves_deterministic_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            estate = root / "estate"
            estate.mkdir()
            repository = make_fixture_repository(estate)
            (repository / ".DS_Store").write_bytes(b"metadata")
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )
            findings = root / "findings"
            write_json(findings / "z.json", finding)
            write_json(findings / "a.json", finding)

            first = scan(findings, estate, self.contracts)
            second = scan(findings, estate, self.contracts)

            self.assertEqual(first, second)
            self.assertEqual(1, first["findings_loaded"])
            self.assertEqual(1, len(first["proposals"]))
            self.assertEqual(1, len(first["evidence_summaries"]))

    def test_scan_records_deprecated_source_refusal_without_a_proposal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            estate = root / "estate"
            estate.mkdir()
            repository = estate / "example-private-deprecated"
            (repository / ".atlas").mkdir(parents=True)
            write_json(
                repository / ".atlas" / "governance.json",
                {
                    "schema_version": "atlas-repository-governance/v1",
                    "repository": "AtlasReaper311/example-private-deprecated",
                    "visibility": "private",
                    "estate_membership": "internal",
                    "lifecycle": "deprecated",
                    "provenance": "original",
                    "public_projection": False,
                },
            )
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )
            path = root / "finding.json"
            write_json(path, finding)

            report = scan(path, estate, self.contracts)

            self.assertEqual([], report["proposals"])
            self.assertIn("deprecated", report["refusals"][0]["reason"])

    def test_apply_is_dry_run_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_fixture_repository(root)
            metadata = repository / ".DS_Store"
            metadata.write_bytes(b"metadata")
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )
            proposal, _, _ = propose(finding, repository, self.contracts)
            proposal_path = root / "proposal.json"
            write_json(proposal_path, proposal)

            result = apply_proposal(proposal_path, repository, self.contracts)

            self.assertFalse(result["applied"])
            self.assertTrue(metadata.exists())
            self.assertFalse((repository / ".gitignore").exists())

    def test_real_local_apply_requires_explicit_flag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "atlas-badges"
            repository.mkdir()
            init_dirty_repository(repository)
            # The metadata-only exception permits proposal creation, while apply remains gated.
            (repository / "dirty.txt").unlink()
            (repository / ".DS_Store").write_bytes(b"metadata")
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )
            from atlas_gardener.models import RepositoryClassification

            proposal, _, _ = propose(
                finding,
                repository,
                self.contracts,
                classification_override=RepositoryClassification(
                    "active", "internal", "original"
                ),
            )
            proposal_path = root / "proposal.json"
            write_json(proposal_path, proposal)

            with self.assertRaisesRegex(SafetyRefusal, "local-fixture-only"):
                apply_proposal(
                    proposal_path,
                    repository,
                    self.contracts,
                    apply=True,
                )

    def test_actual_apply_refuses_main_even_for_a_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_fixture_repository(root)
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
                text=True,
            )
            (repository / ".DS_Store").write_bytes(b"metadata")
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )
            proposal, _, _ = propose(finding, repository, self.contracts)
            proposal_path = root / "proposal.json"
            write_json(proposal_path, proposal)

            with self.assertRaisesRegex(SafetyRefusal, "main branch"):
                apply_proposal(
                    proposal_path,
                    repository,
                    self.contracts,
                    apply=True,
                )


if __name__ == "__main__":
    unittest.main()
