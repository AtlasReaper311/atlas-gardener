"""Finding ingestion and Phase 1 contract integration tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from atlas_gardener.contracts import ContractError, load_findings

from tests.helpers import contracts, make_finding, write_json


class FindingIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contracts = contracts()

    def test_valid_finding_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "finding.json"
            finding = make_finding(
                self.contracts,
                repository="fixture-repo",
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )
            write_json(path, finding)

            loaded = load_findings(path, self.contracts)

            self.assertEqual([finding], [item.value for item in loaded])

    def test_invalid_finding_rejected_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            finding = make_finding(
                self.contracts,
                repository="fixture-repo",
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )
            finding.pop("evidence")
            write_json(path, finding)

            with self.assertRaisesRegex(ContractError, "evidence is required"):
                load_findings(path, self.contracts)

    def test_directory_rejects_if_any_finding_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = make_finding(
                self.contracts,
                repository="fixture-repo",
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )
            write_json(root / "a-valid.json", finding)
            write_json(root / "b-invalid.json", {"schema_version": "wrong"})

            with self.assertRaises(ContractError):
                load_findings(root, self.contracts)

    def test_duplicate_fingerprint_is_deduplicated_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = make_finding(
                self.contracts,
                repository="fixture-repo",
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
                summary="Zulu summary",
            )
            second = dict(first)
            second["evidence"] = dict(first["evidence"], summary="Alpha summary")
            write_json(root / "z.json", first)
            write_json(root / "a.json", second)

            loaded_once = load_findings(root, self.contracts)
            loaded_twice = load_findings(root, self.contracts)

            self.assertEqual(1, len(loaded_once))
            self.assertEqual(loaded_once, loaded_twice)
            self.assertEqual(
                "Alpha summary", loaded_once[0].value["evidence"]["summary"]
            )

    def test_bad_canonical_fingerprint_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "finding.json"
            finding = make_finding(
                self.contracts,
                repository="fixture-repo",
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )
            finding["fingerprint"] = "sha256:" + "f" * 64
            write_json(path, finding)

            with self.assertRaisesRegex(ContractError, "canonical selected fields"):
                load_findings(path, self.contracts)


if __name__ == "__main__":
    unittest.main()
