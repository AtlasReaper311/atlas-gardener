"""Repository classification, worktree, path, and symlink refusal tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from atlas_gardener.engine import propose
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.models import RepositoryClassification
from atlas_gardener.safety import safe_relative_path

from tests.helpers import (
    contracts,
    init_dirty_repository,
    make_finding,
    make_fixture_repository,
)


class SafetyRefusalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contracts = contracts()

    def test_simple_proxy_is_completely_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = make_fixture_repository(Path(directory), "simple-proxy")
            finding = make_finding(
                self.contracts,
                repository="simple-proxy",
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )
            with self.assertRaisesRegex(SafetyRefusal, "completely excluded"):
                propose(finding, repository, self.contracts)

    def test_deprecated_repository_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = make_fixture_repository(Path(directory))
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )
            classification = RepositoryClassification(
                "deprecated", "internal", "original"
            )
            with self.assertRaisesRegex(SafetyRefusal, "deprecated"):
                propose(
                    finding,
                    repository,
                    self.contracts,
                    classification_override=classification,
                )

    def test_external_derived_repository_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = make_fixture_repository(Path(directory))
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="macos-metadata-ignore",
                location=".DS_Store",
            )
            classification = RepositoryClassification(
                "active", "internal", "external-derived"
            )
            with self.assertRaisesRegex(SafetyRefusal, "external-derived"):
                propose(
                    finding,
                    repository,
                    self.contracts,
                    classification_override=classification,
                )

    def test_dirty_real_worktree_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "real-repo"
            repository.mkdir()
            init_dirty_repository(repository)
            finding = make_finding(
                self.contracts,
                repository=repository.name,
                rule_id="python-cache-ignore",
                location="src/__pycache__/example.pyc",
            )
            classification = RepositoryClassification("active", "internal", "original")
            with self.assertRaisesRegex(SafetyRefusal, "dirty real worktree"):
                propose(
                    finding,
                    repository,
                    self.contracts,
                    classification_override=classification,
                )

    def test_path_traversal_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            with self.assertRaisesRegex(SafetyRefusal, "traversal"):
                safe_relative_path(repository, "../outside.txt")

    def test_symlink_escape_is_refused(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            tempfile.TemporaryDirectory() as outside,
        ):
            repository = Path(directory)
            target = Path(outside) / "outside.txt"
            target.write_text("outside\n", encoding="utf-8")
            try:
                os.symlink(target, repository / "escape.txt")
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlink creation unavailable: {error}")
            with self.assertRaisesRegex(SafetyRefusal, "escapes"):
                safe_relative_path(repository, "escape.txt", allow_missing=False)


if __name__ == "__main__":
    unittest.main()
