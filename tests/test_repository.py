"""Repository baseline, workflow hardening, and no-network surface tests."""

from __future__ import annotations

import re
import tomllib
import unittest

from atlas_gardener.contracts import read_json

from tests.helpers import ROOT, contracts


class RepositoryBaselineTests(unittest.TestCase):
    def test_pyproject_is_standard_library_only_and_exposes_cli(self) -> None:
        payload = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual([], payload["project"]["dependencies"])
        self.assertEqual(
            "atlas_gardener.cli:main",
            payload["project"]["scripts"]["atlas-gardener"],
        )

    def test_ci_workflow_has_required_hardening(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("concurrency:", workflow)
        self.assertIn("timeout-minutes:", workflow)
        self.assertNotIn("upload-artifact", workflow)
        action_lines = [
            line.strip() for line in workflow.splitlines() if "uses:" in line
        ]
        self.assertTrue(action_lines)
        for line in action_lines:
            self.assertRegex(line, r"@[0-9a-f]{40} # v[0-9]")

    def test_source_has_no_shell_or_http_client_surface(self) -> None:
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "src").rglob("*.py"))
        )
        forbidden = (
            "shell=True",
            "os.system(",
            "urllib.request",
            "http.client",
            "import requests",
            "from requests",
            "import socket",
            "eval(",
            "exec(",
        )
        for value in forbidden:
            self.assertNotIn(value, sources)

    def test_example_finding_matches_authoritative_schema_and_fingerprint(self) -> None:
        finding = read_json(ROOT / "examples" / "finding.workflow-timeout.json")
        self.assertEqual(finding, contracts().validate_finding(finding))

    def test_example_pin_is_a_full_immutable_sha(self) -> None:
        pins = read_json(ROOT / "examples" / "action-pins.json")
        self.assertEqual("atlas-gardener/action-pins/v1", pins["schema_version"])
        for sha in pins["pins"].values():
            self.assertIsNotNone(re.fullmatch(r"[0-9a-f]{40}", sha))

    def test_required_docs_and_licence_exist(self) -> None:
        required = (
            "README.md",
            "LICENSE",
            "docs/threat-model.md",
            "docs/allowed-fixers.md",
            "docs/adding-a-fixer.md",
            "docs/ownership.md",
            "docs/future-github-pr-model.md",
            "docs/runbooks/refusal-and-rollback.md",
        )
        for relative in required:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_text_files_have_final_newlines_and_no_trailing_whitespace(self) -> None:
        text_names = {".gitignore", "LICENSE", "README.md"}
        text_suffixes = {".json", ".md", ".py", ".toml", ".yml", ".yaml"}
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file() or ".git" in path.parts or ".contracts" in path.parts:
                continue
            if path.name not in text_names and path.suffix not in text_suffixes:
                continue
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.endswith("\n"), str(path))
            for line_number, line in enumerate(text.splitlines(), start=1):
                self.assertEqual(line.rstrip(), line, f"{path}:{line_number}")


if __name__ == "__main__":
    unittest.main()
