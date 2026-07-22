"""Repository baseline, workflow hardening, and bounded-network surface tests."""

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

    def test_source_has_no_unbounded_shell_or_http_client_surface(self) -> None:
        sources = {
            path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "src").rglob("*.py"))
        }
        combined = "\n".join(sources.values())
        for value in (
            "shell=True",
            "os.system(",
            "http.client",
            "import requests",
            "from requests",
            "import socket",
            "eval(",
            "exec(",
        ):
            self.assertNotIn(value, combined)

        adapter_path = "src/atlas_gardener/github_app_pr.py"
        self.assertIn(adapter_path, sources)
        for relative, source in sources.items():
            if relative != adapter_path:
                self.assertNotIn("urllib.request", source, relative)

        adapter = sources[adapter_path]
        self.assertIn("urllib.request", adapter)
        self.assertIn("_allowed_api_operation", adapter)
        self.assertIn("_MAX_RESPONSE_BYTES", adapter)
        self.assertIn("timeout=30", adapter)
        self.assertNotIn("/merge", adapter)
        self.assertNotIn("/actions/", adapter)

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
            "docs/github-app-pr-adapter.md",
            "docs/github-app-provider-rollout-checklist.md",
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
