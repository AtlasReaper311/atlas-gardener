"""Repository baseline, workflow hardening, and bounded-network surface tests."""

from __future__ import annotations

import re
import subprocess
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

        allowed_adapters = {
            "src/atlas_gardener/automatic_github.py",
            "src/atlas_gardener/github_app_auth.py",
            "src/atlas_gardener/github_app_pr.py",
            "src/atlas_gardener/notifications.py",
        }
        network_sources = {
            relative for relative, source in sources.items() if "urllib.request" in source
        }
        self.assertEqual(allowed_adapters, network_sources)

        app_pr = sources["src/atlas_gardener/github_app_pr.py"]
        self.assertIn("_allowed_api_operation", app_pr)
        self.assertIn("_MAX_RESPONSE_BYTES", app_pr)
        self.assertIn("timeout=30", app_pr)
        self.assertNotIn("/merge", app_pr)
        self.assertNotIn("/actions/", app_pr)

        app_auth = sources["src/atlas_gardener/github_app_auth.py"]
        self.assertIn("RestAppTransport", app_auth)
        self.assertIn("MAX_RESPONSE_BYTES", app_auth)
        self.assertIn("timeout=30", app_auth)
        self.assertNotIn("/pulls/", app_auth)
        self.assertNotIn("/actions/", app_auth)

        automatic = sources["src/atlas_gardener/automatic_github.py"]
        self.assertIn("RestControllerTransport", automatic)
        self.assertIn("MAX_RESPONSE_BYTES", automatic)
        self.assertIn("timeout=30", automatic)
        self.assertNotIn("/merge", automatic)
        self.assertNotIn("/actions/", automatic)

        notifications = sources["src/atlas_gardener/notifications.py"]
        self.assertIn(
            'NOTIFY_URL = "https://api.atlas-systems.uk/notify"',
            notifications,
        )
        self.assertIn("timeout=20", notifications)
        self.assertNotIn("urlopen(payload", notifications)
        self.assertNotIn("X-GitHub-Stateless-S2S-Token", combined)

    def test_token_format_probe_is_syntax_checked_and_temporary(self) -> None:
        script_path = ROOT / "scripts" / "check-github-app-token-formats.sh"
        script = script_path.read_text(encoding="utf-8")
        completed = subprocess.run(
            ["bash", "-n", str(script_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("X-GitHub-Stateless-S2S-Token: ${override}", script)
        self.assertIn('mint_and_probe "enabled" "2" "stateless"', script)
        self.assertIn('mint_and_probe "disabled" "0" "classic"', script)
        self.assertIn(
            "Routine token minting should omit the temporary override header.", script
        )

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
            "docs/automatic-controller.md",
            "docs/threat-model.md",
            "docs/allowed-fixers.md",
            "docs/adding-a-fixer.md",
            "docs/ownership.md",
            "docs/future-github-pr-model.md",
            "docs/runbooks/refusal-and-rollback.md",
            "docs/github-app-pr-adapter.md",
            "docs/github-app-provider-rollout-checklist.md",
            "scripts/check-github-app-token-formats.sh",
            "scripts/setup-automatic-controller.sh",
        )
        for relative in required:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_text_files_have_final_newlines_and_no_trailing_whitespace(self) -> None:
        text_names = {".gitignore", "LICENSE", "README.md"}
        text_suffixes = {".json", ".md", ".py", ".sh", ".toml", ".yml", ".yaml"}
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
