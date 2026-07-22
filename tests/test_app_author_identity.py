from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from atlas_gardener.errors import SafetyRefusal

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/gardener_automerge_gate.py"
SPEC = importlib.util.spec_from_file_location("gardener_automerge_gate", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class AppAuthorIdentityTests(unittest.TestCase):
    def test_accepts_exact_github_cli_app_identity(self) -> None:
        GATE._validate_app_author(
            {
                "is_bot": True,
                "login": "app/atlas-gardener-w37-atlasreaper",
            },
            "atlas-gardener-w37-atlasreaper[bot]",
        )

    def test_refuses_user_other_app_and_non_cli_forms(self) -> None:
        rejected = [
            {
                "is_bot": False,
                "login": "app/atlas-gardener-w37-atlasreaper",
            },
            {
                "is_bot": True,
                "login": "app/another-gardener",
            },
            {
                "is_bot": True,
                "login": "atlas-gardener-w37-atlasreaper[bot]",
            },
            {
                "login": "app/atlas-gardener-w37-atlasreaper",
            },
            "app/atlas-gardener-w37-atlasreaper",
        ]
        for author in rejected:
            with self.subTest(author=author):
                with self.assertRaisesRegex(
                    SafetyRefusal,
                    "not the approved Gardener App bot",
                ):
                    GATE._validate_app_author(
                        author,
                        "atlas-gardener-w37-atlasreaper[bot]",
                    )

    def test_refuses_invalid_expected_app_configuration(self) -> None:
        author = {
            "is_bot": True,
            "login": "app/atlas-gardener-w37-atlasreaper",
        }
        with self.assertRaisesRegex(SafetyRefusal, "must end with"):
            GATE._validate_app_author(
                author,
                "atlas-gardener-w37-atlasreaper",
            )
        with self.assertRaisesRegex(SafetyRefusal, "login is invalid"):
            GATE._validate_app_author(author, "bad/app[bot]")


if __name__ == "__main__":
    unittest.main()
