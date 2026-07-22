from __future__ import annotations

import unittest
from unittest.mock import patch

from atlas_gardener.github_app_pr import (
    apply_pr_plan,
    installation_token_from_environment,
)
from test_github_app_pr import FakeTransport, make_plan


class GitHubAppTokenFormatTests(unittest.TestCase):
    def test_stateless_installation_token_is_treated_as_opaque(self) -> None:
        plan = make_plan()
        transport = FakeTransport(base_sha=plan["base_sha"])
        token = (
            "ghs_1234567890_"
            + ("A" * 180)
            + "."
            + ("B" * 160)
            + "."
            + ("C" * 160)
        )

        result = apply_pr_plan(
            plan,
            approved_plan_digest=plan["plan_digest"],
            token=token,
            current_classification=plan["classification"],
            transport=transport,
        )

        self.assertGreaterEqual(len(token), 520)
        self.assertEqual(2, token.count("."))
        self.assertTrue(result["draft_pull_request"]["draft"])
        self.assertTrue(result["stopped"])

    def test_environment_reader_preserves_long_token_without_introspection(self) -> None:
        token = (
            "ghs_9876543210_"
            + ("x" * 170)
            + "."
            + ("y" * 170)
            + "."
            + ("z" * 170)
        )

        with patch.dict(
            "os.environ",
            {"ATLAS_GARDENER_INSTALLATION_TOKEN": token},
            clear=False,
        ):
            self.assertEqual(token, installation_token_from_environment())


if __name__ == "__main__":
    unittest.main()
