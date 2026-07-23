from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "verify_gardener_rollout.py"
)
SPEC = importlib.util.spec_from_file_location("verify_gardener_rollout", SCRIPT)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def file_record(patch: str, additions: int) -> dict:
    return {
        "filename": ".gitignore",
        "additions": additions,
        "deletions": 0,
        "patch": patch,
    }


class RolloutPatchVerifierTests(unittest.TestCase):
    def test_accepts_one_line_addition(self) -> None:
        patch = "@@ -1 +1,2 @@\n .wrangler/\n+.DS_Store"
        additions = VERIFY.validate_policy_patch(
            pr_files=[file_record(patch, 1)],
            commit_files=[file_record(patch, 1)],
        )
        self.assertEqual(1, additions)

    def test_accepts_blank_separator_and_rule(self) -> None:
        patch = "@@ -1 +1,3 @@\n .wrangler/\n+\n+.DS_Store"
        additions = VERIFY.validate_policy_patch(
            pr_files=[file_record(patch, 2)],
            commit_files=[file_record(patch, 2)],
        )
        self.assertEqual(2, additions)

    def test_rejects_unapproved_added_line(self) -> None:
        patch = "@@ -1 +1,3 @@\n .wrangler/\n+.env\n+.DS_Store"
        with self.assertRaisesRegex(
            VERIFY.CANARY.VerificationError,
            "exact policy-allowed",
        ):
            VERIFY.validate_policy_patch(
                pr_files=[file_record(patch, 2)],
                commit_files=[file_record(patch, 2)],
            )

    def test_rejects_deletions(self) -> None:
        patch = "@@ -1 +1 @@\n-.wrangler/\n+.DS_Store"
        record = file_record(patch, 1)
        record["deletions"] = 1
        with self.assertRaisesRegex(
            VERIFY.CANARY.VerificationError,
            "deletion",
        ):
            VERIFY.validate_policy_patch(
                pr_files=[record],
                commit_files=[record],
            )

    def test_rejects_mismatched_pr_and_commit_patch(self) -> None:
        one_line = "@@ -1 +1,2 @@\n .wrangler/\n+.DS_Store"
        two_lines = "@@ -1 +1,3 @@\n .wrangler/\n+\n+.DS_Store"
        with self.assertRaisesRegex(
            VERIFY.CANARY.VerificationError,
            "not identical",
        ):
            VERIFY.validate_policy_patch(
                pr_files=[file_record(one_line, 1)],
                commit_files=[file_record(two_lines, 2)],
            )


if __name__ == "__main__":
    unittest.main()
