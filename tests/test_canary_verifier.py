from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify_gardener_canary.py"
SPEC = importlib.util.spec_from_file_location("verify_gardener_canary", SCRIPT)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class CanaryVerifierTests(unittest.TestCase):
    def evidence(self, *, author: str = "app/atlas-gardener-w37-atlasreaper") -> dict:
        target = "AtlasReaper311/atlas-dora"
        head = "2" * 40
        merge = "5" * 40
        variables = {
            f"{repository}:{name}": value
            for (repository, name), value in VERIFY.EXPECTED_DISABLED_VARIABLES.items()
        }
        variables[f"{target}:ATLAS_GARDENER_AUTOMERGE_ENABLED"] = "false"
        return {
            "target_repository": target,
            "pull_request_number": 30,
            "gate_run_id": 29964113312,
            "expected_head_sha": head,
            "expected_merge_sha": merge,
            "expected_app_login": "atlas-gardener-w37-atlasreaper[bot]",
            "expected_gardener_ref": "8" * 40,
            "expected_authority_ref": "6" * 40,
            "pr": {
                "number": 30,
                "state": "MERGED",
                "mergedAt": "2026-07-22T22:48:53Z",
                "mergeCommit": {"oid": merge},
                "author": {"login": author},
                "headRefName": "gardener/macos-metadata-ignore-4aa01a70ecd6",
                "headRefOid": head,
                "baseRefName": "main",
                "baseRefOid": "9" * 40,
                "commits": [{"oid": head}],
                "files": [{"path": ".gitignore", "additions": 1, "deletions": 0}],
            },
            "run": {
                "id": 29964113312,
                "event": "pull_request",
                "head_sha": head,
                "status": "completed",
                "conclusion": "success",
            },
            "jobs_document": {
                "jobs": [
                    {
                        "name": VERIFY.GATE_JOB,
                        "status": "completed",
                        "conclusion": "success",
                        "steps": [
                            {
                                "name": "Revalidate the automatic approval",
                                "conclusion": "success",
                            },
                            {
                                "name": "Enable native squash auto-merge",
                                "conclusion": "success",
                            },
                            {
                                "name": "Revoke workflow-owned auto-merge after refusal",
                                "conclusion": "skipped",
                            },
                        ],
                    },
                    {
                        "name": VERIFY.BARRIER_JOB,
                        "status": "completed",
                        "conclusion": "success",
                        "steps": [
                            {
                                "name": "Hold the native auto-merge barrier",
                                "conclusion": "success",
                            }
                        ],
                    },
                    {
                        "name": "Dependabot review policy/review",
                        "status": "completed",
                        "conclusion": "skipped",
                        "steps": [],
                    },
                ]
            },
            "repository": {"full_name": target, "allow_auto_merge": False},
            "commit": {
                "sha": merge,
                "author": {"login": "atlas-gardener-w37-atlasreaper[bot]"},
                "files": [
                    {"filename": ".gitignore", "additions": 1, "deletions": 0}
                ],
            },
            "variables": variables,
            "gitignore": "node_modules/\n\n.DS_Store\n",
            "target_workflow": (
                "uses: AtlasReaper311/atlas-gardener/.github/workflows/"
                f"gardener-automerge-gate.yml@{'8' * 40}\n"
                f"authority_ref: {'6' * 40}\n"
            ),
        }

    def test_structured_success_ignores_unrelated_skipped_jobs(self) -> None:
        report = VERIFY.validate_canary(**self.evidence())
        self.assertEqual("verified", report["status"])
        self.assertTrue(report["controls_disabled"])

    def test_both_github_app_login_representations_are_accepted(self) -> None:
        for author in (
            "app/atlas-gardener-w37-atlasreaper",
            "atlas-gardener-w37-atlasreaper[bot]",
        ):
            with self.subTest(author=author):
                self.assertEqual(
                    "verified",
                    VERIFY.validate_canary(**self.evidence(author=author))["status"],
                )

    def test_native_auto_merge_step_must_succeed(self) -> None:
        evidence = self.evidence()
        gate = evidence["jobs_document"]["jobs"][0]
        gate["steps"][1]["conclusion"] = "failure"
        with self.assertRaisesRegex(VERIFY.VerificationError, "Enable native"):
            VERIFY.validate_canary(**evidence)

    def test_refusal_cleanup_must_remain_skipped(self) -> None:
        evidence = self.evidence()
        gate = evidence["jobs_document"]["jobs"][0]
        gate["steps"][2]["conclusion"] = "success"
        with self.assertRaisesRegex(VERIFY.VerificationError, "Revoke workflow-owned"):
            VERIFY.validate_canary(**evidence)

    def test_repository_auto_merge_must_return_to_false(self) -> None:
        evidence = self.evidence()
        evidence["repository"]["allow_auto_merge"] = True
        with self.assertRaisesRegex(VERIFY.VerificationError, "returned to false"):
            VERIFY.validate_canary(**evidence)

    def test_all_controls_must_return_to_disabled(self) -> None:
        evidence = self.evidence()
        key = "AtlasReaper311/atlas-gardener:ATLAS_GARDENER_MODE"
        evidence["variables"][key] = "automerge-low-risk"
        with self.assertRaisesRegex(VERIFY.VerificationError, "ATLAS_GARDENER_MODE"):
            VERIFY.validate_canary(**evidence)

    def test_gitignore_must_contain_one_rule(self) -> None:
        evidence = self.evidence()
        evidence["gitignore"] = ".DS_Store\n.DS_Store\n"
        with self.assertRaisesRegex(VERIFY.VerificationError, "exactly one"):
            VERIFY.validate_canary(**evidence)


if __name__ == "__main__":
    unittest.main()
