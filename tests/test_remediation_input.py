from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import atlas_gardener.github_app_pr as github_app_pr
from atlas_gardener.engine import apply_proposal, propose
from atlas_gardener.contracts import write_json
from tests.helpers import contracts, make_finding, make_fixture_repository


class RemediationInputTests(unittest.TestCase):
    def candidate_finding(self, contract_set, repository: str) -> dict:
        finding = make_finding(
            contract_set,
            repository=repository,
            rule_id="dependency-vulnerability",
            location="requirements.txt:1",
        )
        finding["category"] = "security"
        finding["remediation"]["candidate"] = {
            "kind": "dependency-update",
            "ecosystem": "PyPI",
            "dependency": "example",
            "current_version": "1.2.3",
            "target_version": "1.2.4",
            "source_file": "requirements.txt",
            "update_class": "patch",
            "direct": True,
            "vulnerability_ids": ["GHSA-test-0001"],
        }
        return contract_set.validate_finding(finding)

    def test_proposal_binds_candidate_and_regenerates_exactly(self) -> None:
        contract_set = contracts()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = make_fixture_repository(root, "fixture-repo")
            (repository / "requirements.txt").write_text(
                "example==1.2.3\n", encoding="utf-8"
            )
            finding = self.candidate_finding(contract_set, repository.name)
            proposal, plan, _ = propose(finding, repository, contract_set)

            self.assertEqual("python-security-pin", proposal["fixer"]["id"])
            self.assertEqual("medium", proposal["risk_class"])
            self.assertEqual(
                finding["remediation"]["candidate"], proposal["remediation_input"]
            )
            self.assertEqual(["requirements.txt"], plan.files_affected)

            proposal_path = root / "proposal.json"
            write_json(proposal_path, proposal)
            result = apply_proposal(
                proposal_path,
                repository,
                contract_set,
                apply=False,
            )
            self.assertFalse(result["applied"])
            self.assertEqual(plan.patch_digest, result["patch_digest"])

            regenerated_proposal, regenerated_plan, _ = github_app_pr._regenerate_reviewed_plan(
                proposal_path=proposal_path,
                repository=repository,
                contracts=contract_set,
                pins_file=None,
            )
            self.assertEqual(proposal["proposal_id"], regenerated_proposal["proposal_id"])
            self.assertEqual(plan.patch_digest, regenerated_plan.patch_digest)


if __name__ == "__main__":
    unittest.main()
