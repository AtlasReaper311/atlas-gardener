from __future__ import annotations

import copy
import hashlib
import unittest
from datetime import datetime, timedelta, timezone

from atlas_gardener.contracts import sha256_value
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.github_app_pr import (
    _allowed_api_operation,
    _plan_digest,
    _pr_body,
    apply_pr_plan,
    plan_summary,
    validate_pr_plan,
)


class FakeTransport:
    def __init__(
        self,
        *,
        base_sha: str,
        branch_exists: bool = False,
        drift_after_first_base_read: bool = False,
    ) -> None:
        self.base_sha = base_sha
        self.branch_exists = branch_exists
        self.drift_after_first_base_read = drift_after_first_base_read
        self.base_reads = 0
        self.blob_count = 0
        self.calls: list[tuple[str, str, dict | None, bool]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: dict | None = None,
        allow_not_found: bool = False,
    ):
        self.calls.append((method, path, payload, allow_not_found))
        if "/git/ref/heads/main" in path:
            self.base_reads += 1
            if self.drift_after_first_base_read and self.base_reads > 1:
                return {"object": {"sha": "9" * 40}}
            return {"object": {"sha": self.base_sha}}
        if "/git/ref/heads/gardener%2F" in path:
            if self.branch_exists:
                return {"object": {"sha": self.base_sha}}
            return None if allow_not_found else {}
        if "/git/commits/" in path and method == "GET":
            return {"tree": {"sha": "1" * 40}}
        if path.endswith("/git/blobs") and method == "POST":
            self.blob_count += 1
            return {"sha": f"{self.blob_count:040x}"}
        if path.endswith("/git/trees") and method == "POST":
            return {"sha": "2" * 40}
        if path.endswith("/git/commits") and method == "POST":
            return {"sha": "3" * 40}
        if path.endswith("/pulls") and method == "POST":
            return {
                "number": 42,
                "html_url": "https://github.com/AtlasReaper311/example/pull/42",
                "draft": True,
            }
        return {}


def make_plan() -> dict:
    base_sha = "a" * 40
    after_text = "reviewed content\n"
    classification = {
        "lifecycle": "active",
        "scope": "public",
        "provenance": "original",
    }
    plan = {
        "schema_version": "atlas-gardener/github-app-pr-plan/v1",
        "plan_digest": "sha256:" + "0" * 64,
        "proposal_id": "proposal:sha256:" + "b" * 64,
        "finding_fingerprint": "sha256:" + "c" * 64,
        "patch_digest": "sha256:" + "d" * 64,
        "fixer": {"id": "readme-contract", "version": "1.0.0"},
        "risk_class": "low",
        "repository": "AtlasReaper311/example",
        "classification": classification,
        "classification_fingerprint": sha256_value(classification),
        "base_branch": "main",
        "base_sha": base_sha,
        "branch": "gardener/readme-contract-" + "b" * 12,
        "commit_message": "chore: apply reviewed gardener proposal readme-contract",
        "pr_title": "chore: gardener remediation readme-contract",
        "files": [
            {
                "path": "README.md",
                "action": "replace",
                "mode": "100644",
                "expected_blob_sha": "e" * 40,
                "before_sha256": "f" * 64,
                "after_sha256": hashlib.sha256(after_text.encode("utf-8")).hexdigest(),
                "after_text": after_text,
            }
        ],
        "validation_plan": [
            {
                "check_id": "repository-tests",
                "command": "python3 scripts/validate.py",
                "expected": "exit code 0",
            }
        ],
        "rollback_plan": [
            "Close the draft pull request and delete the unmerged branch manually."
        ],
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=1))
        .isoformat()
        .replace("+00:00", "Z"),
        "permissions_required": {
            "metadata": "read",
            "contents": "write",
            "pull_requests": "write",
        },
        "stop_after": "draft-pull-request",
    }
    plan["plan_digest"] = _plan_digest(plan)
    return plan


class GitHubAppPrTests(unittest.TestCase):
    def test_valid_plan_is_deterministic(self) -> None:
        plan = make_plan()
        self.assertEqual(plan, validate_pr_plan(copy.deepcopy(plan)))
        self.assertEqual(plan["plan_digest"], _plan_digest(plan))

    def test_tampered_file_content_fails_closed(self) -> None:
        plan = make_plan()
        plan["files"][0]["after_text"] = "different\n"
        with self.assertRaisesRegex(SafetyRefusal, "after_text digest mismatch"):
            validate_pr_plan(plan)

    def test_tampered_plan_digest_fails_closed(self) -> None:
        plan = make_plan()
        plan["pr_title"] = "different title"
        with self.assertRaisesRegex(SafetyRefusal, "plan digest"):
            validate_pr_plan(plan)

    def test_summary_does_not_repeat_file_contents_or_credentials(self) -> None:
        plan = make_plan()
        summary = plan_summary(plan)
        rendered = str(summary)
        self.assertNotIn("reviewed content", rendered)
        self.assertNotIn("installation-token", rendered)
        self.assertFalse(summary["network_access"])
        self.assertFalse(summary["provider_mutation"])

    def test_apply_creates_one_exact_commit_branch_and_draft_pr(self) -> None:
        plan = make_plan()
        transport = FakeTransport(base_sha=plan["base_sha"])
        result = apply_pr_plan(
            plan,
            approved_plan_digest=plan["plan_digest"],
            token="installation-token-that-is-long-enough",
            current_classification=plan["classification"],
            transport=transport,
        )

        self.assertEqual("3" * 40, result["commit_sha"])
        self.assertTrue(result["draft_pull_request"]["draft"])
        self.assertTrue(result["stopped"])
        methods_and_paths = [(method, path) for method, path, _, _ in transport.calls]
        self.assertEqual(
            1,
            sum(
                method == "POST" and path.endswith("/git/commits")
                for method, path in methods_and_paths
            ),
        )
        self.assertEqual(
            1,
            sum(
                method == "POST" and path.endswith("/git/refs")
                for method, path in methods_and_paths
            ),
        )
        self.assertIn(
            ("POST", "/repos/AtlasReaper311/example/pulls"),
            methods_and_paths,
        )
        self.assertFalse(any("/contents/" in path for _, path in methods_and_paths))
        self.assertFalse(any("merge" in path for _, path in methods_and_paths))
        self.assertFalse(any("actions" in path for _, path in methods_and_paths))
        commit_payload = next(
            payload
            for method, path, payload, _ in transport.calls
            if method == "POST" and path.endswith("/git/commits")
        )
        self.assertEqual([plan["base_sha"]], commit_payload["parents"])
        pull_payload = next(
            payload
            for method, path, payload, _ in transport.calls
            if method == "POST" and path.endswith("/pulls")
        )
        self.assertTrue(pull_payload["draft"])

    def test_pr_body_contains_required_review_evidence(self) -> None:
        body = _pr_body(make_plan())
        for expected in (
            "Finding fingerprint:",
            "Fixer:",
            "Proposal:",
            "Plan digest:",
            "Patch digest:",
            "Risk:",
            "Expires:",
            "Repository-owned validation",
            "Rollback",
            "did not approve or merge",
            "deploy",
        ):
            self.assertIn(expected, body)

    def test_base_branch_drift_refuses_before_remote_mutation(self) -> None:
        plan = make_plan()
        transport = FakeTransport(base_sha="9" * 40)
        with self.assertRaisesRegex(SafetyRefusal, "remote base branch changed"):
            apply_pr_plan(
                plan,
                approved_plan_digest=plan["plan_digest"],
                token="installation-token-that-is-long-enough",
                current_classification=plan["classification"],
                transport=transport,
            )
        self.assertTrue(all(method == "GET" for method, _, _, _ in transport.calls))

    def test_late_base_drift_leaves_no_remote_branch_or_pr(self) -> None:
        plan = make_plan()
        transport = FakeTransport(
            base_sha=plan["base_sha"], drift_after_first_base_read=True
        )
        with self.assertRaisesRegex(SafetyRefusal, "changed while preparing"):
            apply_pr_plan(
                plan,
                approved_plan_digest=plan["plan_digest"],
                token="installation-token-that-is-long-enough",
                current_classification=plan["classification"],
                transport=transport,
            )
        mutation_paths = [
            path for method, path, _, _ in transport.calls if method != "GET"
        ]
        self.assertFalse(any(path.endswith("/git/refs") for path in mutation_paths))
        self.assertFalse(any(path.endswith("/pulls") for path in mutation_paths))

    def test_existing_remote_branch_refuses_before_write(self) -> None:
        plan = make_plan()
        transport = FakeTransport(base_sha=plan["base_sha"], branch_exists=True)
        with self.assertRaisesRegex(SafetyRefusal, "branch already exists"):
            apply_pr_plan(
                plan,
                approved_plan_digest=plan["plan_digest"],
                token="installation-token-that-is-long-enough",
                current_classification=plan["classification"],
                transport=transport,
            )
        self.assertTrue(all(method == "GET" for method, _, _, _ in transport.calls))

    def test_unapproved_digest_refuses_without_network(self) -> None:
        plan = make_plan()
        transport = FakeTransport(base_sha=plan["base_sha"])
        with self.assertRaisesRegex(SafetyRefusal, "approved plan digest"):
            apply_pr_plan(
                plan,
                approved_plan_digest="sha256:" + "0" * 64,
                token="installation-token-that-is-long-enough",
                current_classification=plan["classification"],
                transport=transport,
            )
        self.assertEqual([], transport.calls)

    def test_changed_classification_refuses_without_network(self) -> None:
        plan = make_plan()
        transport = FakeTransport(base_sha=plan["base_sha"])
        changed = dict(plan["classification"])
        changed["lifecycle"] = "deprecated"
        with self.assertRaisesRegex(SafetyRefusal, "target classification changed"):
            apply_pr_plan(
                plan,
                approved_plan_digest=plan["plan_digest"],
                token="installation-token-that-is-long-enough",
                current_classification=changed,
                transport=transport,
            )
        self.assertEqual([], transport.calls)

    def test_short_token_refuses_without_network(self) -> None:
        plan = make_plan()
        transport = FakeTransport(base_sha=plan["base_sha"])
        with self.assertRaisesRegex(SafetyRefusal, "installation token is missing"):
            apply_pr_plan(
                plan,
                approved_plan_digest=plan["plan_digest"],
                token="short",
                current_classification=plan["classification"],
                transport=transport,
            )
        self.assertEqual([], transport.calls)

    def test_workflow_file_plan_is_refused(self) -> None:
        plan = make_plan()
        plan["files"][0]["path"] = ".github/workflows/ci.yml"
        plan["plan_digest"] = _plan_digest(plan)
        with self.assertRaisesRegex(SafetyRefusal, "workflow-file proposals"):
            validate_pr_plan(plan)

    def test_sensitive_path_is_refused_even_for_digest_valid_plan(self) -> None:
        plan = make_plan()
        plan["files"][0]["path"] = ".env.production"
        plan["plan_digest"] = _plan_digest(plan)
        with self.assertRaisesRegex(SafetyRefusal, "environment file"):
            validate_pr_plan(plan)

    def test_missing_validation_mapping_fails_closed(self) -> None:
        plan = make_plan()
        plan["validation_plan"] = []
        plan["plan_digest"] = _plan_digest(plan)
        with self.assertRaisesRegex(SafetyRefusal, "validation mapping"):
            validate_pr_plan(plan)

    def test_transport_endpoint_allowlist_is_exact(self) -> None:
        self.assertTrue(
            _allowed_api_operation(
                "POST", "/repos/AtlasReaper311/example/git/commits", False
            )
        )
        for method, path in (
            ("PUT", "/repos/AtlasReaper311/example/contents/README.md"),
            ("POST", "/repos/AtlasReaper311/example/actions/workflows/1/dispatches"),
            ("PUT", "/repos/AtlasReaper311/example/pulls/42/merge"),
            ("DELETE", "/repos/AtlasReaper311/example/git/refs/heads/main"),
            ("GET", "/repos/SomebodyElse/example/git/ref/heads/main"),
        ):
            self.assertFalse(_allowed_api_operation(method, path, False))


if __name__ == "__main__":
    unittest.main()
