from __future__ import annotations

import copy
import unittest

from atlas_gardener.errors import GardenerError, SafetyRefusal
from atlas_gardener.github_app_pr import (
    _plan_digest,
    apply_pr_plan,
    plan_summary,
    validate_pr_plan,
)


class FakeTransport:
    def __init__(self, *, base_sha: str, branch_exists: bool = False) -> None:
        self.base_sha = base_sha
        self.branch_exists = branch_exists
        self.calls: list[tuple[str, str, dict | None]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: dict | None = None,
        allow_not_found: bool = False,
    ):
        self.calls.append((method, path, payload))
        if "/git/ref/heads/main" in path:
            return {"object": {"sha": self.base_sha}}
        if "/git/ref/heads/gardener%2F" in path:
            if self.branch_exists:
                return {"object": {"sha": self.base_sha}}
            return None if allow_not_found else {}
        if path.endswith("/pulls") and method == "POST":
            return {
                "number": 42,
                "html_url": "https://github.com/AtlasReaper311/example/pull/42",
                "draft": True,
            }
        return {}


def make_plan() -> dict:
    base_sha = "a" * 40
    plan = {
        "schema_version": "atlas-gardener/github-app-pr-plan/v1",
        "plan_digest": "sha256:" + "0" * 64,
        "proposal_id": "proposal:sha256:" + "b" * 64,
        "finding_fingerprint": "sha256:" + "c" * 64,
        "patch_digest": "sha256:" + "d" * 64,
        "repository": "AtlasReaper311/example",
        "base_branch": "main",
        "base_sha": base_sha,
        "branch": "gardener/readme-contract-" + "b" * 12,
        "commit_message": "chore: apply reviewed gardener proposal",
        "pr_title": "chore: gardener remediation readme-contract",
        "files": [
            {
                "path": "README.md",
                "action": "replace",
                "expected_blob_sha": "e" * 40,
                "before_sha256": "f" * 64,
                "after_sha256": None,
                "after_text": "reviewed content\n",
            }
        ],
        "validation_plan": [
            {
                "command": "python3 scripts/validate.py",
                "expected": "exit code 0",
            }
        ],
        "expires_at": "2099-01-01T00:00:00Z",
        "permissions_required": {
            "metadata": "read",
            "contents": "write",
            "pull_requests": "write",
        },
        "stop_after": "draft-pull-request",
    }
    import hashlib

    plan["files"][0]["after_sha256"] = hashlib.sha256(
        plan["files"][0]["after_text"].encode("utf-8")
    ).hexdigest()
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

    def test_summary_does_not_repeat_file_contents(self) -> None:
        plan = make_plan()
        summary = plan_summary(plan)
        rendered = str(summary)
        self.assertNotIn("reviewed content", rendered)
        self.assertNotIn("installation", rendered.lower())
        self.assertFalse(summary["network_access"])
        self.assertFalse(summary["provider_mutation"])

    def test_apply_creates_branch_exact_file_and_draft_pr_then_stops(self) -> None:
        plan = make_plan()
        transport = FakeTransport(base_sha=plan["base_sha"])
        result = apply_pr_plan(
            plan,
            approved_plan_digest=plan["plan_digest"],
            token="installation-token-that-is-long-enough",
            transport=transport,
        )

        self.assertTrue(result["draft_pull_request"]["draft"])
        self.assertTrue(result["stopped"])
        methods_and_paths = [(method, path) for method, path, _ in transport.calls]
        self.assertIn(
            ("POST", "/repos/AtlasReaper311/example/git/refs"),
            methods_and_paths,
        )
        self.assertIn(
            ("PUT", "/repos/AtlasReaper311/example/contents/README.md"),
            methods_and_paths,
        )
        self.assertIn(
            ("POST", "/repos/AtlasReaper311/example/pulls"),
            methods_and_paths,
        )
        self.assertFalse(any("merge" in path for _, path in methods_and_paths))
        self.assertFalse(any("actions" in path for _, path in methods_and_paths))
        pull_payload = next(
            payload
            for method, path, payload in transport.calls
            if method == "POST" and path.endswith("/pulls")
        )
        self.assertTrue(pull_payload["draft"])

    def test_base_branch_drift_refuses_before_remote_mutation(self) -> None:
        plan = make_plan()
        transport = FakeTransport(base_sha="9" * 40)
        with self.assertRaisesRegex(SafetyRefusal, "remote base branch changed"):
            apply_pr_plan(
                plan,
                approved_plan_digest=plan["plan_digest"],
                token="installation-token-that-is-long-enough",
                transport=transport,
            )
        self.assertTrue(all(method == "GET" for method, _, _ in transport.calls))

    def test_existing_remote_branch_refuses_before_write(self) -> None:
        plan = make_plan()
        transport = FakeTransport(base_sha=plan["base_sha"], branch_exists=True)
        with self.assertRaisesRegex(SafetyRefusal, "branch already exists"):
            apply_pr_plan(
                plan,
                approved_plan_digest=plan["plan_digest"],
                token="installation-token-that-is-long-enough",
                transport=transport,
            )
        self.assertTrue(all(method == "GET" for method, _, _ in transport.calls))

    def test_unapproved_digest_refuses_without_network(self) -> None:
        plan = make_plan()
        transport = FakeTransport(base_sha=plan["base_sha"])
        with self.assertRaisesRegex(SafetyRefusal, "approved plan digest"):
            apply_pr_plan(
                plan,
                approved_plan_digest="sha256:" + "0" * 64,
                token="installation-token-that-is-long-enough",
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
                transport=transport,
            )
        self.assertEqual([], transport.calls)


if __name__ == "__main__":
    unittest.main()
