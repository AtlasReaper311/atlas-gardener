from __future__ import annotations

import copy
import hashlib
import unittest
import urllib.parse
from datetime import datetime, timedelta, timezone

from atlas_gardener.automatic_github import (
    RestControllerTransport,
    find_existing,
    prepare_commit,
    publish_prepared,
    resolve_publication_plan,
)
from atlas_gardener.automation import approval_marker
from atlas_gardener.contracts import sha256_value
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.github_app_pr import _plan_digest


class FakeTransport:
    def __init__(self, plan: dict) -> None:
        self.plan = plan
        self.calls: list[tuple[str, str, dict | None, bool]] = []
        self.branch_exists = False
        self.pull_list: list[dict] = []
        self.pull_lists: dict[str, list[dict]] = {}
        self.blobs = 0

    def request(self, method, path, *, token, payload=None, allow_not_found=False):
        self.calls.append((method, path, payload, allow_not_found))
        if "/pulls?" in path:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            head = query.get("head", [""])[0]
            branch = head.split(":", 1)[-1]
            if branch in self.pull_lists:
                return self.pull_lists[branch]
            return self.pull_list if branch == self.plan["branch"] else []
        if "/git/ref/heads/main" in path:
            return {"object": {"sha": self.plan["base_sha"]}}
        if "/git/ref/heads/gardener%2F" in path:
            return {"object": {"sha": "3" * 40}} if self.branch_exists else None
        if method == "GET" and "/git/commits/" in path:
            return {"tree": {"sha": "1" * 40}}
        if method == "POST" and path.endswith("/git/blobs"):
            self.blobs += 1
            return {"sha": f"{self.blobs:040x}"}
        if method == "POST" and path.endswith("/git/trees"):
            return {"sha": "2" * 40}
        if method == "POST" and path.endswith("/git/commits"):
            return {"sha": "3" * 40}
        if method == "POST" and path.endswith("/git/refs"):
            self.branch_exists = True
            return {}
        if method == "POST" and path.endswith("/pulls"):
            return {
                "number": 42,
                "html_url": "https://github.com/AtlasReaper311/example/pull/42",
                "draft": bool(payload["draft"]),
            }
        return {}


def make_plan() -> dict:
    after = "node_modules/\n\n.DS_Store\n"
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
        "fixer": {"id": "macos-metadata-ignore", "version": "0.1.0"},
        "risk_class": "low",
        "repository": "AtlasReaper311/example",
        "classification": classification,
        "classification_fingerprint": sha256_value(classification),
        "base_branch": "main",
        "base_sha": "a" * 40,
        "branch": "gardener/macos-metadata-ignore-" + "b" * 12,
        "commit_message": "chore: apply reviewed gardener proposal macos-metadata-ignore",
        "pr_title": "chore: gardener remediation macos-metadata-ignore",
        "files": [
            {
                "path": ".gitignore",
                "action": "replace",
                "mode": "100644",
                "expected_blob_sha": "e" * 40,
                "before_sha256": "f" * 64,
                "after_sha256": hashlib.sha256(after.encode("utf-8")).hexdigest(),
                "after_text": after,
            }
        ],
        "validation_plan": [
            {
                "check_id": "repository-tests",
                "command": "git diff --check",
                "expected": "exit code 0",
            }
        ],
        "rollback_plan": ["Close the unmerged pull request."],
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


def make_approval(plan: dict, commit_sha: str) -> dict:
    return {
        "schema_version": "atlas-control-plane/gardener-automation-approval/v1",
        "approval_id": "approval:sha256:" + "1" * 64,
        "remediation_key": "sha256:" + "2" * 64,
        "plan_digest": plan["plan_digest"],
        "expected_head_sha": commit_sha,
        "base_sha": plan["base_sha"],
        "patch_digest": plan["patch_digest"],
        "mode": "automerge-low-risk",
    }


class AutomaticGitHubTests(unittest.TestCase):
    def test_endpoint_allowlist_has_no_merge_or_actions_write(self) -> None:
        self.assertTrue(
            RestControllerTransport._allowed(
                "GET",
                "/repos/AtlasReaper311/example/pulls?state=all&head=AtlasReaper311%3Agardener%2Ffix&base=main&per_page=100",
                False,
            )
        )
        for method, path in (
            ("PUT", "/repos/AtlasReaper311/example/pulls/42/merge"),
            ("POST", "/repos/AtlasReaper311/example/actions/workflows/1/dispatches"),
            ("PATCH", "/repos/AtlasReaper311/example"),
            ("DELETE", "/repos/AtlasReaper311/example/git/refs/heads/main"),
        ):
            self.assertFalse(RestControllerTransport._allowed(method, path, False))

    def test_prepare_and_publish_exact_ready_pr(self) -> None:
        plan = make_plan()
        transport = FakeTransport(plan)
        prepared = prepare_commit(
            plan=plan,
            token="installation-token-that-is-long-enough",
            transport=transport,
        )
        approval = make_approval(plan, prepared["commit_sha"])
        result = publish_prepared(
            plan=plan,
            prepared=prepared,
            approval=approval,
            token="installation-token-that-is-long-enough",
            ready=True,
            transport=transport,
        )
        self.assertFalse(result["pull_request"]["draft"])
        self.assertTrue(result["target_gate_requested"])
        pull_payload = next(
            payload
            for method, path, payload, _ in transport.calls
            if method == "POST" and path.endswith("/pulls")
        )
        self.assertFalse(pull_payload["draft"])
        self.assertIn("atlas-gardener-approval:", pull_payload["body"])
        self.assertFalse(any("/merge" in path for _, path, _, _ in transport.calls))
        self.assertFalse(any("/actions/" in path for _, path, _, _ in transport.calls))

    def test_changed_head_refuses_before_branch_publication(self) -> None:
        plan = make_plan()
        transport = FakeTransport(plan)
        prepared = prepare_commit(
            plan=plan,
            token="installation-token-that-is-long-enough",
            transport=transport,
        )
        approval = make_approval(plan, "9" * 40)
        before = len(transport.calls)
        with self.assertRaisesRegex(SafetyRefusal, "bind the prepared commit"):
            publish_prepared(
                plan=plan,
                prepared=prepared,
                approval=approval,
                token="installation-token-that-is-long-enough",
                ready=True,
                transport=transport,
            )
        self.assertEqual(before, len(transport.calls))

    def test_existing_open_or_merged_pr_is_idempotent(self) -> None:
        plan = make_plan()
        transport = FakeTransport(plan)
        approval = make_approval(plan, "3" * 40)
        body = approval_marker(approval)
        transport.pull_list = [
            {
                "number": 42,
                "html_url": "https://github.com/AtlasReaper311/example/pull/42",
                "body": body,
                "state": "open",
                "merged_at": None,
            }
        ]
        found = find_existing(
            plan=plan,
            remediation_key=approval["remediation_key"],
            token="installation-token-that-is-long-enough",
            transport=transport,
        )
        self.assertEqual(42, found["number"])
        self.assertTrue(all(method == "GET" for method, _, _, _ in transport.calls))

        transport.calls.clear()
        transport.pull_list[0]["state"] = "closed"
        transport.pull_list[0]["merged_at"] = "2026-07-22T10:00:00Z"
        found = find_existing(
            plan=plan,
            remediation_key=approval["remediation_key"],
            token="installation-token-that-is-long-enough",
            transport=transport,
        )
        self.assertIsNotNone(found["merged_at"])
        self.assertTrue(all(method == "GET" for method, _, _, _ in transport.calls))

    def test_exact_closed_unmerged_pr_respects_owner_closure(self) -> None:
        plan = make_plan()
        transport = FakeTransport(plan)
        approval = make_approval(plan, "3" * 40)
        closed = {
            "number": 42,
            "html_url": "https://github.com/AtlasReaper311/example/pull/42",
            "body": approval_marker(approval),
            "state": "closed",
            "merged_at": None,
        }
        transport.pull_list = [closed]
        selected, found = resolve_publication_plan(
            plan=plan,
            remediation_key=approval["remediation_key"],
            token="installation-token-that-is-long-enough",
            transport=transport,
        )
        self.assertEqual(plan, selected)
        self.assertEqual(42, found["number"])

    def test_closed_obsolete_patch_selects_deterministic_replacement(self) -> None:
        plan = make_plan()
        transport = FakeTransport(plan)
        stale_plan = copy.deepcopy(plan)
        stale_plan["patch_digest"] = "sha256:" + "9" * 64
        stale_plan["plan_digest"] = _plan_digest(stale_plan)
        stale_approval = make_approval(stale_plan, "3" * 40)
        transport.pull_list = [
            {
                "number": 42,
                "html_url": "https://github.com/AtlasReaper311/example/pull/42",
                "body": approval_marker(stale_approval),
                "state": "closed",
                "merged_at": None,
            }
        ]
        selected, found = resolve_publication_plan(
            plan=plan,
            remediation_key=stale_approval["remediation_key"],
            token="installation-token-that-is-long-enough",
            transport=transport,
        )
        self.assertIsNone(found)
        self.assertEqual(
            "gardener/macos-metadata-ignore-222222222222-r-dddddddddddd",
            selected["branch"],
        )
        self.assertNotEqual(plan["plan_digest"], selected["plan_digest"])
        self.assertEqual(selected["plan_digest"], _plan_digest(selected))

    def test_exact_replacement_pr_is_idempotent(self) -> None:
        plan = make_plan()
        transport = FakeTransport(plan)
        stale_plan = copy.deepcopy(plan)
        stale_plan["patch_digest"] = "sha256:" + "9" * 64
        stale_plan["plan_digest"] = _plan_digest(stale_plan)
        stale_approval = make_approval(stale_plan, "3" * 40)
        transport.pull_list = [
            {
                "number": 42,
                "body": approval_marker(stale_approval),
                "state": "closed",
                "merged_at": None,
            }
        ]
        replacement = copy.deepcopy(plan)
        replacement["branch"] = (
            "gardener/macos-metadata-ignore-222222222222-r-dddddddddddd"
        )
        replacement["plan_digest"] = _plan_digest(replacement)
        replacement_approval = make_approval(replacement, "4" * 40)
        transport.pull_lists[replacement["branch"]] = [
            {
                "number": 43,
                "html_url": "https://github.com/AtlasReaper311/example/pull/43",
                "body": approval_marker(replacement_approval),
                "state": "open",
                "merged_at": None,
            }
        ]
        selected, found = resolve_publication_plan(
            plan=plan,
            remediation_key=stale_approval["remediation_key"],
            token="installation-token-that-is-long-enough",
            transport=transport,
        )
        self.assertEqual(replacement["branch"], selected["branch"])
        self.assertEqual(43, found["number"])

    def test_conflicting_open_plan_fails_closed(self) -> None:
        plan = make_plan()
        transport = FakeTransport(plan)
        stale_plan = copy.deepcopy(plan)
        stale_plan["patch_digest"] = "sha256:" + "9" * 64
        stale_plan["plan_digest"] = _plan_digest(stale_plan)
        stale_approval = make_approval(stale_plan, "3" * 40)
        transport.pull_list = [
            {
                "number": 42,
                "body": approval_marker(stale_approval),
                "state": "open",
                "merged_at": None,
            }
        ]
        with self.assertRaisesRegex(SafetyRefusal, "conflicts with the current"):
            resolve_publication_plan(
                plan=plan,
                remediation_key=stale_approval["remediation_key"],
                token="installation-token-that-is-long-enough",
                transport=transport,
            )

    def test_duplicate_remediation_prs_fail_closed(self) -> None:
        plan = make_plan()
        transport = FakeTransport(plan)
        approval = make_approval(plan, "3" * 40)
        value = {
            "number": 42,
            "body": approval_marker(approval),
            "state": "open",
        }
        transport.pull_list = [value, copy.deepcopy(value)]
        with self.assertRaisesRegex(SafetyRefusal, "multiple pull requests"):
            find_existing(
                plan=plan,
                remediation_key=approval["remediation_key"],
                token="installation-token-that-is-long-enough",
                transport=transport,
            )


if __name__ == "__main__":
    unittest.main()
