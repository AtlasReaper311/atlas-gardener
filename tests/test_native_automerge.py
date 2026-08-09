from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/gardener_native_automerge.py"
WORKFLOW = ROOT / ".github/workflows/gardener-automerge-gate.yml"
SPEC = importlib.util.spec_from_file_location("gardener_native_automerge", SCRIPT)
assert SPEC and SPEC.loader
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)

PR_URL = "https://github.com/AtlasReaper311/atlas-dora/pull/27"
EXPECTED_HEAD = "a" * 40
PR_ID = "PR_kwDOExample"


def squash_request(*, login: str = "github-actions[bot]") -> dict[str, Any]:
    return {
        "enabledAt": "2026-07-22T21:00:00Z",
        "enabledBy": {"login": login},
        "mergeMethod": "SQUASH",
    }


def pr_view(
    *,
    state: str = "OPEN",
    head: str = EXPECTED_HEAD,
    request: Any = None,
    include_id: bool = True,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "state": state,
        "headRefOid": head,
        "autoMergeRequest": request,
    }
    if include_id:
        document["id"] = PR_ID
    return document


def mutation_document(
    *,
    state: str = "OPEN",
    head: str = EXPECTED_HEAD,
    request: Any = None,
) -> dict[str, Any]:
    return {
        "data": {
            "enablePullRequestAutoMerge": {
                "pullRequest": {
                    "state": state,
                    "headRefOid": head,
                    "autoMergeRequest": request,
                }
            }
        }
    }


class FakeRunner:
    def __init__(
        self,
        *,
        views: Sequence[dict[str, Any]],
        mutation: dict[str, Any] | None = None,
    ) -> None:
        self._views = list(views)
        self._mutation = mutation
        self.calls: list[list[str]] = []
        self.mutation_calls = 0
        self.sleeps: list[float] = []

    def __call__(self, arguments: Sequence[str]) -> str:
        args = list(arguments)
        self.calls.append(args)
        if args[:2] == ["pr", "view"]:
            if not self._views:
                raise AssertionError(f"unexpected gh pr view: {args}")
            return json.dumps(self._views.pop(0))
        if args[:2] == ["api", "graphql"]:
            self.mutation_calls += 1
            if self._mutation is None:
                raise AssertionError("unexpected GraphQL mutation")
            joined = " ".join(args)
            if "enablePullRequestAutoMerge" not in joined:
                raise AssertionError("mutation query missing enablePullRequestAutoMerge")
            if "mergeMethod: SQUASH" not in joined:
                raise AssertionError("mutation query missing mergeMethod: SQUASH")
            if f"pullRequestId={PR_ID}" not in joined:
                raise AssertionError("mutation missing expected pull request id")
            return json.dumps(self._mutation)
        raise AssertionError(f"unexpected gh invocation: {args}")

    def sleeper(self, seconds: float) -> None:
        self.sleeps.append(seconds)


class NativeAutomergeTests(unittest.TestCase):
    def enable(
        self,
        runner: FakeRunner,
        *,
        poll_attempts: int = 10,
        poll_sleep_seconds: float = 2.0,
    ) -> str:
        return NATIVE.enable_native_automerge(
            PR_URL,
            EXPECTED_HEAD,
            runner=runner,
            sleeper=runner.sleeper,
            poll_attempts=poll_attempts,
            poll_sleep_seconds=poll_sleep_seconds,
        )

    def test_historical_null_automerge_request_after_successful_mutation_fails(
        self,
    ) -> None:
        runner = FakeRunner(
            views=[pr_view(request=None)],
            mutation=mutation_document(request=None),
        )
        with self.assertRaisesRegex(
            NATIVE.NativeAutomergeError,
            "GitHub did not create an autoMergeRequest",
        ):
            self.enable(runner)
        self.assertEqual(runner.mutation_calls, 1)
        self.assertEqual(len(runner.calls), 2)

    def test_valid_enablement_and_retention_succeeds(self) -> None:
        runner = FakeRunner(
            views=[
                pr_view(request=None),
                pr_view(request=squash_request(), include_id=False),
            ],
            mutation=mutation_document(request=squash_request()),
        )
        result = self.enable(runner)
        self.assertEqual(result, "github-actions[bot]")
        self.assertEqual(runner.mutation_calls, 1)
        self.assertEqual(runner.sleeps, [])

    def test_head_movement_before_enablement_fails(self) -> None:
        runner = FakeRunner(
            views=[pr_view(head="b" * 40, request=None)],
            mutation=mutation_document(request=squash_request()),
        )
        with self.assertRaisesRegex(
            NATIVE.NativeAutomergeError,
            "pull request head changed before auto-merge enablement",
        ):
            self.enable(runner)
        self.assertEqual(runner.mutation_calls, 0)

    def test_head_movement_during_mutation_result_fails(self) -> None:
        runner = FakeRunner(
            views=[pr_view(request=None)],
            mutation=mutation_document(head="b" * 40, request=squash_request()),
        )
        with self.assertRaisesRegex(
            NATIVE.NativeAutomergeError,
            "pull request head changed during auto-merge enablement",
        ):
            self.enable(runner)
        self.assertEqual(runner.mutation_calls, 1)

    def test_head_movement_during_polling_fails(self) -> None:
        runner = FakeRunner(
            views=[
                pr_view(request=None),
                pr_view(head="b" * 40, request=None, include_id=False),
            ],
            mutation=mutation_document(request=squash_request()),
        )
        with self.assertRaisesRegex(
            NATIVE.NativeAutomergeError,
            "pull request head changed before the auto-merge postcondition",
        ):
            self.enable(runner, poll_attempts=3)

    def test_wrong_merge_method_after_mutation_fails(self) -> None:
        request = squash_request()
        request["mergeMethod"] = "MERGE"
        runner = FakeRunner(
            views=[pr_view(request=None)],
            mutation=mutation_document(request=request),
        )
        with self.assertRaisesRegex(
            NATIVE.NativeAutomergeError,
            "unexpected merge method",
        ):
            self.enable(runner)

    def test_wrong_merge_method_during_retention_polling_fails(self) -> None:
        retained = squash_request()
        retained["mergeMethod"] = "REBASE"
        runner = FakeRunner(
            views=[
                pr_view(request=None),
                pr_view(request=retained, include_id=False),
            ],
            mutation=mutation_document(request=squash_request()),
        )
        with self.assertRaisesRegex(
            NATIVE.NativeAutomergeError,
            "unexpected merge method during retention polling",
        ):
            self.enable(runner, poll_attempts=3)

    def test_missing_enabling_actor_fails(self) -> None:
        request = {
            "enabledAt": "2026-07-22T21:00:00Z",
            "enabledBy": {"login": ""},
            "mergeMethod": "SQUASH",
        }
        runner = FakeRunner(
            views=[pr_view(request=None)],
            mutation=mutation_document(request=request),
        )
        with self.assertRaisesRegex(
            NATIVE.NativeAutomergeError,
            "does not identify its enabling actor",
        ):
            self.enable(runner)

    def test_request_dropped_after_successful_mutation_fails(self) -> None:
        runner = FakeRunner(
            views=[
                pr_view(request=None),
                pr_view(request=None, include_id=False),
                pr_view(request=None, include_id=False),
                pr_view(request=None, include_id=False),
            ],
            mutation=mutation_document(request=squash_request()),
        )
        with self.assertRaisesRegex(
            NATIVE.NativeAutomergeError,
            "GitHub did not retain the native autoMergeRequest",
        ):
            self.enable(runner, poll_attempts=3, poll_sleep_seconds=0.01)
        self.assertEqual(runner.mutation_calls, 1)
        self.assertEqual(runner.sleeps, [0.01, 0.01])

    def test_valid_already_enabled_request_short_circuits(self) -> None:
        runner = FakeRunner(
            views=[pr_view(request=squash_request(login="octocat"))],
            mutation=mutation_document(request=squash_request()),
        )
        result = self.enable(runner)
        self.assertEqual(result, "already-enabled")
        self.assertEqual(runner.mutation_calls, 0)
        self.assertEqual(len(runner.calls), 1)

    def test_invalid_already_enabled_wrong_merge_method_fails(self) -> None:
        request = squash_request()
        request["mergeMethod"] = "MERGE"
        runner = FakeRunner(
            views=[pr_view(request=request)],
            mutation=mutation_document(request=squash_request()),
        )
        with self.assertRaisesRegex(
            NATIVE.NativeAutomergeError,
            "unexpected merge method for already-enabled request",
        ):
            self.enable(runner)
        self.assertEqual(runner.mutation_calls, 0)

    def test_invalid_already_enabled_missing_actor_fails(self) -> None:
        request = {
            "enabledAt": "2026-07-22T21:00:00Z",
            "enabledBy": {},
            "mergeMethod": "SQUASH",
        }
        runner = FakeRunner(
            views=[pr_view(request=request)],
            mutation=mutation_document(request=squash_request()),
        )
        with self.assertRaisesRegex(
            NATIVE.NativeAutomergeError,
            "does not identify its enabling actor for already-enabled request",
        ):
            self.enable(runner)
        self.assertEqual(runner.mutation_calls, 0)

    def test_closed_pull_request_before_enablement_fails(self) -> None:
        runner = FakeRunner(
            views=[pr_view(state="MERGED", request=None)],
            mutation=mutation_document(request=squash_request()),
        )
        with self.assertRaisesRegex(
            NATIVE.NativeAutomergeError,
            "pull request is no longer open before auto-merge enablement",
        ):
            self.enable(runner)

    def test_mutation_missing_pull_request_object_fails(self) -> None:
        runner = FakeRunner(
            views=[pr_view(request=None)],
            mutation={"data": {"enablePullRequestAutoMerge": {}}},
        )
        with self.assertRaisesRegex(
            NATIVE.NativeAutomergeError,
            "mutation result does not contain the expected pull request object",
        ):
            self.enable(runner)

    def test_workflow_enablement_invokes_script_and_rejects_gh_pr_merge_auto(
        self,
    ) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        enable_marker = "- name: Enable native squash auto-merge"
        cleanup_marker = "- name: Revoke workflow-owned auto-merge after refusal"
        enable_index = text.index(enable_marker)
        cleanup_index = text.index(cleanup_marker)
        enable_section = text[enable_index:cleanup_index]
        self.assertIn(
            ".atlas-gardener/scripts/gardener_native_automerge.py",
            enable_section,
        )
        self.assertIn("--pr-url", enable_section)
        self.assertIn("--expected-head-sha", enable_section)
        self.assertNotIn("gh pr merge --auto", enable_section)
        self.assertNotIn("gh pr merge --auto", text)
        self.assertIn('gh pr merge "$PR_URL" --disable-auto', text)
        self.assertIn(
            ".atlas-gardener/scripts/gardener_native_automerge.py",
            text,
        )
        compile_index = text.index("python3 -m py_compile")
        compile_block = text[compile_index:enable_index]
        self.assertIn(
            ".atlas-gardener/scripts/gardener_native_automerge.py",
            compile_block,
        )


if __name__ == "__main__":
    unittest.main()
