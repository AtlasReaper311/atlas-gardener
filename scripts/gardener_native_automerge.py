#!/usr/bin/env python3
"""Enable and verify GitHub native squash auto-merge for one Gardener PR.

Production transport is the authenticated ``gh`` CLI. External command execution
and sleep are injectable so offline unit tests can exercise postconditions
without network access or real pull-request mutation.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from typing import Any, Callable, Sequence

CommandRunner = Callable[[Sequence[str]], str]
Sleeper = Callable[[float], None]

DEFAULT_POLL_ATTEMPTS = 10
DEFAULT_POLL_SLEEP_SECONDS = 2.0

ENABLE_MUTATION = """
mutation EnableGardenerAutoMerge($pullRequestId: ID!) {
  enablePullRequestAutoMerge(
    input: {
      pullRequestId: $pullRequestId
      mergeMethod: SQUASH
    }
  ) {
    pullRequest {
      state
      headRefOid
      autoMergeRequest {
        enabledAt
        enabledBy {
          login
        }
        mergeMethod
      }
    }
  }
}
""".strip()


class NativeAutomergeError(RuntimeError):
    """Raised when native auto-merge enablement or postconditions fail closed."""


def default_runner(arguments: Sequence[str]) -> str:
    """Run one ``gh`` command and return stdout, failing closed on non-zero exit."""
    completed = subprocess.run(
        ["gh", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown gh failure"
        raise NativeAutomergeError(
            f"gh {' '.join(arguments[:3])} failed: {detail[:300]}"
        )
    return completed.stdout


def validate_pull_request_state(
    document: dict[str, Any],
    expected_head_sha: str,
    *,
    stage: str,
) -> None:
    """Require an OPEN pull request on the exact expected head SHA."""
    if document.get("state") != "OPEN":
        raise NativeAutomergeError(f"pull request is no longer open {stage}")
    if document.get("headRefOid") != expected_head_sha:
        raise NativeAutomergeError(f"pull request head changed {stage}")


def validate_auto_merge_request(request: Any, *, stage: str) -> str:
    """Require a retained SQUASH autoMergeRequest with a non-empty enabling actor."""
    if not isinstance(request, dict):
        raise NativeAutomergeError(f"GitHub did not create an autoMergeRequest {stage}")
    if request.get("mergeMethod") != "SQUASH":
        raise NativeAutomergeError(
            f"GitHub created auto-merge with an unexpected merge method {stage}"
        )
    enabled_by = (request.get("enabledBy") or {}).get("login")
    if not isinstance(enabled_by, str) or not enabled_by:
        raise NativeAutomergeError(
            f"autoMergeRequest does not identify its enabling actor {stage}"
        )
    return enabled_by


def _load_json_object(payload: str, label: str) -> dict[str, Any]:
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as error:
        raise NativeAutomergeError(f"{label} is not valid JSON") from error
    if not isinstance(document, dict):
        raise NativeAutomergeError(f"{label} must be a JSON object")
    return document


def _view_pull_request(
    pr_url: str,
    *,
    runner: CommandRunner,
    fields: str,
) -> dict[str, Any]:
    payload = runner(["pr", "view", pr_url, "--json", fields])
    return _load_json_object(payload, "pull request view")


def _mutation_pull_request(
    document: dict[str, Any],
) -> dict[str, Any]:
    data = document.get("data")
    if not isinstance(data, dict):
        raise NativeAutomergeError(
            "mutation result does not contain the expected pull request object"
        )
    payload = data.get("enablePullRequestAutoMerge")
    if not isinstance(payload, dict):
        raise NativeAutomergeError(
            "mutation result does not contain the expected pull request object"
        )
    pull_request = payload.get("pullRequest")
    if not isinstance(pull_request, dict):
        raise NativeAutomergeError(
            "mutation result does not contain the expected pull request object"
        )
    return pull_request


def enable_pull_request_auto_merge(
    pull_request_id: str,
    *,
    runner: CommandRunner,
) -> dict[str, Any]:
    """Invoke enablePullRequestAutoMerge with mergeMethod SQUASH and return the PR."""
    payload = runner(
        [
            "api",
            "graphql",
            "-f",
            f"query={ENABLE_MUTATION}",
            "-F",
            f"pullRequestId={pull_request_id}",
        ]
    )
    document = _load_json_object(payload, "auto-merge mutation")
    return _mutation_pull_request(document)


def poll_native_automerge(
    pr_url: str,
    expected_head_sha: str,
    *,
    runner: CommandRunner,
    sleeper: Sleeper,
    poll_attempts: int = DEFAULT_POLL_ATTEMPTS,
    poll_sleep_seconds: float = DEFAULT_POLL_SLEEP_SECONDS,
) -> str:
    """Poll until GitHub retains a valid SQUASH autoMergeRequest or fail closed."""
    if poll_attempts < 1:
        raise NativeAutomergeError("poll attempt bound must be at least 1")
    for attempt in range(1, poll_attempts + 1):
        document = _view_pull_request(
            pr_url,
            runner=runner,
            fields="state,headRefOid,autoMergeRequest",
        )
        if document.get("state") != "OPEN":
            raise NativeAutomergeError(
                "pull request closed before the auto-merge postcondition was verified"
            )
        if document.get("headRefOid") != expected_head_sha:
            raise NativeAutomergeError(
                "pull request head changed before the auto-merge postcondition was verified"
            )
        request = document.get("autoMergeRequest")
        if request is None:
            if attempt == poll_attempts:
                raise NativeAutomergeError(
                    "GitHub did not retain the native autoMergeRequest"
                )
            sleeper(poll_sleep_seconds)
            continue
        return validate_auto_merge_request(request, stage="during retention polling")
    raise NativeAutomergeError("GitHub did not retain the native autoMergeRequest")


def enable_native_automerge(
    pr_url: str,
    expected_head_sha: str,
    *,
    runner: CommandRunner | None = None,
    sleeper: Sleeper | None = None,
    poll_attempts: int = DEFAULT_POLL_ATTEMPTS,
    poll_sleep_seconds: float = DEFAULT_POLL_SLEEP_SECONDS,
) -> str:
    """Enable native squash auto-merge and verify GitHub retained the request."""
    active_runner = runner or default_runner
    active_sleeper = sleeper or time.sleep

    before = _view_pull_request(
        pr_url,
        runner=active_runner,
        fields="id,state,headRefOid,autoMergeRequest",
    )
    validate_pull_request_state(
        before,
        expected_head_sha,
        stage="before auto-merge enablement",
    )

    existing = before.get("autoMergeRequest")
    if existing is not None:
        enabled_by = validate_auto_merge_request(
            existing,
            stage="for already-enabled request",
        )
        print(f"Native auto-merge is already enabled by {enabled_by}.")
        return "already-enabled"

    pull_request_id = before.get("id")
    if not isinstance(pull_request_id, str) or not pull_request_id:
        raise NativeAutomergeError("pull request id is unavailable")

    pull_request = enable_pull_request_auto_merge(
        pull_request_id,
        runner=active_runner,
    )
    validate_pull_request_state(
        pull_request,
        expected_head_sha,
        stage="during auto-merge enablement",
    )
    enabled_by = validate_auto_merge_request(
        pull_request.get("autoMergeRequest"),
        stage="after enablement mutation",
    )
    print(f"Native auto-merge armed by {enabled_by}.")

    retained_by = poll_native_automerge(
        pr_url,
        expected_head_sha,
        runner=active_runner,
        sleeper=active_sleeper,
        poll_attempts=poll_attempts,
        poll_sleep_seconds=poll_sleep_seconds,
    )
    print("Verified native autoMergeRequest postcondition.")
    return retained_by


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Enable GitHub native squash auto-merge for one PR and verify "
            "autoMergeRequest postconditions."
        )
    )
    parser.add_argument("--pr-url", required=True, help="Pull request HTML URL")
    parser.add_argument(
        "--expected-head-sha",
        required=True,
        help="Exact pull request head SHA that must remain armed",
    )
    parser.add_argument(
        "--poll-attempts",
        type=int,
        default=DEFAULT_POLL_ATTEMPTS,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--poll-sleep-seconds",
        type=float,
        default=DEFAULT_POLL_SLEEP_SECONDS,
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        enable_native_automerge(
            args.pr_url,
            args.expected_head_sha,
            poll_attempts=args.poll_attempts,
            poll_sleep_seconds=args.poll_sleep_seconds,
        )
    except NativeAutomergeError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
