"""Argparse CLI for offline Atlas Gardener proposal workflows."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Sequence

from atlas_gardener import __version__
from atlas_gardener.contracts import (
    ContractSet,
    read_json,
    resolve_contracts_root,
    write_json,
)
from atlas_gardener.dependabot_rollout import execute_rollout
from atlas_gardener.engine import apply_proposal, propose, scan
from atlas_gardener.errors import GardenerError
from atlas_gardener.fixers import RULE_FIXERS
from atlas_gardener.github_app_pr import (
    apply_pr_plan,
    build_pr_plan,
    installation_token_from_environment,
    plan_summary,
    validate_pr_plan,
    verify_apply_repository,
)
from atlas_gardener.safety import MAX_CHANGED_FILES, MAX_CHANGED_LINES


def _path(value: str) -> Path:
    return Path(value).expanduser()


def _emit_json_result(result: dict[str, Any], output: Path | None = None) -> None:
    """Print one JSON result and optionally write a parse-safe receipt file."""

    if output is not None:
        write_json(output, result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


def build_parser() -> argparse.ArgumentParser:
    """Build the public CLI parser."""

    parser = argparse.ArgumentParser(
        prog="atlas-gardener",
        description="Prepare safe, deterministic, PR-only remediation proposals.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan_parser = commands.add_parser("scan", help="scan a Finding file or directory")
    scan_parser.add_argument("--findings", required=True, type=_path)
    scan_parser.add_argument("--estate-root", required=True, type=_path)
    scan_parser.add_argument("--output", required=True, type=_path)
    scan_parser.add_argument("--contracts-root", type=_path)
    scan_parser.add_argument("--pins-file", type=_path)

    propose_parser = commands.add_parser(
        "propose", help="create one RemediationProposal"
    )
    propose_parser.add_argument("--finding", required=True, type=_path)
    propose_parser.add_argument("--repo", required=True, type=_path)
    propose_parser.add_argument("--output", required=True, type=_path)
    propose_parser.add_argument("--contracts-root", type=_path)
    propose_parser.add_argument("--pins-file", type=_path)

    apply_parser = commands.add_parser(
        "apply", help="verify or locally apply a proposal"
    )
    apply_parser.add_argument("--proposal", required=True, type=_path)
    apply_parser.add_argument("--repo", required=True, type=_path)
    apply_parser.add_argument("--contracts-root", type=_path)
    apply_parser.add_argument("--pins-file", type=_path)
    mode = apply_parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run", action="store_true", help="verify only; this is the default"
    )
    mode.add_argument(
        "--apply", action="store_true", help="write a local fixture or approved target"
    )
    apply_parser.add_argument(
        "--allow-local-target",
        action="store_true",
        help="explicitly allow a clean, non-main real local branch",
    )

    rollout_parser = commands.add_parser(
        "dependabot-rollout",
        help="review or open draft PRs from an approved Dependabot plan",
    )
    rollout_parser.add_argument("--plan", required=True, type=_path)
    rollout_parser.add_argument("--plan-root", required=True, type=_path)
    rollout_parser.add_argument("--estate-root", required=True, type=_path)
    rollout_parser.add_argument("--approved-plan-digest")
    rollout_mode = rollout_parser.add_mutually_exclusive_group()
    rollout_mode.add_argument(
        "--dry-run", action="store_true", help="show diffs only; this is the default"
    )
    rollout_mode.add_argument(
        "--apply", action="store_true", help="confirm, push, and open draft PRs"
    )

    app_plan_parser = commands.add_parser(
        "github-app-pr-plan",
        help="build an offline exact draft-PR plan from a reviewed proposal",
    )
    app_plan_parser.add_argument("--proposal", required=True, type=_path)
    app_plan_parser.add_argument("--repo", required=True, type=_path)
    app_plan_parser.add_argument("--output", required=True, type=_path)
    app_plan_parser.add_argument("--contracts-root", type=_path)
    app_plan_parser.add_argument("--pins-file", type=_path)
    app_plan_parser.add_argument("--base-branch", default="main")

    app_pr_parser = commands.add_parser(
        "github-app-pr",
        help="review or open one draft PR from an exact GitHub App PR plan",
    )
    app_pr_parser.add_argument("--plan", required=True, type=_path)
    app_pr_parser.add_argument(
        "--repo",
        type=_path,
        help="clean exact target checkout; required with --apply",
    )
    app_pr_parser.add_argument("--approved-plan-digest")
    app_pr_parser.add_argument(
        "--result-output",
        type=_path,
        help="write the structured summary or apply result as pure JSON",
    )
    app_pr_mode = app_pr_parser.add_mutually_exclusive_group()
    app_pr_mode.add_argument(
        "--dry-run", action="store_true", help="verify and summarize only; default"
    )
    app_pr_mode.add_argument(
        "--apply",
        action="store_true",
        help="use an externally brokered installation token to open one draft PR",
    )

    doctor_parser = commands.add_parser("doctor", help="verify local prerequisites")
    doctor_parser.add_argument("--contracts-root", type=_path)

    commands.add_parser("version", help="print the package version")
    return parser


def _confirm_github_app_apply(plan: dict, approved_digest: str) -> None:
    print(
        f"Approved GitHub App PR plan: {plan['repository']} "
        f"{plan['base_sha'][:12]} -> {plan['branch']} ({approved_digest})"
    )
    try:
        answer = input("Open this exact draft pull request and stop? [y/N] ").strip().lower()
    except EOFError as error:
        raise GardenerError("interactive confirmation is required") from error
    if answer not in {"y", "yes"}:
        raise GardenerError("GitHub App PR apply was not confirmed")


def main(argv: Sequence[str] | None = None) -> int:
    """Run one CLI command and return a process exit code."""

    args = build_parser().parse_args(argv)
    try:
        if args.command == "version":
            print(__version__)
            return 0
        if args.command == "doctor":
            return _doctor(args)
        if args.command == "scan":
            estate_root = args.estate_root.resolve(strict=True)
            contracts = ContractSet(
                resolve_contracts_root(args.contracts_root, estate_root=estate_root)
            )
            report = scan(
                args.findings,
                estate_root,
                contracts,
                pins_file=args.pins_file,
            )
            write_json(args.output, report)
            print(
                f"dry-run: {len(report['proposals'])} proposal(s), "
                f"{len(report['refusals'])} refusal(s)"
            )
            return 0
        if args.command == "propose":
            repository = args.repo.resolve(strict=True)
            contracts = ContractSet(
                resolve_contracts_root(args.contracts_root, repository=repository)
            )
            proposal, _, evidence = propose(
                read_json(args.finding),
                repository,
                contracts,
                pins_file=args.pins_file,
            )
            write_json(args.output, proposal)
            evidence_path = args.output.with_name(args.output.stem + ".evidence.json")
            write_json(evidence_path, evidence)
            print(f"dry-run proposal written: {args.output}")
            print(f"redacted evidence summary written: {evidence_path}")
            return 0
        if args.command == "apply":
            repository = args.repo.resolve(strict=True)
            contracts = ContractSet(
                resolve_contracts_root(args.contracts_root, repository=repository)
            )
            result = apply_proposal(
                args.proposal,
                repository,
                contracts,
                apply=args.apply,
                allow_local_target=args.allow_local_target,
                pins_file=args.pins_file,
            )
            print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
            return 0
        if args.command == "dependabot-rollout":
            if args.apply and not args.approved_plan_digest:
                raise GardenerError("--apply requires --approved-plan-digest")
            result = execute_rollout(
                plan_path=args.plan.resolve(strict=True),
                plan_root=args.plan_root.resolve(strict=True),
                estate_root=args.estate_root.resolve(strict=True),
                apply=args.apply,
                approved_digest=args.approved_plan_digest,
            )
            print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
            return 0
        if args.command == "github-app-pr-plan":
            repository = args.repo.resolve(strict=True)
            contracts = ContractSet(
                resolve_contracts_root(args.contracts_root, repository=repository)
            )
            plan = build_pr_plan(
                proposal_path=args.proposal.resolve(strict=True),
                repository=repository,
                contracts=contracts,
                base_branch=args.base_branch,
                pins_file=args.pins_file,
            )
            write_json(args.output, plan)
            print(
                json.dumps(
                    plan_summary(plan), ensure_ascii=False, sort_keys=True, indent=2
                )
            )
            print(f"exact GitHub App PR plan written: {args.output}")
            return 0
        if args.command == "github-app-pr":
            plan = validate_pr_plan(read_json(args.plan.resolve(strict=True)))
            if not args.apply:
                _emit_json_result(plan_summary(plan), args.result_output)
                return 0
            if not args.approved_plan_digest:
                raise GardenerError("--apply requires --approved-plan-digest")
            if args.repo is None:
                raise GardenerError("--apply requires --repo for classification revalidation")
            if args.approved_plan_digest != plan["plan_digest"]:
                raise GardenerError("approved plan digest does not match the reviewed plan")
            current_classification = verify_apply_repository(plan, args.repo)
            _confirm_github_app_apply(plan, args.approved_plan_digest)
            result = apply_pr_plan(
                plan,
                approved_plan_digest=args.approved_plan_digest,
                token=installation_token_from_environment(),
                current_classification=current_classification,
            )
            _emit_json_result(result, args.result_output)
            return 0
    except (GardenerError, OSError, ValueError) as error:
        print(f"atlas-gardener: refused: {error}", file=sys.stderr)
        return 2
    return 2


def _doctor(args: argparse.Namespace) -> int:
    contracts_root = resolve_contracts_root(args.contracts_root)
    contracts = ContractSet(contracts_root)
    contracts.validate_finding(contracts.finding_schema["examples"][0])
    contracts.validator.validate(
        contracts.proposal_schema["examples"][0], contracts.proposal_schema
    )
    if shutil.which("git") is None:
        raise GardenerError("git is required for worktree safety checks")
    result = {
        "schema_version": "atlas-gardener/doctor/v1",
        "status": "ok",
        "version": __version__,
        "contracts_root": str(contracts_root),
        "dry_run_default": True,
        "max_changed_files": MAX_CHANGED_FILES,
        "max_changed_lines": MAX_CHANGED_LINES,
        "fixers": sorted(set(RULE_FIXERS.values())),
        "network_access": False,
        "github_app_pr_adapter": {
            "default_mode": "dry-run",
            "apply_network_access": True,
            "single_commit": True,
            "workflow_files_supported": False,
            "installation_token_source": "approved external broker via environment",
            "provider_installation_in_scope": False,
            "stop_after": "draft-pull-request",
        },
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0
