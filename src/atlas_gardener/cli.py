"""Argparse CLI for offline Atlas Gardener proposal workflows."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Sequence

from atlas_gardener import __version__
from atlas_gardener.contracts import (
    ContractSet,
    read_json,
    resolve_contracts_root,
    write_json,
)
from atlas_gardener.engine import apply_proposal, propose, scan
from atlas_gardener.errors import GardenerError
from atlas_gardener.fixers import RULE_FIXERS
from atlas_gardener.safety import MAX_CHANGED_FILES, MAX_CHANGED_LINES


def _path(value: str) -> Path:
    return Path(value).expanduser()


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

    doctor_parser = commands.add_parser("doctor", help="verify local prerequisites")
    doctor_parser.add_argument("--contracts-root", type=_path)

    commands.add_parser("version", help="print the package version")
    return parser


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
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0
