#!/usr/bin/env python3
"""Run the automatic controller and guarantee one bounded evidence file."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from atlas_gardener.error_evidence import write_controller_error_evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--infra-root", required=True, type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--previous-evidence", type=Path)
    parser.add_argument("--attestation-verified", action="store_true")
    args = parser.parse_args()
    try:
        from atlas_gardener.controller import run_controller

        run_controller(
            infra_root=args.infra_root,
            bundle_path=args.bundle,
            output_path=args.output,
            work_root=args.work_root,
            attestation_verified=args.attestation_verified,
        )
    except Exception as error:
        write_controller_error_evidence(
            args.output,
            error,
            previous_evidence_path=args.previous_evidence,
        )
        print(f"Atlas Gardener controller failed closed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
