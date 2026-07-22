#!/usr/bin/env python3
"""Write bounded controller error evidence when workflow preflight fails."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from atlas_gardener.controller import write_controller_error_evidence
from atlas_gardener.errors import SafetyRefusal


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--previous-evidence", type=Path)
    args = parser.parse_args()
    write_controller_error_evidence(
        args.output,
        SafetyRefusal(args.reason[:500]),
        previous_evidence_path=args.previous_evidence,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
