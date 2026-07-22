#!/usr/bin/env python3
"""Write one bounded target-gate status marker into a Gardener PR body."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from atlas_gardener.errors import GardenerError
from atlas_gardener.gate_status import (
    build_gate_status,
    replace_gate_status_marker,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr", required=True, type=Path)
    parser.add_argument("--gate-result", required=True, type=Path)
    parser.add_argument("--required-checks", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        pr = json.loads(args.pr.read_text(encoding="utf-8"))
        result = json.loads(args.gate_result.read_text(encoding="utf-8"))
        required_checks = json.loads(args.required_checks)
        if not isinstance(pr, dict) or not isinstance(result, dict):
            raise GardenerError("PR and gate result must be JSON objects")
        if not isinstance(required_checks, list):
            raise GardenerError("required checks must be a JSON array")
        state = "eligible" if result.get("eligible") is True else "refused"
        status = build_gate_status(
            body=str(pr.get("body") or ""),
            head_sha=str(pr.get("headRefOid") or ""),
            state=state,
            reason=str(result.get("reason") or "target gate refused"),
            required_checks=required_checks,
        )
        body = replace_gate_status_marker(str(pr.get("body") or ""), status)
    except (GardenerError, OSError, UnicodeError, ValueError) as error:
        print(f"Gardener gate marker refused: {error}", file=sys.stderr)
        return 2
    args.output.write_text(body, encoding="utf-8")
    print(json.dumps(status, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
