from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from atlas_gardener.cli import _emit_json_result, build_parser


class CliJsonOutputTests(unittest.TestCase):
    def test_github_app_parser_accepts_structured_result_output(self) -> None:
        args = build_parser().parse_args(
            [
                "github-app-pr",
                "--plan",
                "plan.json",
                "--result-output",
                "result.json",
                "--dry-run",
            ]
        )

        self.assertEqual(Path("result.json"), args.result_output)
        self.assertTrue(args.dry_run)

    def test_emit_json_result_writes_parse_safe_receipt(self) -> None:
        result = {
            "schema_version": "atlas-gardener/github-app-pr-result/v1",
            "draft_pull_request": {"number": 13, "draft": True},
            "stopped": True,
        }

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            stdout = StringIO()
            with redirect_stdout(stdout):
                _emit_json_result(result, output)

            self.assertEqual(result, json.loads(output.read_text(encoding="utf-8")))
            self.assertEqual(result, json.loads(stdout.getvalue()))
            self.assertTrue(output.read_text(encoding="utf-8").endswith("\n"))


if __name__ == "__main__":
    unittest.main()
