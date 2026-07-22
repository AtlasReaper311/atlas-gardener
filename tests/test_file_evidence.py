from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/build_gardener_file_evidence.py"
SPEC = importlib.util.spec_from_file_location("build_gardener_file_evidence", SCRIPT)
assert SPEC and SPEC.loader
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)


class FileEvidenceTests(unittest.TestCase):
    def _repository(self, root: Path, content: str | None) -> str:
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(
            ["git", "-C", str(root), "config", "user.name", "Atlas Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "config",
                "user.email",
                "atlas@example.invalid",
            ],
            check=True,
        )
        if content is not None:
            (root / ".gitignore").write_text(content, encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(root), "add", ".gitignore"], check=True
            )
        else:
            (root / "README.md").write_text("test\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(root), "add", "README.md"], check=True
            )
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "test"],
            check=True,
        )
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip()

    def test_builds_exact_additions_only_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base"
            head = root / "head"
            base_sha = self._repository(
                base, "node_modules/\n.wrangler/\n.dev.vars\n"
            )
            head_sha = self._repository(
                head,
                "node_modules/\n.wrangler/\n.dev.vars\n\n.DS_Store\n",
            )
            files = root / "files.json"
            base_output = root / "base.gitignore"
            head_output = root / "head.gitignore"
            value = EVIDENCE.build_evidence(
                pr={"baseRefOid": base_sha, "headRefOid": head_sha},
                base_root=base,
                head_root=head,
                files_output=files,
                base_output=base_output,
                head_output=head_output,
            )
            self.assertEqual(str(base_output), value)
            document = json.loads(files.read_text(encoding="utf-8"))
            self.assertEqual(1, len(document))
            self.assertEqual(".gitignore", document[0]["filename"])
            self.assertEqual("modified", document[0]["status"])
            self.assertEqual(2, document[0]["additions"])
            self.assertEqual(0, document[0]["deletions"])
            self.assertIn("+", document[0]["patch"])
            self.assertIn("+.DS_Store", document[0]["patch"])
            self.assertEqual(
                (base / ".gitignore").read_bytes(), base_output.read_bytes()
            )
            self.assertEqual(
                (head / ".gitignore").read_bytes(), head_output.read_bytes()
            )

    def test_allows_missing_base_file_but_requires_head_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base"
            head = root / "head"
            base_sha = self._repository(base, None)
            head_sha = self._repository(head, ".DS_Store\n")
            value = EVIDENCE.build_evidence(
                pr={"baseRefOid": base_sha, "headRefOid": head_sha},
                base_root=base,
                head_root=head,
                files_output=root / "files.json",
                base_output=root / "base.gitignore",
                head_output=root / "head.gitignore",
            )
            self.assertEqual("", value)
            document = json.loads(
                (root / "files.json").read_text(encoding="utf-8")
            )
            self.assertEqual("added", document[0]["status"])

    def test_main_records_specific_fail_closed_reason(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base"
            head = root / "head"
            base_sha = self._repository(base, "node_modules/\n")
            head_sha = self._repository(head, None)
            pr = root / "pr.json"
            pr.write_text(
                json.dumps(
                    {
                        "number": 19,
                        "baseRefOid": base_sha,
                        "headRefOid": head_sha,
                    }
                ),
                encoding="utf-8",
            )
            gate_result = root / "gate.json"
            argv = [
                "build_gardener_file_evidence.py",
                "--pr",
                str(pr),
                "--base-root",
                str(base),
                "--head-root",
                str(head),
                "--files-output",
                str(root / "files.json"),
                "--base-output",
                str(root / "base.gitignore"),
                "--head-output",
                str(root / "head.gitignore"),
                "--gate-result-output",
                str(gate_result),
            ]
            with mock.patch.object(
                os,
                "environ",
                {"GITHUB_REPOSITORY": "AtlasReaper311/atlas-dora"},
            ), mock.patch.object(__import__("sys"), "argv", argv):
                self.assertEqual(2, EVIDENCE.main())
            result = json.loads(gate_result.read_text(encoding="utf-8"))
            self.assertFalse(result["eligible"])
            self.assertEqual(19, result["pull_request"])
            self.assertIn("head .gitignore is missing", result["reason"])


if __name__ == "__main__":
    unittest.main()
