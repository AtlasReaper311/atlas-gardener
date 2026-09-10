from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.security_fixers import (
    container_digest_plan,
    npm_security_plan,
    python_security_plan,
)


def dependency_candidate(
    *,
    ecosystem: str,
    dependency: str,
    current: str,
    target: str,
    source_file: str,
) -> dict:
    current_parts = tuple(int(part) for part in current.split("."))
    target_parts = tuple(int(part) for part in target.split("."))
    return {
        "kind": "dependency-update",
        "ecosystem": ecosystem,
        "dependency": dependency,
        "current_version": current,
        "target_version": target,
        "source_file": source_file,
        "update_class": "patch" if current_parts[:2] == target_parts[:2] else "minor",
        "direct": True,
        "vulnerability_ids": ["GHSA-test-0001"],
    }


class SecurityFixerTests(unittest.TestCase):
    def test_python_exact_pin_preserves_extras_and_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text(
                "uvicorn[standard] == 0.52.4 ; python_version >= '3.12'\n",
                encoding="utf-8",
            )
            plan = python_security_plan(
                root,
                dependency_candidate(
                    ecosystem="PyPI",
                    dependency="uvicorn",
                    current="0.52.4",
                    target="0.53.1",
                    source_file="requirements.txt",
                ),
            )
        self.assertEqual(["requirements.txt"], plan.files_affected)
        after = plan.changes[0].after.decode("utf-8")
        self.assertEqual(
            "uvicorn[standard] == 0.53.1 ; python_version >= '3.12'\n",
            after,
        )

    def test_python_wrong_preimage_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("example==1.2.4\n", encoding="utf-8")
            with self.assertRaisesRegex(SafetyRefusal, "preimage"):
                python_security_plan(
                    root,
                    dependency_candidate(
                        ecosystem="PyPI",
                        dependency="example",
                        current="1.2.3",
                        target="1.2.5",
                        source_file="requirements.txt",
                    ),
                )

    def test_major_dependency_update_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("example==1.9.0\n", encoding="utf-8")
            candidate = dependency_candidate(
                ecosystem="PyPI",
                dependency="example",
                current="1.9.0",
                target="2.0.0",
                source_file="requirements.txt",
            )
            candidate["update_class"] = "minor"
            with self.assertRaisesRegex(SafetyRefusal, "same-major"):
                python_security_plan(root, candidate)

    def test_container_digest_changes_one_simple_from_instruction(self) -> None:
        digest = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
            plan = container_digest_plan(
                root,
                {
                    "kind": "container-digest-pin",
                    "source_file": "Dockerfile",
                    "current_reference": "python:3.12-slim",
                    "target_digest": digest,
                },
            )
        self.assertEqual(["Dockerfile"], plan.files_affected)
        self.assertEqual(
            f"FROM python:3.12-slim@{digest}\n",
            plan.changes[0].after.decode("utf-8"),
        )

    def test_named_container_stage_cannot_be_fixed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text("FROM node:24 AS build\n", encoding="utf-8")
            with self.assertRaisesRegex(SafetyRefusal, "staged"):
                container_digest_plan(
                    root,
                    {
                        "kind": "container-digest-pin",
                        "source_file": "Dockerfile",
                        "current_reference": "node:24",
                        "target_digest": "sha256:" + "b" * 64,
                    },
                )

    def test_npm_regeneration_uses_fixed_argv_and_exact_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(
                json.dumps(
                    {"name": "fixture", "dependencies": {"fast-uri": "^3.1.5"}},
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "fixture",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"dependencies": {"fast-uri": "^3.1.5"}},
                            "node_modules/fast-uri": {"version": "3.1.5"},
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            calls: list[list[str]] = []

            def fake_run(args, *, cwd, **kwargs):
                calls.append(list(args))
                package = json.loads((Path(cwd) / "package.json").read_text(encoding="utf-8"))
                self.assertEqual("3.1.7", package["dependencies"]["fast-uri"])
                (Path(cwd) / "package-lock.json").write_text(
                    json.dumps(
                        {
                            "name": "fixture",
                            "lockfileVersion": 3,
                            "packages": {
                                "": {"dependencies": {"fast-uri": "3.1.7"}},
                                "node_modules/fast-uri": {"version": "3.1.7"},
                            },
                        },
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with patch("atlas_gardener.security_fixers.subprocess.run", side_effect=fake_run):
                plan = npm_security_plan(
                    root,
                    dependency_candidate(
                        ecosystem="npm",
                        dependency="fast-uri",
                        current="3.1.5",
                        target="3.1.7",
                        source_file="package.json",
                    ),
                )

        self.assertEqual(["package-lock.json", "package.json"], plan.files_affected)
        self.assertEqual(1, len(calls))
        self.assertEqual(
            [
                "npm",
                "install",
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ],
            calls[0],
        )
        self.assertNotIn("fast-uri", calls[0])
        self.assertNotIn("3.1.7", calls[0])


if __name__ == "__main__":
    unittest.main()
