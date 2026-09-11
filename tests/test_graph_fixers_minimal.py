from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from atlas_gardener.graph_fixers_minimal import NPM_VERSION, npm_graph_plan


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class GraphFixerMinimalTests(unittest.TestCase):
    def write_json(self, path: Path, value: dict) -> bytes:
        data = (json.dumps(value, indent=2) + "\n").encode("utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return data

    def test_transitive_candidate_preserves_unrelated_lock_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.write_json(
                root / "package.json",
                {"name": "fixture", "devDependencies": {"minimatch": "^10.0.0"}},
            )
            original_lock = {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"devDependencies": {"minimatch": "^10.0.0"}},
                    "node_modules/minimatch": {
                        "version": "10.0.0",
                        "dependencies": {"brace-expansion": "^5.0.5"},
                    },
                    "node_modules/brace-expansion": {
                        "version": "5.0.7",
                        "resolved": "old",
                        "integrity": "old",
                    },
                    "node_modules/native-optional": {
                        "version": "1.0.0",
                        "optional": True,
                        "libc": ["glibc"],
                    },
                },
            }
            self.write_json(root / "package-lock.json", original_lock)

            expected_lock = json.loads(json.dumps(original_lock))
            expected_lock["packages"]["node_modules/brace-expansion"] = {
                "version": "5.0.9",
                "resolved": "new",
                "integrity": "new",
            }
            expected_bytes = (json.dumps(expected_lock, indent=2) + "\n").encode("utf-8")
            candidate = {
                "kind": "npm-lock-security-remediation",
                "manifest_file": "package.json",
                "lockfile_file": "package-lock.json",
                "npm_version": NPM_VERSION,
                "direct_updates": [],
                "transitive_updates": [{
                    "dependency": "brace-expansion",
                    "package_path": "node_modules/brace-expansion",
                    "current_version": "5.0.7",
                    "target_version": "5.0.9",
                    "parents": [{
                        "package_path": "node_modules/minimatch",
                        "specifier": "^5.0.5",
                    }],
                    "vulnerability_ids": ["GHSA-example"],
                }],
                "vulnerability_ids": ["GHSA-example"],
                "target_manifest_sha256": digest(manifest),
                "target_lockfile_sha256": digest(expected_bytes),
            }

            def noisy_npm(work: Path, names: list[str]) -> None:
                self.assertEqual(["brace-expansion"], names)
                lock = json.loads((work / "package-lock.json").read_text(encoding="utf-8"))
                lock["packages"]["node_modules/brace-expansion"] = {
                    "version": "5.0.9",
                    "resolved": "new",
                    "integrity": "new",
                }
                lock["packages"]["node_modules/native-optional"].pop("libc")
                self.write_json(work / "package-lock.json", lock)

            with patch("atlas_gardener.graph_fixers._run_pinned_npm", side_effect=noisy_npm), patch(
                "atlas_gardener.graph_fixers._active_vulnerability_ids", return_value=set()
            ):
                plan = npm_graph_plan(root, candidate)

        self.assertEqual(["package-lock.json"], plan.files_affected)
        self.assertEqual(expected_bytes, plan.changes[0].after)
        self.assertIn(b'"libc": [\n        "glibc"\n      ]', plan.changes[0].after)


if __name__ == "__main__":
    unittest.main()
