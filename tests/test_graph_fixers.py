from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.graph_fixers import NPM_VERSION, npm_graph_plan


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class GraphFixerTests(unittest.TestCase):
    def write_json(self, path: Path, value: dict) -> bytes:
        data = (json.dumps(value, indent=2) + "\n").encode("utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return data

    def test_transitive_graph_candidate_regenerates_exact_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_before = self.write_json(root / "package.json", {
                "name": "fixture",
                "dependencies": {"parent": "^2.0.0"},
            })
            self.write_json(root / "package-lock.json", {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"parent": "^2.0.0"}},
                    "node_modules/parent": {"version": "2.0.0", "dependencies": {"vuln": "^1.0.0"}},
                    "node_modules/vuln": {"version": "1.0.0"},
                },
            })
            target_lock = (json.dumps({
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"parent": "^2.0.0"}},
                    "node_modules/parent": {"version": "2.0.0", "dependencies": {"vuln": "^1.0.0"}},
                    "node_modules/vuln": {"version": "1.0.1"},
                },
            }, indent=2) + "\n").encode("utf-8")
            candidate = {
                "kind": "npm-lock-security-remediation",
                "manifest_file": "package.json",
                "lockfile_file": "package-lock.json",
                "npm_version": NPM_VERSION,
                "direct_updates": [],
                "transitive_updates": [{
                    "dependency": "vuln",
                    "package_path": "node_modules/vuln",
                    "current_version": "1.0.0",
                    "target_version": "1.0.1",
                    "parents": [{"package_path": "node_modules/parent", "specifier": "^1.0.0"}],
                    "vulnerability_ids": ["GHSA-vuln"],
                }],
                "vulnerability_ids": ["GHSA-vuln"],
                "target_manifest_sha256": digest(manifest_before),
                "target_lockfile_sha256": digest(target_lock),
            }

            def fake_npm(work: Path, names: list[str]) -> None:
                self.assertEqual(["vuln"], names)
                (work / "package-lock.json").write_bytes(target_lock)

            with patch("atlas_gardener.graph_fixers._run_pinned_npm", side_effect=fake_npm), patch(
                "atlas_gardener.graph_fixers._active_vulnerability_ids", return_value=set()
            ):
                plan = npm_graph_plan(root, candidate)
        self.assertEqual(["package-lock.json"], plan.files_affected)

    def test_direct_parent_update_can_preserve_manifest_spec(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_before = self.write_json(root / "package.json", {
                "name": "fixture",
                "devDependencies": {"wrangler": "^4.127.0"},
            })
            self.write_json(root / "package-lock.json", {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"devDependencies": {"wrangler": "^4.127.0"}},
                    "node_modules/wrangler": {"version": "4.127.0", "dependencies": {"sharp": "0.35.2"}},
                    "node_modules/sharp": {"version": "0.35.2"},
                },
            })
            target_lock = (json.dumps({
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"devDependencies": {"wrangler": "^4.127.0"}},
                    "node_modules/wrangler": {"version": "4.131.0", "dependencies": {"sharp": "0.35.4"}},
                    "node_modules/sharp": {"version": "0.35.4"},
                },
            }, indent=2) + "\n").encode("utf-8")
            candidate = {
                "kind": "npm-lock-security-remediation",
                "manifest_file": "package.json",
                "lockfile_file": "package-lock.json",
                "npm_version": NPM_VERSION,
                "direct_updates": [{
                    "dependency": "wrangler",
                    "section": "devDependencies",
                    "current_version": "4.127.0",
                    "target_version": "4.131.0",
                    "current_spec": "^4.127.0",
                    "target_spec": "^4.127.0",
                    "vulnerability_ids": ["GHSA-sharp"],
                }],
                "transitive_updates": [],
                "vulnerability_ids": ["GHSA-sharp"],
                "target_manifest_sha256": digest(manifest_before),
                "target_lockfile_sha256": digest(target_lock),
            }

            with patch(
                "atlas_gardener.graph_fixers._run_pinned_npm",
                side_effect=lambda work, names: (work / "package-lock.json").write_bytes(target_lock),
            ), patch("atlas_gardener.graph_fixers._active_vulnerability_ids", return_value=set()):
                plan = npm_graph_plan(root, candidate)
        self.assertEqual(["package-lock.json"], plan.files_affected)

    def test_parent_constraint_mismatch_fails_closed_before_npm(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.write_json(root / "package.json", {"name": "fixture", "dependencies": {"parent": "^2.0.0"}})
            lock = self.write_json(root / "package-lock.json", {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"parent": "^2.0.0"}},
                    "node_modules/parent": {"version": "2.0.0", "dependencies": {"vuln": "1.0.0"}},
                    "node_modules/vuln": {"version": "1.0.0"},
                },
            })
            candidate = {
                "kind": "npm-lock-security-remediation",
                "manifest_file": "package.json",
                "lockfile_file": "package-lock.json",
                "npm_version": NPM_VERSION,
                "direct_updates": [],
                "transitive_updates": [{
                    "dependency": "vuln",
                    "package_path": "node_modules/vuln",
                    "current_version": "1.0.0",
                    "target_version": "1.0.1",
                    "parents": [{"package_path": "node_modules/parent", "specifier": "^1.0.0"}],
                    "vulnerability_ids": ["GHSA-vuln"],
                }],
                "vulnerability_ids": ["GHSA-vuln"],
                "target_manifest_sha256": digest(manifest),
                "target_lockfile_sha256": digest(lock),
            }
            with patch("atlas_gardener.graph_fixers._run_pinned_npm") as runner:
                with self.assertRaisesRegex(SafetyRefusal, "parent constraint evidence"):
                    npm_graph_plan(root, candidate)
                runner.assert_not_called()

    def test_producer_digest_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.write_json(root / "package.json", {"name": "fixture", "dependencies": {"vuln": "^1.0.0"}})
            self.write_json(root / "package-lock.json", {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"vuln": "^1.0.0"}},
                    "node_modules/vuln": {"version": "1.0.0"},
                },
            })
            target_lock = (json.dumps({
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"vuln": "^1.0.1"}},
                    "node_modules/vuln": {"version": "1.0.1"},
                },
            }, indent=2) + "\n").encode("utf-8")
            candidate = {
                "kind": "npm-lock-security-remediation",
                "manifest_file": "package.json",
                "lockfile_file": "package-lock.json",
                "npm_version": NPM_VERSION,
                "direct_updates": [{
                    "dependency": "vuln",
                    "section": "dependencies",
                    "current_version": "1.0.0",
                    "target_version": "1.0.1",
                    "current_spec": "^1.0.0",
                    "target_spec": "^1.0.1",
                    "vulnerability_ids": ["GHSA-vuln"],
                }],
                "transitive_updates": [],
                "vulnerability_ids": ["GHSA-vuln"],
                "target_manifest_sha256": digest(manifest),
                "target_lockfile_sha256": "sha256:" + "0" * 64,
            }
            with patch(
                "atlas_gardener.graph_fixers._run_pinned_npm",
                side_effect=lambda work, names: (work / "package-lock.json").write_bytes(target_lock),
            ):
                with self.assertRaisesRegex(SafetyRefusal, "target digests"):
                    npm_graph_plan(root, candidate)

    def test_vulnerability_postcondition_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.write_json(root / "package.json", {"name": "fixture", "dependencies": {"parent": "^2.0.0"}})
            self.write_json(root / "package-lock.json", {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"parent": "^2.0.0"}},
                    "node_modules/parent": {"version": "2.0.0", "dependencies": {"vuln": "^1.0.0"}},
                    "node_modules/vuln": {"version": "1.0.0"},
                },
            })
            target_lock = (json.dumps({
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"parent": "^2.0.0"}},
                    "node_modules/parent": {"version": "2.0.0", "dependencies": {"vuln": "^1.0.0"}},
                    "node_modules/vuln": {"version": "1.0.1"},
                },
            }, indent=2) + "\n").encode("utf-8")
            candidate = {
                "kind": "npm-lock-security-remediation",
                "manifest_file": "package.json",
                "lockfile_file": "package-lock.json",
                "npm_version": NPM_VERSION,
                "direct_updates": [],
                "transitive_updates": [{
                    "dependency": "vuln",
                    "package_path": "node_modules/vuln",
                    "current_version": "1.0.0",
                    "target_version": "1.0.1",
                    "parents": [{"package_path": "node_modules/parent", "specifier": "^1.0.0"}],
                    "vulnerability_ids": ["GHSA-vuln"],
                }],
                "vulnerability_ids": ["GHSA-vuln"],
                "target_manifest_sha256": digest(manifest),
                "target_lockfile_sha256": digest(target_lock),
            }
            with patch(
                "atlas_gardener.graph_fixers._run_pinned_npm",
                side_effect=lambda work, names: (work / "package-lock.json").write_bytes(target_lock),
            ), patch("atlas_gardener.graph_fixers._active_vulnerability_ids", return_value={"GHSA-vuln"}):
                with self.assertRaisesRegex(SafetyRefusal, "vulnerability postcondition"):
                    npm_graph_plan(root, candidate)


if __name__ == "__main__":
    unittest.main()
