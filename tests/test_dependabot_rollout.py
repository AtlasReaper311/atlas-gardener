"""Tests for the guarded Dependabot estate rollout executor."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from atlas_gardener.dependabot_rollout import (
    build_changes,
    execute_rollout,
    render_diff,
    validate_plan,
)
from atlas_gardener.errors import SafetyRefusal


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def plan(entries: list[dict]) -> dict:
    value = {
        "schema_version": "atlas-dependabot/rollout-plan/v1",
        "owner": "AtlasReaper311",
        "registry_reviewed_at": "2026-07-18T00:00:00Z",
        "registry_digest": "a" * 64,
        "reconciliation_digest": "b" * 64,
        "github_only": [],
        "registry_only": [],
        "repositories": entries,
    }
    value["plan_digest"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return value


class DependabotRolloutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.estate = self.root / "estate"
        self.plan_root = self.root / "plan"
        self.estate.mkdir()
        self.plan_root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def repository(self, name: str, *, fixture: bool = True) -> Path:
        repository = self.estate / name
        repository.mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(repository)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(repository), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repository), "config", "user.name", "Test"],
            check=True,
        )
        (repository / "README.md").write_text("fixture\n", encoding="utf-8")
        tracked = ["README.md"]
        if fixture:
            (repository / ".atlas-gardener-fixture").write_text("fixture\n", encoding="utf-8")
            tracked.append(".atlas-gardener-fixture")
        subprocess.run(
            ["git", "-C", str(repository), "add", *tracked], check=True
        )
        subprocess.run(
            ["git", "-C", str(repository), "commit", "-m", "fixture"],
            check=True,
            capture_output=True,
        )
        return repository

    def source_governance(
        self,
        repository: Path,
        *,
        lifecycle: str = "active",
        provenance: str = "original",
    ) -> None:
        path = repository / ".atlas" / "governance.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        write_json(
            path,
            {
                "schema_version": "atlas-repository-governance/v1",
                "repository": f"AtlasReaper311/{repository.name}",
                "visibility": "private",
                "estate_membership": "internal",
                "lifecycle": lifecycle,
                "provenance": provenance,
                "public_projection": False,
            },
        )
        subprocess.run(
            ["git", "-C", str(repository), "add", ".atlas/governance.json"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repository), "commit", "-m", "governance"],
            check=True,
            capture_output=True,
        )

    def test_plan_digest_and_owner_digest_are_enforced(self) -> None:
        path = self.root / "plan.json"
        value = plan([])
        write_json(path, value)
        self.assertEqual(value, validate_plan(path, value["plan_digest"]))
        with self.assertRaises(SafetyRefusal):
            validate_plan(path, "f" * 64)

    def test_mismatched_estate_is_refused(self) -> None:
        path = self.root / "plan.json"
        value = plan([])
        value["github_only"] = ["AtlasReaper311/unapproved"]
        stable = dict(value)
        stable.pop("plan_digest")
        value["plan_digest"] = hashlib.sha256(
            json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        write_json(path, value)
        with self.assertRaises(SafetyRefusal):
            validate_plan(path)

    def test_build_changes_copies_plan_and_updates_known_node_action(self) -> None:
        repository = self.repository("example")
        workflow = repository / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "steps:\n  - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "-C", str(repository), "add", ".github/workflows/ci.yml"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repository), "commit", "-m", "workflow"],
            check=True,
            capture_output=True,
        )
        generated = self.plan_root / "example" / ".github" / "dependabot.yml"
        generated.parent.mkdir(parents=True)
        generated.write_text("version: 2\nupdates: []\n", encoding="utf-8")
        value = plan(
            [
                {
                    "repository": "AtlasReaper311/example",
                    "action": "propose",
                    "default_branch": "main",
                    "files": [".github/dependabot.yml"],
                }
            ]
        )
        changes = build_changes(value, self.plan_root, self.estate)
        self.assertEqual(1, len(changes))
        self.assertIn(".github/dependabot.yml", changes[0].files)
        self.assertIn("Node 24", changes[0].files[".github/workflows/ci.yml"])
        self.assertIn("setup-node@820762", render_diff(changes[0]))

    def test_public_rollout_exclusion_is_never_changed(self) -> None:
        self.repository("atlas-dep-audit")
        value = plan(
            [
                {
                    "repository": "AtlasReaper311/atlas-dep-audit",
                    "action": "propose",
                    "default_branch": "main",
                    "files": [],
                }
            ]
        )
        self.assertEqual([], build_changes(value, self.plan_root, self.estate))

    def test_deprecated_source_governance_refuses_proposed_change(self) -> None:
        repository = self.repository("example-deprecated", fixture=False)
        self.source_governance(repository, lifecycle="deprecated")
        value = plan(
            [
                {
                    "repository": "AtlasReaper311/example-deprecated",
                    "action": "propose",
                    "default_branch": "main",
                    "files": [],
                }
            ]
        )
        with self.assertRaisesRegex(SafetyRefusal, "deprecated"):
            build_changes(value, self.plan_root, self.estate)

    def test_external_derived_source_governance_refuses_proposed_change(self) -> None:
        repository = self.repository("example-external", fixture=False)
        self.source_governance(repository, provenance="external-derived")
        value = plan(
            [
                {
                    "repository": "AtlasReaper311/example-external",
                    "action": "propose",
                    "default_branch": "main",
                    "files": [],
                }
            ]
        )
        with self.assertRaisesRegex(SafetyRefusal, "external-derived"):
            build_changes(value, self.plan_root, self.estate)

    def test_unknown_real_repository_refuses_proposed_change(self) -> None:
        self.repository("example-unknown", fixture=False)
        value = plan(
            [
                {
                    "repository": "AtlasReaper311/example-unknown",
                    "action": "propose",
                    "default_branch": "main",
                    "files": [],
                }
            ]
        )
        with self.assertRaisesRegex(SafetyRefusal, "classification is unavailable"):
            build_changes(value, self.plan_root, self.estate)

    def test_dry_run_writes_no_repository_files(self) -> None:
        repository = self.repository("example")
        generated = self.plan_root / "example" / ".github" / "dependabot.yml"
        generated.parent.mkdir(parents=True)
        generated.write_text("version: 2\nupdates: []\n", encoding="utf-8")
        value = plan(
            [
                {
                    "repository": "AtlasReaper311/example",
                    "action": "propose",
                    "default_branch": "main",
                    "files": [".github/dependabot.yml"],
                }
            ]
        )
        plan_path = self.root / "plan.json"
        write_json(plan_path, value)
        result = execute_rollout(
            plan_path=plan_path,
            plan_root=self.plan_root,
            estate_root=self.estate,
            apply=False,
            approved_digest=None,
        )
        self.assertEqual("dry-run", result["mode"])
        self.assertFalse((repository / ".github" / "dependabot.yml").exists())

    def test_planned_path_traversal_is_refused(self) -> None:
        self.repository("example")
        value = plan(
            [
                {
                    "repository": "AtlasReaper311/example",
                    "action": "propose",
                    "default_branch": "main",
                    "files": ["../escape.yml"],
                }
            ]
        )
        with self.assertRaises(SafetyRefusal):
            build_changes(value, self.plan_root, self.estate)


if __name__ == "__main__":
    unittest.main()
