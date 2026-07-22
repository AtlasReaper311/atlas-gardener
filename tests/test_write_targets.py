from __future__ import annotations

import os
import unittest
from pathlib import Path

from atlas_gardener.automation import read_object
from atlas_gardener.errors import SafetyRefusal
from atlas_gardener.write_targets import resolve_write_targets


class WriteTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        infra = Path(os.environ["ATLAS_GARDENER_INFRA_ROOT"]).resolve()
        cls.policy = read_object(
            infra / "policy/gardener-automation.json", label="automation policy"
        )
        cls.coverage = read_object(
            infra / "policy/gardener-github-app-coverage.json",
            label="coverage policy",
        )

    def test_non_write_modes_need_no_target_list(self) -> None:
        self.assertEqual((), resolve_write_targets(self.policy, self.coverage, "disabled", {}))
        self.assertEqual((), resolve_write_targets(self.policy, self.coverage, "observe", {}))

    def test_canary_write_target_is_accepted(self) -> None:
        self.assertEqual(
            ("AtlasReaper311/atlas-dora",),
            resolve_write_targets(
                self.policy,
                self.coverage,
                "pr-only",
                {
                    "ATLAS_GARDENER_WRITE_TARGETS_JSON": (
                        '["AtlasReaper311/atlas-dora"]'
                    )
                },
            ),
        )

    def test_missing_empty_and_malformed_targets_fail_closed(self) -> None:
        for value, message in (
            (None, "requires explicit write targets"),
            ("[]", "cannot be empty"),
            ("not-json", "valid JSON"),
            ("{}", "JSON string array"),
        ):
            environment = {}
            if value is not None:
                environment["ATLAS_GARDENER_WRITE_TARGETS_JSON"] = value
            with self.subTest(value=value):
                with self.assertRaisesRegex(SafetyRefusal, message):
                    resolve_write_targets(
                        self.policy,
                        self.coverage,
                        "pr-only",
                        environment,
                    )

    def test_unsorted_duplicate_and_uncovered_targets_fail_closed(self) -> None:
        cases = (
            (
                '["AtlasReaper311/status","AtlasReaper311/atlas-dora"]',
                "must be sorted",
            ),
            (
                '["AtlasReaper311/atlas-dora","AtlasReaper311/atlas-dora"]',
                "must be unique",
            ),
            ('["AtlasReaper311/not-covered"]', "outside verified public coverage"),
        )
        for value, message in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(SafetyRefusal, message):
                    resolve_write_targets(
                        self.policy,
                        self.coverage,
                        "automerge-low-risk",
                        {"ATLAS_GARDENER_WRITE_TARGETS_JSON": value},
                    )


if __name__ == "__main__":
    unittest.main()
