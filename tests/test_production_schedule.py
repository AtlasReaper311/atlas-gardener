from __future__ import annotations

import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "controller.yml"


class ProductionScheduleTests(unittest.TestCase):
    def test_controller_runs_after_monday_audit(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('cron: "15 10 * * 1"', content)
        self.assertNotIn('cron: "15 10 * * *"', content)

    def test_manual_dispatch_remains_available(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", content)


if __name__ == "__main__":
    unittest.main()
