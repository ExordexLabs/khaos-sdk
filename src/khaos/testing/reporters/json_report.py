"""JSON reporter for @khaostest results.

Generates structured JSON output for CI scripting and downstream processing.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from khaos.testing.runner import TestSummary


class TestJsonReporter:
    """Generate structured JSON from @khaostest TestSummary.

    Flat top-level fields for easy CI scripting.  ``"khaos_test": true``
    discriminator to distinguish from ``khaos ci`` JSON output.

    Example output::

        {
          "khaos_test": true,
          "timestamp": "2025-01-15T...",
          "total": 5, "passed": 4, "failed": 1,
          "duration_ms": 2340.5,
          "verdict": "fail",
          "exit_code": 1,
          "results": [
            {"name": "test_resilience", "agent": "my-agent", "passed": true, ...}
          ]
        }
    """

    def __init__(self, summary: TestSummary) -> None:
        self.summary = summary

    def generate(self) -> str:
        """Generate JSON report string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_dict(self) -> dict[str, Any]:
        """Generate dictionary representation."""
        verdict = "pass" if self.summary.failed == 0 else "fail"
        exit_code = 0 if self.summary.failed == 0 else 1

        return {
            "khaos_test": True,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total": self.summary.total,
            "passed": self.summary.passed,
            "failed": self.summary.failed,
            "duration_ms": round(self.summary.duration_ms, 1),
            "verdict": verdict,
            "exit_code": exit_code,
            "results": [
                {
                    "name": r.name,
                    "agent": r.agent,
                    "passed": r.passed,
                    "duration_ms": round(r.duration_ms, 1),
                    "error": r.error,
                }
                for r in self.summary.results
            ],
        }

    def write(self, path: Path) -> None:
        """Write JSON to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate())
