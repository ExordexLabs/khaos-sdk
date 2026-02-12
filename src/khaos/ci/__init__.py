"""CI/CD integration module for Khaos.

Provides exit codes, reporters, and baseline comparison for CI pipelines.

Usage:
    from khaos.ci import ExitCode, JUnitReporter, BaselineManager

Exit Codes:
    0 - SUCCESS: All gates passed
    1 - SECURITY_FAIL: Security threshold not met
    2 - RESILIENCE_FAIL: Resilience threshold not met
    3 - BOTH_FAIL: Both security and resilience failed
    4 - BASELINE_FAIL: Baseline tests failed
    5 - REGRESSION_FAIL: Regression detected vs baseline
    6 - TEST_FAIL: @khaostest tests failed
    10 - CONFIG_ERROR: Configuration/setup error
    11 - RUNTIME_ERROR: Execution error
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """CI-friendly exit codes for Khaos commands.

    Uses bitwise OR for combining failures:
    - SECURITY_FAIL | RESILIENCE_FAIL = BOTH_FAIL (3)
    """

    SUCCESS = 0
    SECURITY_FAIL = 1
    RESILIENCE_FAIL = 2
    BOTH_FAIL = 3  # SECURITY_FAIL | RESILIENCE_FAIL
    BASELINE_FAIL = 4
    REGRESSION_FAIL = 5
    TEST_FAIL = 6
    CONFIG_ERROR = 10
    RUNTIME_ERROR = 11

    @classmethod
    def from_gate_results(
        cls,
        security_passed: bool,
        resilience_passed: bool,
        regression_detected: bool = False,
        fail_on_regression: bool = False,
    ) -> "ExitCode":
        """Determine exit code from gate check results."""
        if fail_on_regression and regression_detected:
            return cls.REGRESSION_FAIL

        code = cls.SUCCESS
        if not security_passed:
            code |= cls.SECURITY_FAIL
        if not resilience_passed:
            code |= cls.RESILIENCE_FAIL

        return cls(code)

    @property
    def is_success(self) -> bool:
        """Check if this exit code indicates success."""
        return self == ExitCode.SUCCESS

    @property
    def is_threshold_failure(self) -> bool:
        """Check if this is a threshold-related failure."""
        return self in (
            ExitCode.SECURITY_FAIL,
            ExitCode.RESILIENCE_FAIL,
            ExitCode.BOTH_FAIL,
        )

    def describe(self) -> str:
        """Human-readable description of exit code."""
        descriptions = {
            ExitCode.SUCCESS: "All gates passed",
            ExitCode.SECURITY_FAIL: "Security threshold not met",
            ExitCode.RESILIENCE_FAIL: "Resilience threshold not met",
            ExitCode.BOTH_FAIL: "Security and resilience thresholds not met",
            ExitCode.BASELINE_FAIL: "Baseline tests failed",
            ExitCode.REGRESSION_FAIL: "Regression detected vs baseline",
            ExitCode.TEST_FAIL: "@khaostest tests failed",
            ExitCode.CONFIG_ERROR: "Configuration error",
            ExitCode.RUNTIME_ERROR: "Runtime error during execution",
        }
        return descriptions.get(self, f"Unknown exit code: {self}")


# Re-export reporters
from khaos.ci.reporters import JUnitReporter, MarkdownReporter, JsonReporter

__all__ = [
    "ExitCode",
    "JUnitReporter",
    "MarkdownReporter",
    "JsonReporter",
]
