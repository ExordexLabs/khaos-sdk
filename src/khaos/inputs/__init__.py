"""Unified Input System for Khaos.

Provides a simple, user-friendly way to define test cases without
needing to understand the Khaos protocol or ChaosScenario internals.

Example usage:
    from khaos.inputs import TestCase, load_test_cases

    # Load from YAML
    cases = load_test_cases("tests.yaml")

    # Or create programmatically
    case = TestCase(
        name="greeting_test",
        input="Hello, how are you?",
        expect={"contains": "hello"}
    )
"""

from khaos.inputs.schema import (
    Conversation,
    Expectation,
    TestCase,
    TestSuite,
    Turn,
    load_test_cases,
    load_test_suite,
)
from khaos.inputs.expectations import (
    ExpectationResult,
    evaluate_expectation,
    evaluate_expectations,
)
from khaos.inputs.detection import (
    InputMethod,
    detect_input_method,
)
from khaos.inputs.transpiler import (
    to_chaos_scenario,
    transpile_test_suite,
)

__all__ = [
    # Schema
    "TestCase",
    "TestSuite",
    "Conversation",
    "Turn",
    "Expectation",
    "load_test_cases",
    "load_test_suite",
    # Expectations
    "ExpectationResult",
    "evaluate_expectation",
    "evaluate_expectations",
    # Detection
    "InputMethod",
    "detect_input_method",
    # Transpiler
    "to_chaos_scenario",
    "transpile_test_suite",
]
