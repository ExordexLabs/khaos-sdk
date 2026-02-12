"""Transpiler from user-friendly inputs to ChaosScenario.

Converts TestCase and TestSuite objects to internal ChaosScenario
format for execution by the Khaos engine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from khaos.inputs.schema import Expectation, TestCase, TestSuite


def _expectation_to_assertions(
    expectation: Expectation,
    name_prefix: str = "assert",
) -> list[dict[str, Any]]:
    """Convert Expectation to list of assertion definitions.

    Returns list of dicts compatible with ChaosScenario AssertionDefinition.
    """
    assertions = []
    idx = 0

    def _to_list(val: Any) -> list[Any]:
        if val is None:
            return []
        if isinstance(val, list):
            return val
        return [val]

    # Contains assertions
    for val in _to_list(expectation.contains):
        assertions.append({
            "name": f"{name_prefix}_{idx}_contains",
            "description": f"Output contains '{val}'",
            "target": "final_response",
            "path": "payload",
            "type": "contains",
            "expected": val,
            "ignore_case": True,
        })
        idx += 1

    # Not contains assertions
    for val in _to_list(expectation.not_contains):
        assertions.append({
            "name": f"{name_prefix}_{idx}_not_contains",
            "description": f"Output does not contain '{val}'",
            "target": "final_response",
            "path": "payload",
            "type": "not_contains",
            "expected": val,
            "ignore_case": True,
        })
        idx += 1

    # Regex assertions
    for val in _to_list(expectation.regex):
        assertions.append({
            "name": f"{name_prefix}_{idx}_regex",
            "description": f"Output matches pattern '{val}'",
            "target": "final_response",
            "path": "payload",
            "type": "regex",
            "expected": val,
        })
        idx += 1

    # Equals assertion
    if expectation.equals is not None:
        assertions.append({
            "name": f"{name_prefix}_{idx}_equals",
            "description": "Output equals expected",
            "target": "final_response",
            "path": "payload",
            "type": "equals",
            "expected": expectation.equals,
        })
        idx += 1

    # Tool assertions
    if expectation.tools_called:
        for tool in expectation.tools_called:
            assertions.append({
                "name": f"{name_prefix}_{idx}_tool_{tool}",
                "description": f"Tool '{tool}' was called",
                "target": "any_tool_call",
                "path": "payload.name",
                "type": "equals",
                "expected": tool,
            })
            idx += 1

    if expectation.no_tools:
        assertions.append({
            "name": f"{name_prefix}_{idx}_no_tools",
            "description": "No tools should be called",
            "target": "first_tool_call",
            "path": "payload",
            "type": "not_exists",
            "expected": "",
        })
        idx += 1

    return assertions


def _test_case_to_input_config(test_case: TestCase) -> dict[str, Any]:
    """Convert TestCase input to ChaosScenario input configuration."""
    if test_case.conversation:
        # Multi-turn conversation
        return {
            "type": "conversation",
            "turns": [
                {"role": t.role, "content": t.content}
                for t in test_case.conversation.turns
            ],
        }
    else:
        # Single input
        return {
            "type": "single",
            "text": test_case.input,
        }


def to_chaos_scenario(
    test_case: TestCase,
    agent_command: list[str] | None = None,
) -> dict[str, Any]:
    """Convert a TestCase to a ChaosScenario dict.

    Args:
        test_case: The test case to convert
        agent_command: Optional agent command (for reference)

    Returns:
        Dict compatible with ChaosScenario.from_dict()
    """
    scenario: dict[str, Any] = {
        "name": test_case.name,
        "description": f"Auto-generated from TestCase '{test_case.name}'",
        "version": "1.0.0",
        "metadata": {
            **test_case.metadata,
            "source": "khaos.inputs",
            "tags": test_case.tags,
        },
    }

    # Input configuration
    scenario["input"] = _test_case_to_input_config(test_case)

    # Environment
    if test_case.env:
        scenario["env"] = test_case.env

    # Timeout
    if test_case.timeout_ms:
        scenario["timeout_ms"] = test_case.timeout_ms

    # Assertions from expectations
    if test_case.expect:
        assertions = _expectation_to_assertions(
            test_case.expect,
            name_prefix=f"{test_case.name}_assert",
        )
        if assertions:
            scenario["assertions"] = assertions

            # Create a default goal
            scenario["goals"] = [{
                "name": f"{test_case.name}_goal",
                "description": f"All assertions for {test_case.name}",
                "assertions": [a["name"] for a in assertions],
                "weight": 1.0,
                "success_threshold": 1.0,
            }]

    # Security testing
    if test_case.security:
        scenario["security_enabled"] = True

    return scenario


def transpile_test_suite(
    suite: TestSuite,
    agent_command: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Transpile a TestSuite to list of ChaosScenario dicts.

    Args:
        suite: The test suite to transpile
        agent_command: Optional agent command

    Returns:
        List of dicts compatible with ChaosScenario.from_dict()
    """
    scenarios = []

    for test_case in suite.tests:
        # Apply suite defaults
        if suite.default_timeout_ms and not test_case.timeout_ms:
            test_case.timeout_ms = suite.default_timeout_ms

        if suite.default_env:
            merged_env = {**suite.default_env, **test_case.env}
            test_case.env = merged_env

        if suite.tags:
            test_case.tags = list(set(test_case.tags + suite.tags))

        scenario = to_chaos_scenario(test_case, agent_command)

        # Add suite metadata
        scenario["metadata"]["suite_name"] = suite.name
        scenario["metadata"]["suite_description"] = suite.description

        scenarios.append(scenario)

    return scenarios


def save_scenarios(
    scenarios: list[dict[str, Any]],
    output_dir: str | Path,
    format: str = "yaml",
) -> list[Path]:
    """Save transpiled scenarios to files.

    Args:
        scenarios: List of scenario dicts
        output_dir: Directory to save files
        format: Output format ("yaml" or "json")

    Returns:
        List of paths to saved files
    """
    import json
    import yaml

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    saved = []
    for scenario in scenarios:
        name = scenario.get("name", "unnamed")
        # Sanitize name for filename
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)

        if format == "yaml":
            path = output_dir / f"{safe_name}.yaml"
            with path.open("w") as f:
                yaml.safe_dump(scenario, f, default_flow_style=False)
        else:
            path = output_dir / f"{safe_name}.json"
            with path.open("w") as f:
                json.dump(scenario, f, indent=2)

        saved.append(path)

    return saved


def transpile_file(
    input_path: str | Path,
    output_dir: str | Path | None = None,
    format: str = "yaml",
) -> list[dict[str, Any]] | list[Path]:
    """Transpile a test file to ChaosScenarios.

    Args:
        input_path: Path to input test file (YAML/JSON)
        output_dir: If provided, save scenarios to this directory
        format: Output format if saving ("yaml" or "json")

    Returns:
        List of scenario dicts, or list of saved file paths if output_dir provided
    """
    from khaos.inputs.schema import load_test_suite

    suite = load_test_suite(input_path)
    scenarios = transpile_test_suite(suite)

    if output_dir:
        return save_scenarios(scenarios, output_dir, format)

    return scenarios
