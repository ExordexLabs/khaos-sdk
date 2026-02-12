"""Auto-input detection for agent scripts.

Detects how an agent receives input for debugging and migration purposes:
- stdin: Reads from standard input (should migrate to @khaosagent)
- args: Command-line arguments
- env: Environment variables
- file: Reads from a file
- interactive: Interactive REPL-style

Note: All agents should use the @khaosagent decorator for proper integration.
This module helps identify input patterns for legacy code migration.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class InputMethod(Enum):
    """How an agent receives input."""

    STDIN = "stdin"
    ARGS = "args"
    ENV = "env"
    FILE = "file"
    INTERACTIVE = "interactive"
    UNKNOWN = "unknown"


@dataclass
class InputPattern:
    """Detected input pattern in code."""

    method: InputMethod
    confidence: float  # 0.0 to 1.0
    line: int | None = None
    code: str | None = None
    variable: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    """Result of input method detection."""

    primary: InputMethod
    patterns: list[InputPattern] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        """Overall confidence in detection."""
        if not self.patterns:
            return 0.0
        # Weight by individual pattern confidence
        return max(p.confidence for p in self.patterns)

    def summary(self) -> str:
        """Human-readable summary."""
        if self.primary == InputMethod.UNKNOWN:
            return "Could not detect input method"
        return f"Detected: {self.primary.value} (confidence: {self.confidence:.0%})"


# Regex patterns for quick detection
STDIN_PATTERNS = [
    (r"input\s*\(", 0.9, "input() call"),
    (r"sys\.stdin", 0.95, "sys.stdin"),
    (r"stdin\.read", 0.95, "stdin.read()"),
    (r"fileinput\.", 0.8, "fileinput module"),
]

ARGS_PATTERNS = [
    (r"sys\.argv", 0.95, "sys.argv"),
    (r"argparse\.", 0.95, "argparse"),
    (r"click\.", 0.9, "click"),
    (r"typer\.", 0.9, "typer"),
    (r"fire\.Fire", 0.9, "fire.Fire"),
]

ENV_PATTERNS = [
    (r"os\.environ", 0.9, "os.environ"),
    (r"os\.getenv", 0.9, "os.getenv"),
    (r"environ\.get", 0.85, "environ.get"),
    (r"dotenv", 0.7, "dotenv"),
]

FILE_PATTERNS = [
    (r"open\s*\(['\"]", 0.6, "open() with literal path"),
    (r"Path\s*\(['\"].*\)\.read", 0.7, "Path().read"),
    (r"json\.load\s*\(", 0.5, "json.load"),
    (r"yaml\.safe_load", 0.5, "yaml.safe_load"),
]

INTERACTIVE_PATTERNS = [
    (r"while\s+True.*input\s*\(", 0.9, "interactive loop"),
    (r"prompt_toolkit", 0.95, "prompt_toolkit"),
    (r"readline\.", 0.8, "readline"),
    (r"cmd\.Cmd", 0.85, "cmd.Cmd"),
]


def _scan_patterns(
    source: str,
    patterns: list[tuple[str, float, str]],
    method: InputMethod,
) -> list[InputPattern]:
    """Scan source code for input patterns."""
    results = []
    lines = source.split("\n")

    for pattern, confidence, description in patterns:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                results.append(
                    InputPattern(
                        method=method,
                        confidence=confidence,
                        line=i,
                        code=line.strip(),
                        details={"pattern": description},
                    )
                )

    return results


def _analyze_ast(source: str) -> list[InputPattern]:
    """Analyze Python AST for input patterns."""
    results = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return results

    for node in ast.walk(tree):
        # Check for input() calls
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                results.append(
                    InputPattern(
                        method=InputMethod.STDIN,
                        confidence=0.95,
                        line=node.lineno,
                        code="input()",
                        details={"ast_type": "Call"},
                    )
                )

        # Check for sys.argv access
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                if (
                    isinstance(node.value.value, ast.Name)
                    and node.value.value.id == "sys"
                    and node.value.attr == "argv"
                ):
                    results.append(
                        InputPattern(
                            method=InputMethod.ARGS,
                            confidence=0.95,
                            line=node.lineno,
                            code="sys.argv[...]",
                            details={"ast_type": "Subscript"},
                        )
                    )

        # Check for os.getenv calls
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ("getenv", "get") and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "os" or (
                        isinstance(node.func.value, ast.Attribute)
                        and node.func.value.attr == "environ"
                    ):
                        results.append(
                            InputPattern(
                                method=InputMethod.ENV,
                                confidence=0.9,
                                line=node.lineno,
                                code="os.getenv(...)",
                                details={"ast_type": "Call"},
                            )
                        )

    return results


def detect_input_method(source: str | Path) -> DetectionResult:
    """Detect how an agent receives input.

    Args:
        source: Python source code string or path to file

    Returns:
        DetectionResult with detected patterns and recommendations
    """
    if isinstance(source, Path):
        source = source.read_text()

    all_patterns: list[InputPattern] = []

    # Regex-based detection
    all_patterns.extend(_scan_patterns(source, STDIN_PATTERNS, InputMethod.STDIN))
    all_patterns.extend(_scan_patterns(source, ARGS_PATTERNS, InputMethod.ARGS))
    all_patterns.extend(_scan_patterns(source, ENV_PATTERNS, InputMethod.ENV))
    all_patterns.extend(_scan_patterns(source, FILE_PATTERNS, InputMethod.FILE))
    all_patterns.extend(_scan_patterns(source, INTERACTIVE_PATTERNS, InputMethod.INTERACTIVE))

    # AST-based detection (more accurate)
    all_patterns.extend(_analyze_ast(source))

    # Deduplicate by line number and method
    seen = set()
    unique_patterns = []
    for p in all_patterns:
        key = (p.method, p.line)
        if key not in seen:
            seen.add(key)
            unique_patterns.append(p)

    # Sort by confidence
    unique_patterns.sort(key=lambda p: p.confidence, reverse=True)

    # Determine primary method
    if not unique_patterns:
        primary = InputMethod.UNKNOWN
    else:
        # Group by method and sum confidence
        method_scores: dict[InputMethod, float] = {}
        for p in unique_patterns:
            method_scores[p.method] = method_scores.get(p.method, 0) + p.confidence

        primary = max(method_scores, key=lambda m: method_scores[m])

    # Generate recommendations
    recommendations = []
    if primary == InputMethod.STDIN:
        recommendations.append("Agent reads stdin - add @khaosagent decorator for automatic integration")
        recommendations.append("Example: khaos run <agent-name> --pack baseline --input \"Hello\"")
    elif primary == InputMethod.ARGS:
        recommendations.append("Pass input via --input/--inputs (recommended)")
        recommendations.append("Example: khaos run <agent-name> --pack baseline --input \"Hello\"")
    elif primary == InputMethod.ENV:
        recommendations.append("Set input via environment variable")
        recommendations.append("Example: khaos run <agent-name> --env INPUT='Hello' --pack baseline --input \"Hello\"")
    elif primary == InputMethod.INTERACTIVE:
        recommendations.append("Agent appears to be interactive")
        recommendations.append("Consider using --stdin for automated testing")
    elif primary == InputMethod.UNKNOWN:
        recommendations.append("Could not detect input method")
        recommendations.append("Try running with --stdin as default")

    return DetectionResult(
        primary=primary,
        patterns=unique_patterns,
        recommendations=recommendations,
    )


def suggest_input_config(script_path: Path) -> dict[str, Any]:
    """Suggest input configuration for an agent script.

    Returns a dict that can be used to configure test case execution.
    """
    result = detect_input_method(script_path)

    config: dict[str, Any] = {
        "method": result.primary.value,
        "confidence": result.confidence,
    }

    if result.primary == InputMethod.STDIN:
        config["use_stdin"] = True
    elif result.primary == InputMethod.ARGS:
        config["use_args"] = True
        config["arg_position"] = 1  # Default to first argument
    elif result.primary == InputMethod.ENV:
        config["use_env"] = True
        # Try to detect env var name
        for p in result.patterns:
            if p.method == InputMethod.ENV and p.code:
                # Extract env var name from code like os.getenv("INPUT")
                match = re.search(r'["\']([A-Z_]+)["\']', p.code)
                if match:
                    config["env_var"] = match.group(1)
                    break

    return config
