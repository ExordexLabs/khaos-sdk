"""Input file schema for Khaos test cases.

Provides a simple YAML/JSON format for defining test cases without
needing to understand ChaosScenario internals.

Example YAML format:
    name: my_test_suite
    description: Tests for my agent

    tests:
      - name: simple_greeting
        input: "Hello, how are you?"
        expect:
          contains: "hello"

      - name: multi_turn_conversation
        conversation:
          - user: "What is Python?"
          - assistant: null  # Wait for response
          - user: "How do I install it?"
        expect:
          - contains: "python"
          - min_turns: 2

      - name: tool_usage_test
        input: "What's the weather in NYC?"
        expect:
          tools_called: ["get_weather"]
          contains: "weather"
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

@dataclass
class Turn:
    """A single turn in a conversation."""

    role: Literal["user", "assistant", "system"]
    content: str | None  # None means wait for agent response

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Turn":
        """Create Turn from dict like {"user": "hello"}."""
        if "user" in data:
            return cls(role="user", content=data["user"])
        elif "assistant" in data:
            return cls(role="assistant", content=data["assistant"])
        elif "system" in data:
            return cls(role="system", content=data["system"])
        elif "role" in data:
            return cls(role=data["role"], content=data.get("content"))
        else:
            raise ValueError(f"Invalid turn format: {data}")

@dataclass
class Conversation:
    """Multi-turn conversation for testing."""

    turns: list[Turn] = field(default_factory=list)

    @classmethod
    def from_list(cls, data: list[dict[str, Any]]) -> "Conversation":
        """Create Conversation from list of turn dicts."""
        return cls(turns=[Turn.from_dict(t) for t in data])

    def get_user_inputs(self) -> list[str]:
        """Get all user inputs in order."""
        return [t.content for t in self.turns if t.role == "user" and t.content]

    def get_initial_input(self) -> str | None:
        """Get the first user input."""
        inputs = self.get_user_inputs()
        return inputs[0] if inputs else None

@dataclass
class Expectation:
    """Expectation for test case output.

    Supports multiple assertion types:
    - contains: Output contains substring
    - not_contains: Output does not contain substring
    - regex: Output matches regex pattern
    - equals: Output exactly equals value
    - min_turns: Minimum number of conversation turns
    - max_turns: Maximum number of conversation turns
    - tools_called: List of tools that should be called
    - no_tools: No tools should be called
    - min_tokens: Minimum token count
    - max_tokens: Maximum token count
    - latency_ms: Maximum latency in milliseconds
    """

    contains: str | list[str] | None = None
    not_contains: str | list[str] | None = None
    regex: str | list[str] | None = None
    equals: str | None = None
    min_turns: int | None = None
    max_turns: int | None = None
    tools_called: list[str] | None = None
    no_tools: bool = False
    min_tokens: int | None = None
    max_tokens: int | None = None
    latency_ms: float | None = None
    custom: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Expectation":
        """Create Expectation from dict."""
        return cls(
            contains=data.get("contains"),
            not_contains=data.get("not_contains"),
            regex=data.get("regex"),
            equals=data.get("equals"),
            min_turns=data.get("min_turns"),
            max_turns=data.get("max_turns"),
            tools_called=data.get("tools_called"),
            no_tools=data.get("no_tools", False),
            min_tokens=data.get("min_tokens"),
            max_tokens=data.get("max_tokens"),
            latency_ms=data.get("latency_ms"),
            custom=data.get("custom"),
        )

    @classmethod
    def from_value(cls, value: Any) -> "Expectation":
        """Create Expectation from various input formats."""
        if isinstance(value, Expectation):
            return value
        elif isinstance(value, dict):
            return cls.from_dict(value)
        elif isinstance(value, str):
            # Simple string = contains assertion
            return cls(contains=value)
        elif isinstance(value, list):
            # List of expectations - merge them
            merged = cls()
            for item in value:
                exp = cls.from_value(item)
                merged = merged.merge(exp)
            return merged
        else:
            raise ValueError(f"Cannot convert {type(value)} to Expectation")

    def merge(self, other: "Expectation") -> "Expectation":
        """Merge two expectations together."""
        def merge_field(a: Any, b: Any) -> Any:
            if a is None:
                return b
            if b is None:
                return a
            if isinstance(a, list) and isinstance(b, list):
                return a + b
            if isinstance(a, list):
                return a + [b]
            if isinstance(b, list):
                return [a] + b
            return [a, b]

        return Expectation(
            contains=merge_field(self.contains, other.contains),
            not_contains=merge_field(self.not_contains, other.not_contains),
            regex=merge_field(self.regex, other.regex),
            equals=other.equals if other.equals else self.equals,
            min_turns=max(self.min_turns or 0, other.min_turns or 0) or None,
            max_turns=min(self.max_turns or 999, other.max_turns or 999) if (self.max_turns or other.max_turns) else None,
            tools_called=merge_field(self.tools_called, other.tools_called),
            no_tools=self.no_tools or other.no_tools,
            min_tokens=max(self.min_tokens or 0, other.min_tokens or 0) or None,
            max_tokens=min(self.max_tokens or 999999, other.max_tokens or 999999) if (self.max_tokens or other.max_tokens) else None,
            latency_ms=min(self.latency_ms or 999999, other.latency_ms or 999999) if (self.latency_ms or other.latency_ms) else None,
            custom={**(self.custom or {}), **(other.custom or {})},
        )

@dataclass
class TestCase:
    """A single test case for an agent.

    Can be defined with either:
    - input: A single user input string
    - conversation: A multi-turn conversation
    """

    name: str
    input: str | None = None
    conversation: Conversation | None = None
    expect: Expectation | None = None
    tags: list[str] = field(default_factory=list)
    timeout_ms: float | None = None
    env: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    security: bool = False  # Run security tests on this case

    def __post_init__(self):
        if not self.input and not self.conversation:
            raise ValueError("TestCase must have either 'input' or 'conversation'")
        if self.input and self.conversation:
            raise ValueError("TestCase cannot have both 'input' and 'conversation'")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TestCase":
        """Create TestCase from dict."""
        conversation = None
        if "conversation" in data:
            conversation = Conversation.from_list(data["conversation"])

        expect = None
        if "expect" in data:
            expect = Expectation.from_value(data["expect"])

        return cls(
            name=data["name"],
            input=data.get("input"),
            conversation=conversation,
            expect=expect,
            tags=data.get("tags", []),
            timeout_ms=data.get("timeout_ms"),
            env=data.get("env", {}),
            metadata=data.get("metadata", {}),
            security=data.get("security", False),
        )

    def get_initial_input(self) -> str:
        """Get the first input to send to the agent."""
        if self.input:
            return self.input
        if self.conversation:
            initial = self.conversation.get_initial_input()
            if initial:
                return initial
        raise ValueError(f"TestCase '{self.name}' has no input")

    def is_multi_turn(self) -> bool:
        """Check if this is a multi-turn conversation test."""
        if self.conversation:
            return len(self.conversation.get_user_inputs()) > 1
        return False

@dataclass
class TestSuite:
    """Collection of test cases."""

    name: str
    description: str = ""
    tests: list[TestCase] = field(default_factory=list)
    default_timeout_ms: float = 30000.0
    default_env: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TestSuite":
        """Create TestSuite from dict."""
        tests = [TestCase.from_dict(t) for t in data.get("tests", [])]
        return cls(
            name=data.get("name", "unnamed_suite"),
            description=data.get("description", ""),
            tests=tests,
            default_timeout_ms=data.get("default_timeout_ms", 30000.0),
            default_env=data.get("default_env", {}),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )

    def filter_by_tags(self, include: list[str] | None = None, exclude: list[str] | None = None) -> list[TestCase]:
        """Filter tests by tags."""
        result = []
        for test in self.tests:
            if include and not any(t in test.tags for t in include):
                continue
            if exclude and any(t in test.tags for t in exclude):
                continue
            result.append(test)
        return result

def load_test_suite(path: str | Path) -> TestSuite:
    """Load a test suite from a YAML or JSON file."""
    path = Path(path)
    with path.open("r") as f:
        if path.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(f)
        elif path.suffix == ".json":
            data = json.load(f)
        else:
            # Try YAML first, then JSON
            content = f.read()
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError:
                data = json.loads(content)

    return TestSuite.from_dict(data)

def load_test_cases(path: str | Path) -> list[TestCase]:
    """Load test cases from a file.

    Supports:
    - Full test suite format (returns all tests)
    - List of test cases directly
    - Single test case
    """
    path = Path(path)
    with path.open("r") as f:
        if path.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(f)
        elif path.suffix == ".json":
            data = json.load(f)
        else:
            content = f.read()
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError:
                data = json.loads(content)

    if isinstance(data, list):
        return [TestCase.from_dict(t) for t in data]
    elif "tests" in data:
        return TestSuite.from_dict(data).tests
    else:
        return [TestCase.from_dict(data)]
