"""Conversation replay engine for multi-turn testing.

Feeds multi-turn conversations to agents and captures responses.
Supports various input methods detected by the detection module.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from collections.abc import AsyncIterator, Iterator

from khaos.inputs.schema import Conversation, TestCase, Turn

@dataclass
class TurnResult:
    """Result of a single conversation turn."""

    turn_index: int
    input: str
    output: str
    latency_ms: float
    tokens_in: int = 0
    tokens_out: int = 0
    tools_called: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class ReplayResult:
    """Result of replaying a conversation."""

    test_name: str
    turns: list[TurnResult] = field(default_factory=list)
    total_latency_ms: float = 0.0
    total_tokens: int = 0
    success: bool = True
    error: str | None = None
    final_output: str = ""

    @property
    def turn_count(self) -> int:
        return len(self.turns)

    def get_all_tools_called(self) -> list[str]:
        """Get all tools called across all turns."""
        tools = []
        for turn in self.turns:
            tools.extend(turn.tools_called)
        return tools

class ReplayEngine:
    """Engine for replaying conversations against an agent."""

    def __init__(
        self,
        command: list[str],
        env: dict[str, str] | None = None,
        timeout_ms: float = 30000.0,
        cwd: str | Path | None = None,
    ):
        """Initialize the replay engine.

        Args:
            command: Command to run the agent (e.g., ["python", "agent.py"])
            env: Environment variables to pass to agent
            timeout_ms: Timeout for each turn in milliseconds
            cwd: Working directory for the agent
        """
        self.command = command
        self.env = {**os.environ, **(env or {})}
        self.timeout_ms = timeout_ms
        self.cwd = Path(cwd) if cwd else None

    def _create_input_payload(self, user_input: str, turn_index: int) -> str:
        """Create input payload for the agent.

        Uses Khaos protocol format for stdin.
        """
        # Khaos protocol input format
        payload = {
            "type": "input",
            "payload": {
                "text": user_input,
                "turn": turn_index,
            },
        }
        return json.dumps(payload)

    def _parse_output(self, stdout: str) -> tuple[str, dict[str, Any]]:
        """Parse agent output.

        Handles both Khaos protocol and plain text.
        """
        text_parts = []
        metadata: dict[str, Any] = {"events": []}

        for line in stdout.strip().split("\n"):
            if not line:
                continue

            # Try to parse as JSON (Khaos protocol)
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    event_type = data.get("type", "")
                    if event_type == "output":
                        text_parts.append(data.get("payload", {}).get("text", ""))
                    elif event_type == "llm_call":
                        metadata["events"].append(data)
                    elif event_type == "tool_call":
                        metadata["events"].append(data)
                    else:
                        metadata["events"].append(data)
                    continue
            except json.JSONDecodeError:
                pass

            # Plain text output
            text_parts.append(line)

        return "\n".join(text_parts), metadata

    def _extract_tools_called(self, metadata: dict[str, Any]) -> list[str]:
        """Extract tool names from metadata events."""
        tools = []
        for event in metadata.get("events", []):
            if event.get("type") == "tool_call":
                tool_name = event.get("payload", {}).get("name")
                if tool_name:
                    tools.append(tool_name)
            elif event.get("type") == "llm_call":
                # Check for tool calls in LLM response
                tool_calls = event.get("payload", {}).get("metadata", {}).get("tool_calls", [])
                for tc in tool_calls:
                    if isinstance(tc, dict) and "name" in tc:
                        tools.append(tc["name"])
        return tools

    def _extract_tokens(self, metadata: dict[str, Any]) -> tuple[int, int]:
        """Extract token counts from metadata events."""
        tokens_in = 0
        tokens_out = 0
        for event in metadata.get("events", []):
            if event.get("type") == "llm_call":
                payload = event.get("payload", {})
                tokens = payload.get("tokens", {})
                tokens_in += tokens.get("prompt", 0)
                tokens_out += tokens.get("completion", 0)
        return tokens_in, tokens_out

    def replay_single_turn(self, user_input: str, turn_index: int = 0) -> TurnResult:
        """Replay a single turn of conversation.

        Args:
            user_input: The user's input text
            turn_index: Index of this turn in the conversation

        Returns:
            TurnResult with output and metrics
        """
        start_time = time.perf_counter()

        # Create input payload
        input_payload = self._create_input_payload(user_input, turn_index)

        try:
            result = subprocess.run(
                self.command,
                input=input_payload + "\n",
                capture_output=True,
                text=True,
                timeout=self.timeout_ms / 1000,
                env=self.env,
                cwd=self.cwd,
            )

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            # Parse output
            output, metadata = self._parse_output(result.stdout)
            tools_called = self._extract_tools_called(metadata)
            tokens_in, tokens_out = self._extract_tokens(metadata)

            return TurnResult(
                turn_index=turn_index,
                input=user_input,
                output=output,
                latency_ms=elapsed_ms,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                tools_called=tools_called,
                metadata=metadata,
            )

        except subprocess.TimeoutExpired:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return TurnResult(
                turn_index=turn_index,
                input=user_input,
                output="",
                latency_ms=elapsed_ms,
                metadata={"error": "timeout"},
            )

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return TurnResult(
                turn_index=turn_index,
                input=user_input,
                output="",
                latency_ms=elapsed_ms,
                metadata={"error": str(e)},
            )

    def replay_conversation(self, conversation: Conversation) -> ReplayResult:
        """Replay a full multi-turn conversation.

        Args:
            conversation: The conversation to replay

        Returns:
            ReplayResult with all turn results
        """
        result = ReplayResult(test_name="conversation")
        user_inputs = conversation.get_user_inputs()

        for i, user_input in enumerate(user_inputs):
            turn_result = self.replay_single_turn(user_input, turn_index=i)
            result.turns.append(turn_result)
            result.total_latency_ms += turn_result.latency_ms
            result.total_tokens += turn_result.tokens_in + turn_result.tokens_out

            if "error" in turn_result.metadata:
                result.success = False
                result.error = turn_result.metadata["error"]
                break

        if result.turns:
            result.final_output = result.turns[-1].output

        return result

    def replay_test_case(self, test_case: TestCase) -> ReplayResult:
        """Replay a test case.

        Args:
            test_case: The test case to run

        Returns:
            ReplayResult with execution details
        """
        result = ReplayResult(test_name=test_case.name)

        # Apply test case env
        original_env = self.env.copy()
        self.env.update(test_case.env)

        # Apply timeout
        original_timeout = self.timeout_ms
        if test_case.timeout_ms:
            self.timeout_ms = test_case.timeout_ms

        try:
            if test_case.conversation:
                # Multi-turn conversation
                conv_result = self.replay_conversation(test_case.conversation)
                result.turns = conv_result.turns
                result.total_latency_ms = conv_result.total_latency_ms
                result.total_tokens = conv_result.total_tokens
                result.success = conv_result.success
                result.error = conv_result.error
                result.final_output = conv_result.final_output
            else:
                # Single input
                turn_result = self.replay_single_turn(test_case.get_initial_input())
                result.turns.append(turn_result)
                result.total_latency_ms = turn_result.latency_ms
                result.total_tokens = turn_result.tokens_in + turn_result.tokens_out
                result.final_output = turn_result.output

                if "error" in turn_result.metadata:
                    result.success = False
                    result.error = turn_result.metadata["error"]

        finally:
            self.env = original_env
            self.timeout_ms = original_timeout

        return result

def replay_test_cases(
    command: list[str],
    test_cases: list[TestCase],
    env: dict[str, str] | None = None,
    timeout_ms: float = 30000.0,
    cwd: str | Path | None = None,
) -> Iterator[ReplayResult]:
    """Replay multiple test cases.

    Args:
        command: Command to run the agent
        test_cases: List of test cases to run
        env: Environment variables
        timeout_ms: Default timeout
        cwd: Working directory

    Yields:
        ReplayResult for each test case
    """
    engine = ReplayEngine(
        command=command,
        env=env,
        timeout_ms=timeout_ms,
        cwd=cwd,
    )

    for test_case in test_cases:
        yield engine.replay_test_case(test_case)
