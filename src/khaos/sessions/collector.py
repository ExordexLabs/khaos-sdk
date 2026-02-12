"""Session collector with turn boundary detection.

Collects LLM telemetry events and organizes them into a coherent
session structure with automatic turn detection.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterator

from khaos.sessions.models import (
    LLMCall,
    Message,
    MessageRole,
    Session,
    ToolCall,
    Turn,
)

class SessionCollector:
    """Collects and organizes LLM events into sessions.

    Features:
    - Automatic turn boundary detection
    - Message history reconstruction
    - Context growth tracking
    """

    def __init__(
        self,
        agent_name: str = "",
        agent_version: str = "",
        session_id: str | None = None,
    ):
        """Initialize the collector.

        Args:
            agent_name: Name of the agent
            agent_version: Version of the agent
            session_id: Optional session ID (auto-generated if not provided)
        """
        self.agent_name = agent_name
        self.agent_version = agent_version
        self._session_id = session_id
        self._events: list[dict[str, Any]] = []
        self._messages: list[Message] = []

    def add_event(self, event: dict[str, Any]) -> None:
        """Add a telemetry event to the collection."""
        self._events.append(event)

    def add_events(self, events: list[dict[str, Any]]) -> None:
        """Add multiple events."""
        self._events.extend(events)

    def add_message(self, role: MessageRole, content: str | None) -> None:
        """Add a message to the conversation history."""
        self._messages.append(Message(role=role, content=content))

    def build_session(self) -> Session:
        """Build a Session from collected events.

        Automatically detects turn boundaries and organizes
        LLM calls into turns.
        """
        # Parse all LLM calls from events
        llm_calls = self._parse_llm_calls()

        # Detect turns from LLM calls
        turns = self._detect_turns(llm_calls)

        # Build message history from turns
        messages = self._build_message_history(turns)

        # Calculate timing
        start_time = llm_calls[0].timestamp if llm_calls else datetime.now(timezone.utc)
        end_time = llm_calls[-1].timestamp if llm_calls else None

        return Session(
            session_id=self._session_id or None,  # Will auto-generate if None
            agent_name=self.agent_name,
            agent_version=self.agent_version,
            start_time=start_time,
            end_time=end_time,
            turns=turns,
            messages=messages,
            llm_calls=llm_calls,
        )

    def _parse_llm_calls(self) -> list[LLMCall]:
        """Parse LLM calls from collected events."""
        calls = []
        for event in self._events:
            event_type = event.get("event", event.get("type", ""))
            if event_type in ("llm.call", "llm_call"):
                calls.append(LLMCall.from_event(event))
        return sorted(calls, key=lambda c: c.timestamp)

    def _detect_turns(self, llm_calls: list[LLMCall]) -> list[Turn]:
        """Detect turn boundaries from LLM calls.

        Turn boundary heuristics:
        1. First call starts a new turn
        2. A call with tool calls continues the current turn
        3. A call after tool results may be same turn (follow-up)
        4. A call with significantly different context starts new turn
        """
        if not llm_calls:
            return []

        turns: list[Turn] = []
        current_turn: Turn | None = None
        turn_index = 0

        for call in llm_calls:
            # Check if this starts a new turn
            should_start_new_turn = False

            if current_turn is None:
                should_start_new_turn = True
            elif self._is_turn_boundary(current_turn, call):
                should_start_new_turn = True

            if should_start_new_turn:
                if current_turn:
                    turns.append(current_turn)
                turn_index = len(turns)
                current_turn = Turn(
                    turn_index=turn_index,
                    start_time=call.timestamp,
                )

            # Add call to current turn
            current_turn.llm_calls.append(call)
            current_turn.end_time = call.timestamp

            # Track tool calls
            current_turn.tool_calls.extend(call.tool_calls)

        # Add final turn
        if current_turn:
            turns.append(current_turn)

        # Reconstruct user/assistant messages for each turn
        self._populate_turn_messages(turns)

        return turns

    def _is_turn_boundary(self, current_turn: Turn, call: LLMCall) -> bool:
        """Determine if a call represents a turn boundary.

        Returns True if this call should start a new turn.
        """
        # If current turn has no calls, not a boundary
        if not current_turn.llm_calls:
            return False

        last_call = current_turn.llm_calls[-1]

        # If last call had tool calls and this call is a follow-up, same turn
        if last_call.tool_calls and call.finish_reason != "stop":
            return False

        # If last call finished with "stop" and significant time gap, new turn
        if last_call.finish_reason == "stop":
            time_gap_ms = (call.timestamp - last_call.timestamp).total_seconds() * 1000
            # More than 100ms gap after a "stop" suggests new user input
            if time_gap_ms > 100:
                return True

        # If context size (prompt tokens) drops significantly, new turn
        # (suggests context was reset for new conversation)
        if call.prompt_tokens < last_call.prompt_tokens * 0.5:
            return True

        # If context grew by more than 2x, likely new user input
        if call.prompt_tokens > last_call.prompt_tokens * 2:
            return True

        return False

    def _populate_turn_messages(self, turns: list[Turn]) -> None:
        """Populate user/assistant messages for each turn."""
        for turn in turns:
            if not turn.llm_calls:
                continue

            # First call in turn typically contains user message
            first_call = turn.llm_calls[0]
            last_call = turn.llm_calls[-1]

            # Create user message from first call's prompt
            if first_call.prompt:
                turn.user_message = Message(
                    role=MessageRole.USER,
                    content=first_call.prompt,
                    timestamp=first_call.timestamp,
                )

            # Create assistant message from last call's completion
            if last_call.completion:
                turn.assistant_message = Message(
                    role=MessageRole.ASSISTANT,
                    content=last_call.completion,
                    timestamp=last_call.timestamp,
                )

    def _build_message_history(self, turns: list[Turn]) -> list[Message]:
        """Build full message history from turns."""
        messages = []

        for turn in turns:
            if turn.user_message:
                messages.append(turn.user_message)

            # Add tool call/result messages if present
            for tool_call in turn.tool_calls:
                # Tool call request
                messages.append(Message(
                    role=MessageRole.ASSISTANT,
                    content=None,
                    tool_call_id=tool_call.id,
                    tool_name=tool_call.name,
                    metadata={"arguments": tool_call.arguments},
                ))
                # Tool result if available
                if tool_call.result:
                    messages.append(Message(
                        role=MessageRole.TOOL,
                        content=tool_call.result,
                        tool_call_id=tool_call.id,
                        tool_name=tool_call.name,
                    ))

            if turn.assistant_message:
                messages.append(turn.assistant_message)

        return messages

    def clear(self) -> None:
        """Clear all collected events."""
        self._events.clear()
        self._messages.clear()

def collect_session(
    events: list[dict[str, Any]],
    agent_name: str = "",
    agent_version: str = "",
) -> Session:
    """Convenience function to collect events into a session.

    Args:
        events: List of telemetry events
        agent_name: Name of the agent
        agent_version: Version of the agent

    Returns:
        Session object with organized telemetry
    """
    collector = SessionCollector(
        agent_name=agent_name,
        agent_version=agent_version,
    )
    collector.add_events(events)
    return collector.build_session()

def load_session_from_file(path: str | Path) -> Session:
    """Load a session from a JSONL event file.

    Args:
        path: Path to JSONL event file

    Returns:
        Session object
    """
    path = Path(path)
    events = []

    with path.open("r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    return collect_session(events)

def iter_sessions_from_file(path: str | Path) -> Iterator[Session]:
    """Iterate over sessions in a JSONL file.

    Sessions are separated by gaps in timestamp or session_id changes.
    """
    path = Path(path)
    current_events: list[dict[str, Any]] = []
    last_timestamp: datetime | None = None

    with path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Check for session boundary
            ts_str = event.get("ts")
            try:
                timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else None
            except (ValueError, AttributeError):
                timestamp = None

            # If large time gap (> 60s), emit current session and start new
            if last_timestamp and timestamp:
                gap = (timestamp - last_timestamp).total_seconds()
                if gap > 60:
                    if current_events:
                        yield collect_session(current_events)
                    current_events = []

            current_events.append(event)
            last_timestamp = timestamp

    # Emit final session
    if current_events:
        yield collect_session(current_events)
