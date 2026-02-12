"""Session capture and YAML export for the Khaos Playground.

This module captures all interactions during a playground session and
can export them as a valid Khaos pack YAML for CI/CD integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


@dataclass
class SessionEvent:
    """A single event in a playground session."""

    timestamp: datetime
    event_type: Literal[
        "user_message",
        "agent_response",
        "tool_call",
        "tool_result",
        "fault_toggle",
        "security_attack",
    ]
    content: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FaultToggle:
    """Record of a fault being toggled."""

    timestamp: datetime
    fault: str
    enabled: bool


@dataclass
class PlaygroundSession:
    """Captures a playground session for YAML export.

    The session records all user prompts, agent responses, tool calls,
    fault toggles, and security attacks to enable exporting as a
    reproducible Khaos pack.
    """

    agent_name: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    events: list[SessionEvent] = field(default_factory=list)
    fault_toggles: list[FaultToggle] = field(default_factory=list)
    security_attacks: list[str] = field(default_factory=list)

    def add_user_message(self, content: str) -> None:
        """Add a user message to the session."""
        self.events.append(
            SessionEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="user_message",
                content=content,
            )
        )

    def add_agent_response(self, content: str) -> None:
        """Add an agent response to the session."""
        self.events.append(
            SessionEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="agent_response",
                content=content,
            )
        )

    def add_tool_call(
        self, tool: str, args: dict[str, Any], call_id: str = ""
    ) -> None:
        """Add a tool call to the session."""
        self.events.append(
            SessionEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="tool_call",
                content=tool,
                metadata={"args": args, "call_id": call_id},
            )
        )

    def add_tool_result(
        self, tool: str, result: Any, duration_ms: int, call_id: str = ""
    ) -> None:
        """Add a tool result to the session."""
        self.events.append(
            SessionEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="tool_result",
                content=tool,
                metadata={"result": result, "duration_ms": duration_ms, "call_id": call_id},
            )
        )

    def add_fault_toggle(self, fault: str, enabled: bool) -> None:
        """Add a fault toggle to the session."""
        self.fault_toggles.append(
            FaultToggle(
                timestamp=datetime.now(timezone.utc),
                fault=fault,
                enabled=enabled,
            )
        )
        self.events.append(
            SessionEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="fault_toggle",
                content=fault,
                metadata={"enabled": enabled},
            )
        )

    def add_security_attack(self, attack_id: str) -> None:
        """Add a security attack to the session."""
        self.security_attacks.append(attack_id)
        self.events.append(
            SessionEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="security_attack",
                content=attack_id,
            )
        )

    def _extract_conversations(self) -> list[dict[str, Any]]:
        """Extract user/agent conversation turns from events."""
        conversations = []
        current_turn: dict[str, Any] | None = None

        for event in self.events:
            if event.event_type == "user_message":
                if current_turn:
                    conversations.append(current_turn)
                current_turn = {
                    "text": event.content,
                    "expected_response": None,
                    "metadata": {},
                }
            elif event.event_type == "agent_response" and current_turn:
                # Store response for goal inference
                current_turn["expected_response"] = event.content

        if current_turn:
            conversations.append(current_turn)

        return conversations

    def _infer_goals(self) -> list[dict[str, Any]]:
        """Infer goal criteria from the conversations.

        This creates basic goal criteria based on observed responses.
        Users can refine these in the exported YAML.
        """
        goals = []
        for conv in self._extract_conversations():
            goal: dict[str, Any] = {}
            response = conv.get("expected_response", "")

            if response:
                # Basic goal: response should be non-empty
                goal["min_length"] = 1

                # If response contains specific patterns, add contains criteria
                # This is a heuristic - users should refine
                if len(response) > 50:
                    # For longer responses, just check minimum length
                    goal["min_length"] = 10

            goals.append({"text": conv["text"], "goal": goal if goal else None})

        return goals

    def _build_fault_config(self) -> dict[str, Any] | None:
        """Build fault configuration from toggles."""
        if not self.fault_toggles:
            return None

        # Get final state of each fault
        final_state: dict[str, bool] = {}
        for toggle in self.fault_toggles:
            final_state[toggle.fault] = toggle.enabled

        # Convert to fault rules
        rules = []
        if final_state.get("llm_timeout"):
            rules.append({"type": "timeout", "delay_seconds": 30})
        if final_state.get("llm_rate_limit"):
            rules.append({"type": "rate_limit"})
        if final_state.get("llm_malformed"):
            rules.append({"type": "malformed_response"})
        if final_state.get("http_network_error"):
            rules.append({"type": "http_error", "status_code": 0})
        if final_state.get("http_slow_response"):
            rules.append({"type": "http_slow", "delay_seconds": 10})
        if final_state.get("http_bad_status"):
            rules.append({"type": "http_error", "status_code": 500})

        return {"rules": rules} if rules else None

    def to_yaml(self) -> str:
        """Export session as Khaos pack YAML.

        The exported YAML can be used directly with `khaos run` to
        reproduce the session interactions.
        """
        import yaml

        timestamp = self.created_at.strftime("%Y%m%d_%H%M%S")
        pack_name = f"playground-{self.agent_name}-{timestamp}"

        # Build inputs from conversations
        inputs = self._infer_goals()

        # Build pack structure
        pack_data: dict[str, Any] = {
            "pack": {
                "name": pack_name,
                "version": "1.0",
                "description": f"Exported from playground session with {self.agent_name}",
                "metadata": {
                    "source": "playground",
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "session_duration_events": len(self.events),
                },
            },
            "phases": {},
        }

        # Add baseline phase with inputs
        if inputs:
            pack_data["phases"]["baseline"] = {
                "inputs": [
                    {"text": i["text"], "goal": i["goal"]} for i in inputs if i.get("text")
                ]
            }

        # Add resilience phase if faults were used
        fault_config = self._build_fault_config()
        if fault_config:
            pack_data["phases"]["resilience"] = {
                "fault_config": fault_config,
            }

        # Add security phase if attacks were used
        if self.security_attacks:
            pack_data["phases"]["security"] = {
                "security": True,
                "security_config": {
                    "attack_ids": list(set(self.security_attacks)),
                },
            }

        # Format as YAML with nice formatting
        return yaml.dump(
            pack_data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=100,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert session to dictionary for JSON serialization."""
        return {
            "agent_name": self.agent_name,
            "created_at": self.created_at.isoformat(),
            "events": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "event_type": e.event_type,
                    "content": e.content,
                    "metadata": e.metadata,
                }
                for e in self.events
            ],
            "fault_toggles": [
                {
                    "timestamp": f.timestamp.isoformat(),
                    "fault": f.fault,
                    "enabled": f.enabled,
                }
                for f in self.fault_toggles
            ],
            "security_attacks": self.security_attacks,
        }
