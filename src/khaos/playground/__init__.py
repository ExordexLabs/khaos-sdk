"""Khaos Playground - Interactive agent testing interface.

The playground allows users to interact with their @khaosagent agents in real-time
through a ChatGPT-like interface, with fault injection controls and security testing.
"""

from __future__ import annotations

from .protocol import (
    ClientMessageType,
    ServerMessageType,
    ClientMessage,
    ServerMessage,
    FaultType,
    FaultState,
    ToolInfo,
    AgentInfo,
    TokenUsage,
)
from .server import PlaygroundServer
from .session import PlaygroundSession
from .auth import (
    PlaygroundAuthError,
    NotLoggedInError,
    SessionLimitError,
    PlaygroundSessionInfo,
    request_playground_session,
    request_playground_session_sync,
    is_authenticated,
)

__all__ = [
    # Protocol types
    "ClientMessageType",
    "ServerMessageType",
    "ClientMessage",
    "ServerMessage",
    "FaultType",
    "FaultState",
    "ToolInfo",
    "AgentInfo",
    "TokenUsage",
    # Server
    "PlaygroundServer",
    # Session
    "PlaygroundSession",
    # Auth
    "PlaygroundAuthError",
    "NotLoggedInError",
    "SessionLimitError",
    "PlaygroundSessionInfo",
    "request_playground_session",
    "request_playground_session_sync",
    "is_authenticated",
]
