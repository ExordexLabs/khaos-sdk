"""Agent discovery system.

Provides robust detection of agent entry points across different patterns:
- Functions (sync and async)
- Classes with callable methods
- Framework-specific patterns (Crew, StateGraph, etc.)
- Decorated handlers (@khaos_agent)
"""

from .detector import (
    AgentEntryPoint,
    EntryPointType,
    detect_entry_points,
    select_best_entry_point,
)
from .patterns import (
    FRAMEWORK_PATTERNS,
    CALLABLE_PATTERNS,
    register_pattern,
)

__all__ = [
    "AgentEntryPoint",
    "EntryPointType",
    "detect_entry_points",
    "select_best_entry_point",
    "FRAMEWORK_PATTERNS",
    "CALLABLE_PATTERNS",
    "register_pattern",
]
