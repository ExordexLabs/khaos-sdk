"""Entry point detection patterns.

Extensible pattern registry for detecting agent entry points.
Patterns are organized by priority - higher priority patterns match first.
"""

from __future__ import annotations
from collections.abc import Callable

from dataclasses import dataclass, field
from enum import Enum

class PatternType(Enum):
    """Type of pattern for detection."""

    DECORATOR = "decorator"      # @khaos_agent, @agent, etc.
    FUNCTION = "function"        # Named functions
    ASYNC_FUNCTION = "async_function"  # Async functions
    CLASS = "class"              # Class definitions
    CLASS_METHOD = "class_method"  # Methods on classes
    FRAMEWORK = "framework"      # Framework-specific patterns
    VARIABLE = "variable"        # Variable assignments (crew = Crew(...))

@dataclass(frozen=True, slots=True)
class DetectionPattern:
    """A pattern for detecting agent entry points."""

    name: str
    pattern_type: PatternType
    priority: int  # Higher = matched first (100 = decorator, 50 = common, 10 = fallback)

    # What to match
    match_names: tuple[str, ...] = ()  # Function/class/method names
    match_decorators: tuple[str, ...] = ()  # Decorator names
    match_base_classes: tuple[str, ...] = ()  # Base class names
    match_imports: tuple[str, ...] = ()  # Required imports

    # Invocation info
    invoke_method: str | None = None  # Method to call on class instances
    invoke_style: str = "call"  # "call", "invoke", "run", "kickoff", etc.

    # Framework association
    framework: str | None = None

    # Description for debugging
    description: str = ""

# ============================================================================
# Decorator Patterns (Priority 100) - Highest priority, explicit user intent
# ============================================================================

DECORATOR_PATTERNS: list[DetectionPattern] = [
    # Primary unified decorator (highest priority)
    DetectionPattern(
        name="khaosagent_unified",
        pattern_type=PatternType.DECORATOR,
        priority=100,
        match_decorators=("khaosagent", "khaos.khaosagent"),
        description="Unified @khaosagent decorator (primary)",
    ),
    # Deprecated underscore version (still supported for backwards compat)
    DetectionPattern(
        name="khaos_agent_deprecated",
        pattern_type=PatternType.DECORATOR,
        priority=99,
        match_decorators=("khaos_agent", "khaos.khaos_agent"),
        description="Deprecated @khaos_agent decorator (use @khaosagent)",
    ),
    DetectionPattern(
        name="agent_decorator",
        pattern_type=PatternType.DECORATOR,
        priority=95,
        match_decorators=("agent", "tool", "task"),
        description="Common agent framework decorators",
    ),
]

# ============================================================================
# Framework Patterns (Priority 80) - Known framework patterns
# ============================================================================

FRAMEWORK_PATTERNS: list[DetectionPattern] = [
    # LangGraph
    DetectionPattern(
        name="langgraph_compiled",
        pattern_type=PatternType.VARIABLE,
        priority=85,
        match_imports=("langgraph",),
        invoke_method="invoke",
        invoke_style="invoke",
        framework="langgraph",
        description="LangGraph compiled graph (app = graph.compile())",
    ),
    DetectionPattern(
        name="langgraph_stategraph",
        pattern_type=PatternType.CLASS,
        priority=80,
        match_base_classes=("StateGraph", "Graph"),
        match_imports=("langgraph",),
        invoke_method="invoke",
        framework="langgraph",
        description="LangGraph StateGraph class",
    ),

    # CrewAI
    DetectionPattern(
        name="crewai_crew",
        pattern_type=PatternType.CLASS,
        priority=85,
        match_base_classes=("Crew",),
        match_imports=("crewai",),
        invoke_method="kickoff",
        invoke_style="kickoff",
        framework="crewai",
        description="CrewAI Crew class",
    ),
    DetectionPattern(
        name="crewai_agent",
        pattern_type=PatternType.CLASS,
        priority=75,
        match_base_classes=("Agent",),
        match_imports=("crewai",),
        framework="crewai",
        description="CrewAI Agent class",
    ),

    # AutoGen
    DetectionPattern(
        name="autogen_agent",
        pattern_type=PatternType.CLASS,
        priority=80,
        match_base_classes=("AssistantAgent", "UserProxyAgent", "ConversableAgent"),
        match_imports=("autogen", "pyautogen"),
        invoke_method="initiate_chat",
        framework="autogen",
        description="AutoGen agent classes",
    ),

    # LlamaIndex
    DetectionPattern(
        name="llamaindex_engine",
        pattern_type=PatternType.CLASS,
        priority=80,
        match_base_classes=("QueryEngine", "ChatEngine", "BaseQueryEngine"),
        match_imports=("llama_index", "llama-index"),
        invoke_method="query",
        framework="llamaindex",
        description="LlamaIndex query/chat engine",
    ),

    # Instructor
    DetectionPattern(
        name="instructor_client",
        pattern_type=PatternType.VARIABLE,
        priority=75,
        match_imports=("instructor",),
        framework="instructor",
        description="Instructor-wrapped client",
    ),
]

# ============================================================================
# Function Patterns (Priority 50) - Common function names
# ============================================================================

FUNCTION_PATTERNS: list[DetectionPattern] = [
    # High-signal names
    DetectionPattern(
        name="handle_function",
        pattern_type=PatternType.FUNCTION,
        priority=60,
        match_names=("handle", "handler"),
        description="Handler function pattern",
    ),
    DetectionPattern(
        name="agent_function",
        pattern_type=PatternType.FUNCTION,
        priority=55,
        match_names=("agent", "chat_agent", "run_agent"),
        description="Agent function pattern",
    ),

    # Common patterns
    DetectionPattern(
        name="process_function",
        pattern_type=PatternType.FUNCTION,
        priority=50,
        match_names=("process", "process_message", "process_input"),
        description="Process function pattern",
    ),
    DetectionPattern(
        name="execute_function",
        pattern_type=PatternType.FUNCTION,
        priority=50,
        match_names=("execute", "execute_agent", "execute_task"),
        description="Execute function pattern",
    ),
    DetectionPattern(
        name="invoke_function",
        pattern_type=PatternType.FUNCTION,
        priority=50,
        match_names=("invoke", "call", "query"),
        description="Invoke/call function pattern",
    ),
    DetectionPattern(
        name="run_function",
        pattern_type=PatternType.FUNCTION,
        priority=45,
        match_names=("run", "run_agent", "run_chat"),
        description="Run function pattern",
    ),
    DetectionPattern(
        name="chat_function",
        pattern_type=PatternType.FUNCTION,
        priority=45,
        match_names=("chat", "complete", "generate", "respond"),
        description="Chat/generate function pattern",
    ),

    # Lower priority fallbacks
    DetectionPattern(
        name="main_function",
        pattern_type=PatternType.FUNCTION,
        priority=30,
        match_names=("main",),
        description="Main function fallback",
    ),
]

# ============================================================================
# Async Function Patterns (Priority 50) - Same as sync but async
# ============================================================================

ASYNC_FUNCTION_PATTERNS: list[DetectionPattern] = [
    DetectionPattern(
        name="async_handle",
        pattern_type=PatternType.ASYNC_FUNCTION,
        priority=60,
        match_names=("handle", "handler", "async_handle", "async_handler"),
        description="Async handler function",
    ),
    DetectionPattern(
        name="async_process",
        pattern_type=PatternType.ASYNC_FUNCTION,
        priority=50,
        match_names=("process", "process_message", "async_process"),
        description="Async process function",
    ),
    DetectionPattern(
        name="async_run",
        pattern_type=PatternType.ASYNC_FUNCTION,
        priority=45,
        match_names=("run", "arun", "async_run"),
        description="Async run function",
    ),
]

# ============================================================================
# Class Patterns (Priority 40) - Generic class patterns
# ============================================================================

CLASS_PATTERNS: list[DetectionPattern] = [
    DetectionPattern(
        name="agent_class",
        pattern_type=PatternType.CLASS,
        priority=45,
        match_names=("Agent", "ChatAgent", "AIAgent", "LLMAgent"),
        invoke_method="run",
        description="Generic agent class",
    ),
    DetectionPattern(
        name="bot_class",
        pattern_type=PatternType.CLASS,
        priority=40,
        match_names=("Bot", "ChatBot", "Assistant"),
        invoke_method="respond",
        description="Bot/assistant class",
    ),
    DetectionPattern(
        name="handler_class",
        pattern_type=PatternType.CLASS,
        priority=40,
        match_names=("Handler", "MessageHandler", "RequestHandler"),
        invoke_method="handle",
        description="Handler class",
    ),
]

# ============================================================================
# Class Method Patterns (Priority 35) - Methods to look for on classes
# ============================================================================

CALLABLE_PATTERNS: tuple[str, ...] = (
    # High signal
    "__call__",
    "handle",
    "invoke",
    "run",
    "execute",
    "process",
    # Medium signal
    "kickoff",
    "chat",
    "query",
    "complete",
    "generate",
    "respond",
    # Low signal
    "call",
    "forward",
    "predict",
)

# ============================================================================
# Pattern Registry
# ============================================================================

_ALL_PATTERNS: list[DetectionPattern] = (
    DECORATOR_PATTERNS +
    FRAMEWORK_PATTERNS +
    FUNCTION_PATTERNS +
    ASYNC_FUNCTION_PATTERNS +
    CLASS_PATTERNS
)

# Sort by priority (highest first)
_ALL_PATTERNS.sort(key=lambda p: -p.priority)

def get_all_patterns() -> list[DetectionPattern]:
    """Get all registered patterns, sorted by priority."""
    return list(_ALL_PATTERNS)

def get_patterns_by_type(pattern_type: PatternType) -> list[DetectionPattern]:
    """Get patterns of a specific type."""
    return [p for p in _ALL_PATTERNS if p.pattern_type == pattern_type]

def register_pattern(pattern: DetectionPattern) -> None:
    """Register a custom detection pattern."""
    _ALL_PATTERNS.append(pattern)
    _ALL_PATTERNS.sort(key=lambda p: -p.priority)

def get_pattern_by_name(name: str) -> DetectionPattern | None:
    """Get a pattern by name."""
    for p in _ALL_PATTERNS:
        if p.name == name:
            return p
    return None
