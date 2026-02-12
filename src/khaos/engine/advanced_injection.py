"""Advanced fault injection with positional, conditional, and mutation capabilities.

Provides:
- Positional fault injection (by turn or LLM call index)
- Conditional injection based on message content
- Response mutation before returning to agent
- Tool failure simulation by tool name
- Latency profiles for realistic network simulation

Example YAML usage:

    faults:
      - type: timeout
        inject_at:
          turn: 3           # Inject on 3rd turn

      - type: network_error
        inject_at:
          llm_call: 2       # Inject on 2nd LLM call

      - type: latency
        condition: "messages[-1].content contains 'weather'"

      - type: tool_failure
        tool: "get_weather"
        error: "Service unavailable"

      - type: response_mutation
        mutation: "truncate"
        truncate_percent: 50

      - type: latency
        profile: "cellular_3g"  # Use predefined latency profile
"""

from __future__ import annotations

import asyncio
import random
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from collections.abc import Callable

from khaos.engine.scheduler import SeededScheduler

# ---------------------------------------------------------------------------
# Latency Profiles
# ---------------------------------------------------------------------------

class LatencyProfile(Enum):
    """Predefined latency profiles for realistic network simulation."""

    # Stable connections
    FIBER = "fiber"              # 5-15ms, very consistent
    CABLE = "cable"              # 10-30ms, some variation
    DSL = "dsl"                  # 20-50ms, moderate variation

    # Mobile networks
    CELLULAR_5G = "cellular_5g"  # 10-30ms, occasional spikes
    CELLULAR_4G = "cellular_4g"  # 30-80ms, variable
    CELLULAR_3G = "cellular_3g"  # 100-500ms, highly variable

    # Degraded conditions
    CONGESTED = "congested"      # 100-300ms, high jitter
    SATELLITE = "satellite"      # 500-700ms, consistent but high
    OFFLINE = "offline"          # Infinite (timeout)

    # Testing profiles
    RANDOM = "random"            # Random within reasonable bounds
    STRESS = "stress"            # Extreme variation for stress testing

@dataclass
class LatencyConfig:
    """Configuration for a latency profile."""

    base_ms: float              # Base latency in milliseconds
    jitter_ms: float            # Random jitter (± this value)
    spike_probability: float    # Probability of latency spike (0-1)
    spike_multiplier: float     # Multiplier when spike occurs
    packet_loss: float          # Probability of timeout (0-1)

    def sample(self, rng: random.Random | None = None) -> float:
        """Sample a latency value from this profile.

        Returns:
            Latency in milliseconds, or float('inf') for timeout
        """
        r = rng or random.Random()

        # Check for packet loss (timeout)
        if r.random() < self.packet_loss:
            return float('inf')

        # Base latency with jitter
        latency = self.base_ms + r.uniform(-self.jitter_ms, self.jitter_ms)

        # Apply spike if triggered
        if r.random() < self.spike_probability:
            latency *= self.spike_multiplier

        return max(0, latency)

# Predefined profile configurations
LATENCY_PROFILES: dict[str, LatencyConfig] = {
    "fiber": LatencyConfig(
        base_ms=10,
        jitter_ms=5,
        spike_probability=0.01,
        spike_multiplier=2.0,
        packet_loss=0.0001,
    ),
    "cable": LatencyConfig(
        base_ms=20,
        jitter_ms=10,
        spike_probability=0.02,
        spike_multiplier=2.5,
        packet_loss=0.001,
    ),
    "dsl": LatencyConfig(
        base_ms=35,
        jitter_ms=15,
        spike_probability=0.03,
        spike_multiplier=3.0,
        packet_loss=0.002,
    ),
    "cellular_5g": LatencyConfig(
        base_ms=20,
        jitter_ms=10,
        spike_probability=0.05,
        spike_multiplier=4.0,
        packet_loss=0.005,
    ),
    "cellular_4g": LatencyConfig(
        base_ms=55,
        jitter_ms=25,
        spike_probability=0.08,
        spike_multiplier=3.0,
        packet_loss=0.01,
    ),
    "cellular_3g": LatencyConfig(
        base_ms=200,
        jitter_ms=100,
        spike_probability=0.15,
        spike_multiplier=2.5,
        packet_loss=0.03,
    ),
    "congested": LatencyConfig(
        base_ms=200,
        jitter_ms=100,
        spike_probability=0.2,
        spike_multiplier=3.0,
        packet_loss=0.05,
    ),
    "satellite": LatencyConfig(
        base_ms=600,
        jitter_ms=50,
        spike_probability=0.05,
        spike_multiplier=1.5,
        packet_loss=0.02,
    ),
    "offline": LatencyConfig(
        base_ms=0,
        jitter_ms=0,
        spike_probability=0,
        spike_multiplier=1,
        packet_loss=1.0,  # Always timeout
    ),
    "random": LatencyConfig(
        base_ms=100,
        jitter_ms=80,
        spike_probability=0.1,
        spike_multiplier=5.0,
        packet_loss=0.01,
    ),
    "stress": LatencyConfig(
        base_ms=500,
        jitter_ms=400,
        spike_probability=0.3,
        spike_multiplier=4.0,
        packet_loss=0.1,
    ),
}

def get_latency_profile(name: str) -> LatencyConfig | None:
    """Get a latency profile configuration by name."""
    return LATENCY_PROFILES.get(name.lower())

def sample_latency(profile: str, rng: random.Random | None = None) -> float:
    """Sample a latency value from a named profile.

    Args:
        profile: Profile name (e.g., "cellular_4g")
        rng: Optional random number generator for reproducibility

    Returns:
        Latency in milliseconds, or float('inf') for timeout
    """
    config = get_latency_profile(profile)
    if config is None:
        return 0.0
    return config.sample(rng)

# ---------------------------------------------------------------------------
# Positional Injection
# ---------------------------------------------------------------------------

@dataclass
class InjectionPosition:
    """Specifies when to inject a fault based on position."""

    turn: int | None = None           # Inject at specific turn number (1-indexed)
    llm_call: int | None = None       # Inject at specific LLM call (1-indexed)
    first: bool = False               # Inject on first occurrence
    last: bool = False                # Inject on last occurrence (requires knowing total)
    every_n: int | None = None        # Inject every N occurrences
    after_turn: int | None = None     # Inject after turn N
    before_turn: int | None = None    # Inject before turn N

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InjectionPosition":
        """Parse position from scenario YAML."""
        return cls(
            turn=data.get("turn"),
            llm_call=data.get("llm_call"),
            first=data.get("first", False),
            last=data.get("last", False),
            every_n=data.get("every_n"),
            after_turn=data.get("after_turn"),
            before_turn=data.get("before_turn"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        d = {}
        if self.turn is not None:
            d["turn"] = self.turn
        if self.llm_call is not None:
            d["llm_call"] = self.llm_call
        if self.first:
            d["first"] = True
        if self.last:
            d["last"] = True
        if self.every_n is not None:
            d["every_n"] = self.every_n
        if self.after_turn is not None:
            d["after_turn"] = self.after_turn
        if self.before_turn is not None:
            d["before_turn"] = self.before_turn
        return d

@dataclass
class InjectionContext:
    """Current context for evaluating injection conditions."""

    turn_index: int = 0               # Current turn (0-indexed)
    llm_call_index: int = 0           # Current LLM call (0-indexed)
    total_turns: int | None = None    # Total turns if known
    total_llm_calls: int | None = None  # Total LLM calls if known
    messages: list[dict] = field(default_factory=list)  # Message history
    tool_calls: list[dict] = field(default_factory=list)  # Tool call history
    metadata: dict[str, Any] = field(default_factory=dict)  # Additional context

def should_inject_at_position(
    position: InjectionPosition,
    context: InjectionContext,
) -> bool:
    """Determine if a fault should be injected at the current position.

    Args:
        position: The injection position specification
        context: Current execution context

    Returns:
        True if fault should be injected
    """
    # Check turn-based conditions (1-indexed in position, 0-indexed in context)
    if position.turn is not None:
        if context.turn_index + 1 != position.turn:
            return False

    # Check LLM call-based conditions
    if position.llm_call is not None:
        if context.llm_call_index + 1 != position.llm_call:
            return False

    # Check first occurrence (both must be 0)
    if position.first:
        if context.turn_index != 0 or context.llm_call_index != 0:
            return False

    # Check last occurrence (requires knowing total)
    if position.last:
        if context.total_turns is not None:
            if context.turn_index + 1 != context.total_turns:
                return False
        if context.total_llm_calls is not None:
            if context.llm_call_index + 1 != context.total_llm_calls:
                return False

    # Check every_n
    if position.every_n is not None:
        if (context.llm_call_index + 1) % position.every_n != 0:
            return False

    # Check after_turn
    if position.after_turn is not None:
        if context.turn_index + 1 <= position.after_turn:
            return False

    # Check before_turn
    if position.before_turn is not None:
        if context.turn_index + 1 >= position.before_turn:
            return False

    return True

# ---------------------------------------------------------------------------
# Conditional Injection
# ---------------------------------------------------------------------------

@dataclass
class InjectionCondition:
    """Specifies when to inject based on message content or context."""

    expression: str = ""              # Condition expression
    message_contains: str | list[str] | None = None
    message_regex: str | None = None
    tool_called: str | list[str] | None = None
    model_is: str | list[str] | None = None
    token_count_above: int | None = None
    custom: Callable[[InjectionContext], bool] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InjectionCondition":
        """Parse condition from scenario YAML."""
        return cls(
            expression=data.get("expression", ""),
            message_contains=data.get("message_contains"),
            message_regex=data.get("message_regex"),
            tool_called=data.get("tool_called"),
            model_is=data.get("model_is"),
            token_count_above=data.get("token_count_above"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        d = {}
        if self.expression:
            d["expression"] = self.expression
        if self.message_contains:
            d["message_contains"] = self.message_contains
        if self.message_regex:
            d["message_regex"] = self.message_regex
        if self.tool_called:
            d["tool_called"] = self.tool_called
        if self.model_is:
            d["model_is"] = self.model_is
        if self.token_count_above is not None:
            d["token_count_above"] = self.token_count_above
        return d

def evaluate_condition(
    condition: InjectionCondition,
    context: InjectionContext,
) -> bool:
    """Evaluate if an injection condition is met.

    Args:
        condition: The condition specification
        context: Current execution context

    Returns:
        True if condition is met
    """
    # Custom function check
    if condition.custom is not None:
        return condition.custom(context)

    # Expression-based check
    if condition.expression:
        return _evaluate_expression(condition.expression, context)

    # Message contains check
    if condition.message_contains:
        patterns = condition.message_contains
        if isinstance(patterns, str):
            patterns = [patterns]

        for msg in context.messages:
            content = msg.get("content", "")
            if any(p.lower() in content.lower() for p in patterns):
                return True
        return False

    # Regex check
    if condition.message_regex:
        pattern = re.compile(condition.message_regex, re.IGNORECASE)
        for msg in context.messages:
            content = msg.get("content", "")
            if pattern.search(content):
                return True
        return False

    # Tool called check
    if condition.tool_called:
        tools = condition.tool_called
        if isinstance(tools, str):
            tools = [tools]

        called_tools = {tc.get("name", "") for tc in context.tool_calls}
        if any(t in called_tools for t in tools):
            return True
        return False

    # Model check
    if condition.model_is:
        models = condition.model_is
        if isinstance(models, str):
            models = [models]

        current_model = context.metadata.get("model", "")
        if current_model in models:
            return True
        return False

    # Token count check
    if condition.token_count_above is not None:
        total_tokens = context.metadata.get("total_tokens", 0)
        if total_tokens > condition.token_count_above:
            return True
        return False

    return True  # No condition = always true

def _evaluate_expression(expression: str, context: InjectionContext) -> bool:
    """Evaluate a simple expression against context.

    Supported expressions:
    - messages[-1].content contains 'keyword'
    - messages.length > 5
    - turn > 3
    - llm_call == 2
    - tool_called('get_weather')
    """
    expr = expression.strip()

    # messages[-1].content contains 'keyword'
    match = re.match(r"messages\[-1\]\.content\s+contains\s+['\"](.+)['\"]", expr)
    if match:
        keyword = match.group(1).lower()
        if context.messages:
            last_msg = context.messages[-1].get("content", "").lower()
            return keyword in last_msg
        return False

    # messages.length > N
    match = re.match(r"messages\.length\s*(>|<|>=|<=|==)\s*(\d+)", expr)
    if match:
        op, num = match.groups()
        length = len(context.messages)
        num = int(num)
        if op == ">":
            return length > num
        elif op == "<":
            return length < num
        elif op == ">=":
            return length >= num
        elif op == "<=":
            return length <= num
        elif op == "==":
            return length == num

    # turn > N
    match = re.match(r"turn\s*(>|<|>=|<=|==)\s*(\d+)", expr)
    if match:
        op, num = match.groups()
        turn = context.turn_index + 1
        num = int(num)
        if op == ">":
            return turn > num
        elif op == "<":
            return turn < num
        elif op == ">=":
            return turn >= num
        elif op == "<=":
            return turn <= num
        elif op == "==":
            return turn == num

    # llm_call > N
    match = re.match(r"llm_call\s*(>|<|>=|<=|==)\s*(\d+)", expr)
    if match:
        op, num = match.groups()
        call = context.llm_call_index + 1
        num = int(num)
        if op == ">":
            return call > num
        elif op == "<":
            return call < num
        elif op == ">=":
            return call >= num
        elif op == "<=":
            return call <= num
        elif op == "==":
            return call == num

    # tool_called('tool_name')
    match = re.match(r"tool_called\(['\"](.+)['\"]\)", expr)
    if match:
        tool_name = match.group(1)
        called_tools = {tc.get("name", "") for tc in context.tool_calls}
        return tool_name in called_tools

    # Default to false for unrecognized expressions
    return False

# ---------------------------------------------------------------------------
# Response Mutation
# ---------------------------------------------------------------------------

class MutationType(Enum):
    """Types of response mutations."""

    TRUNCATE = "truncate"           # Cut off response at percentage
    CORRUPT = "corrupt"             # Add random characters
    DELAY_WORDS = "delay_words"     # Add pauses between words (streaming)
    EMPTY = "empty"                 # Replace with empty response
    REPLACE = "replace"             # Replace with custom content
    PREPEND = "prepend"             # Add content before response
    APPEND = "append"               # Add content after response
    FILTER = "filter"               # Remove matching patterns
    HALLUCINATE = "hallucinate"     # Add plausible-sounding false info

@dataclass
class ResponseMutation:
    """Configuration for mutating LLM responses."""

    mutation_type: MutationType
    truncate_percent: float = 50.0        # For TRUNCATE
    corruption_rate: float = 0.1          # For CORRUPT
    replacement_content: str = ""         # For REPLACE/PREPEND/APPEND
    filter_pattern: str = ""              # For FILTER
    hallucination_topic: str = ""         # For HALLUCINATE

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResponseMutation":
        """Parse mutation from scenario YAML."""
        mutation_str = data.get("mutation", "truncate")
        try:
            mutation_type = MutationType(mutation_str)
        except ValueError:
            mutation_type = MutationType.TRUNCATE

        return cls(
            mutation_type=mutation_type,
            truncate_percent=data.get("truncate_percent", 50.0),
            corruption_rate=data.get("corruption_rate", 0.1),
            replacement_content=data.get("replacement_content", ""),
            filter_pattern=data.get("filter_pattern", ""),
            hallucination_topic=data.get("hallucination_topic", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "mutation": self.mutation_type.value,
            "truncate_percent": self.truncate_percent,
            "corruption_rate": self.corruption_rate,
            "replacement_content": self.replacement_content,
            "filter_pattern": self.filter_pattern,
            "hallucination_topic": self.hallucination_topic,
        }

def apply_mutation(
    content: str,
    mutation: ResponseMutation,
    rng: random.Random | None = None,
) -> str:
    """Apply a mutation to response content.

    Args:
        content: Original response content
        mutation: Mutation configuration
        rng: Optional random number generator

    Returns:
        Mutated content
    """
    r = rng or random.Random()

    if mutation.mutation_type == MutationType.TRUNCATE:
        cut_at = int(len(content) * mutation.truncate_percent / 100)
        return content[:cut_at]

    elif mutation.mutation_type == MutationType.CORRUPT:
        chars = list(content)
        for i in range(len(chars)):
            if r.random() < mutation.corruption_rate:
                chars[i] = r.choice("!@#$%^&*()_+{}|:<>?~`-=[]\\;',./")
        return "".join(chars)

    elif mutation.mutation_type == MutationType.EMPTY:
        return ""

    elif mutation.mutation_type == MutationType.REPLACE:
        return mutation.replacement_content

    elif mutation.mutation_type == MutationType.PREPEND:
        return mutation.replacement_content + content

    elif mutation.mutation_type == MutationType.APPEND:
        return content + mutation.replacement_content

    elif mutation.mutation_type == MutationType.FILTER:
        if mutation.filter_pattern:
            return re.sub(mutation.filter_pattern, "", content)
        return content

    elif mutation.mutation_type == MutationType.HALLUCINATE:
        # Add a plausible-sounding but false statement
        hallucination = _generate_hallucination(mutation.hallucination_topic, r)
        return content + "\n\n" + hallucination

    elif mutation.mutation_type == MutationType.DELAY_WORDS:
        # For streaming - just return content, delay is handled separately
        return content

    return content

def _generate_hallucination(topic: str, rng: random.Random) -> str:
    """Generate a plausible-sounding hallucination."""
    templates = [
        f"Additionally, according to recent studies, {topic} has been shown to have unexpected effects.",
        f"It's worth noting that {topic} was recently updated in ways that may affect this.",
        f"Furthermore, experts suggest that {topic} considerations should be taken into account.",
        f"Interestingly, {topic} has changed significantly in recent developments.",
    ]
    return rng.choice(templates) if topic else "Note: additional context may be required."

# ---------------------------------------------------------------------------
# Tool Failure Simulation
# ---------------------------------------------------------------------------

@dataclass
class ToolFailure:
    """Configuration for simulating tool failures."""

    tool_name: str                        # Tool to fail
    error_message: str = "Tool execution failed"
    error_type: str = "ToolError"         # Exception type to simulate
    probability: float = 1.0              # Probability of failure (0-1)
    delay_before_failure_ms: float = 0    # Delay before failing
    partial_result: dict | None = None    # Return partial result before failing

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolFailure":
        """Parse tool failure from scenario YAML."""
        return cls(
            tool_name=data.get("tool", data.get("tool_name", "")),
            error_message=data.get("error", data.get("error_message", "Tool execution failed")),
            error_type=data.get("error_type", "ToolError"),
            probability=data.get("probability", 1.0),
            delay_before_failure_ms=data.get("delay_ms", 0),
            partial_result=data.get("partial_result"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "tool_name": self.tool_name,
            "error_message": self.error_message,
            "error_type": self.error_type,
            "probability": self.probability,
            "delay_before_failure_ms": self.delay_before_failure_ms,
            "partial_result": self.partial_result,
        }

async def simulate_tool_failure(
    failure: ToolFailure,
    scheduler: SeededScheduler | None = None,
    rng: random.Random | None = None,
) -> dict[str, Any]:
    """Simulate a tool failure.

    Args:
        failure: Failure configuration
        scheduler: Optional scheduler for timing
        rng: Optional random number generator

    Returns:
        Dict describing the failure outcome
    """
    r = rng or random.Random()

    # Check if failure should occur
    if r.random() > failure.probability:
        return {"injected": False, "reason": "probability_skip"}

    # Apply delay
    if failure.delay_before_failure_ms > 0:
        delay_s = failure.delay_before_failure_ms / 1000
        if scheduler:
            await scheduler.sleep(delay_s)
        else:
            await asyncio.sleep(delay_s)

    return {
        "injected": True,
        "tool_name": failure.tool_name,
        "error_type": failure.error_type,
        "error_message": failure.error_message,
        "partial_result": failure.partial_result,
        "outcome": "tool_failure",
    }

def should_fail_tool(
    tool_name: str,
    failures: list[ToolFailure],
) -> ToolFailure | None:
    """Check if a tool should fail based on configured failures.

    Args:
        tool_name: Name of the tool being called
        failures: List of configured tool failures

    Returns:
        ToolFailure config if tool should fail, None otherwise
    """
    for failure in failures:
        if failure.tool_name == tool_name or failure.tool_name == "*":
            return failure
    return None

# ---------------------------------------------------------------------------
# Advanced Fault Configuration
# ---------------------------------------------------------------------------

@dataclass
class AdvancedFaultConfig:
    """Complete configuration for an advanced fault."""

    fault_type: str                       # Base fault type
    position: InjectionPosition | None = None
    condition: InjectionCondition | None = None
    mutation: ResponseMutation | None = None
    tool_failure: ToolFailure | None = None
    latency_profile: str | None = None
    probability: float = 1.0
    config: dict[str, Any] = field(default_factory=dict)  # Pass-through config

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AdvancedFaultConfig":
        """Parse from scenario YAML."""
        position = None
        if "inject_at" in data:
            position = InjectionPosition.from_dict(data["inject_at"])

        condition = None
        if "condition" in data:
            if isinstance(data["condition"], str):
                condition = InjectionCondition(expression=data["condition"])
            else:
                condition = InjectionCondition.from_dict(data["condition"])

        mutation = None
        if "mutation" in data:
            if isinstance(data["mutation"], str):
                mutation = ResponseMutation.from_dict({"mutation": data["mutation"]})
            else:
                mutation = ResponseMutation.from_dict(data["mutation"])

        tool_failure = None
        if data.get("type") == "tool_failure" or "tool" in data:
            tool_failure = ToolFailure.from_dict(data)

        return cls(
            fault_type=data.get("type", "unknown"),
            position=position,
            condition=condition,
            mutation=mutation,
            tool_failure=tool_failure,
            latency_profile=data.get("profile", data.get("latency_profile")),
            probability=data.get("probability", 1.0),
            config=data,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        d = {
            "type": self.fault_type,
            "probability": self.probability,
            **self.config,
        }
        if self.position:
            d["inject_at"] = self.position.to_dict()
        if self.condition:
            d["condition"] = self.condition.to_dict()
        if self.mutation:
            d["mutation"] = self.mutation.to_dict()
        if self.tool_failure:
            d["tool_failure"] = self.tool_failure.to_dict()
        if self.latency_profile:
            d["profile"] = self.latency_profile
        return d

def should_inject_fault(
    fault: AdvancedFaultConfig,
    context: InjectionContext,
    rng: random.Random | None = None,
) -> bool:
    """Determine if an advanced fault should be injected.

    Args:
        fault: Fault configuration
        context: Current execution context
        rng: Optional random number generator

    Returns:
        True if fault should be injected
    """
    r = rng or random.Random()

    # Check probability
    if r.random() > fault.probability:
        return False

    # Check position
    if fault.position:
        if not should_inject_at_position(fault.position, context):
            return False

    # Check condition
    if fault.condition:
        if not evaluate_condition(fault.condition, context):
            return False

    return True

# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------

def parse_advanced_faults(
    faults_data: list[dict[str, Any]],
) -> list[AdvancedFaultConfig]:
    """Parse a list of fault configurations from scenario YAML.

    Args:
        faults_data: List of fault dicts from YAML

    Returns:
        List of parsed AdvancedFaultConfig objects
    """
    return [AdvancedFaultConfig.from_dict(f) for f in faults_data]

def get_applicable_faults(
    faults: list[AdvancedFaultConfig],
    context: InjectionContext,
    rng: random.Random | None = None,
) -> list[AdvancedFaultConfig]:
    """Filter faults to those that should be applied in the current context.

    Args:
        faults: All configured faults
        context: Current execution context
        rng: Optional random number generator

    Returns:
        List of faults that should be applied
    """
    return [f for f in faults if should_inject_fault(f, context, rng)]
