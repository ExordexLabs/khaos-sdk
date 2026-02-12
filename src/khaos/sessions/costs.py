"""Cost calculation for sessions.

Provides per-model pricing and session cost aggregation.
Extends the base costs module with session-level calculations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from khaos.llm.costs import DEFAULT_PRICING, estimate_cost, PricingNotFound
from khaos.sessions.models import LLMCall, Session, Turn


# Extended pricing with more models
EXTENDED_PRICING: dict[str, dict[str, tuple[float, float]]] = {
    **DEFAULT_PRICING,
    "openai": {
        **DEFAULT_PRICING.get("openai", {}),
        # GPT-4 variants
        "gpt-4": (0.00003, 0.00006),
        "gpt-4-32k": (0.00006, 0.00012),
        "gpt-4-turbo": (0.00001, 0.00003),
        "gpt-4-turbo-preview": (0.00001, 0.00003),
        # GPT-4o variants
        "gpt-4o": (0.0000025, 0.00001),
        "gpt-4o-mini": (0.00000015, 0.0000006),
        # GPT-3.5 variants
        "gpt-3.5-turbo": (0.0000005, 0.0000015),
        "gpt-3.5-turbo-16k": (0.000003, 0.000004),
        # Embeddings
        "text-embedding-3-small": (0.00000002, 0.0),
        "text-embedding-3-large": (0.00000013, 0.0),
        "text-embedding-ada-002": (0.0000001, 0.0),
    },
    "anthropic": {
        **DEFAULT_PRICING.get("anthropic", {}),
        # Claude 3.5
        "claude-3-5-sonnet-20241022": (0.000003, 0.000015),
        "claude-3-5-sonnet-latest": (0.000003, 0.000015),
        "claude-3-5-haiku-20241022": (0.0000008, 0.000004),
        # Claude 3
        "claude-3-opus-20240229": (0.000015, 0.000075),
        "claude-3-sonnet-20240229": (0.000003, 0.000015),
        "claude-3-haiku-20240307": (0.00000025, 0.00000125),
        # Aliases
        "claude-3-opus": (0.000015, 0.000075),
        "claude-3-sonnet": (0.000003, 0.000015),
        "claude-3-haiku": (0.00000025, 0.00000125),
    },
    "google": {
        **DEFAULT_PRICING.get("google", {}),
        "gemini-1.5-pro": (0.00000125, 0.000005),
        "gemini-1.5-flash": (0.000000075, 0.0000003),
        "gemini-1.0-pro": (0.0000005, 0.0000015),
    },
    "mistral": {
        "mistral-large": (0.000004, 0.000012),
        "mistral-medium": (0.0000027, 0.0000081),
        "mistral-small": (0.000001, 0.000003),
        "mistral-tiny": (0.00000025, 0.00000025),
    },
    "cohere": {
        "command-r-plus": (0.000003, 0.000015),
        "command-r": (0.0000005, 0.0000015),
        "command": (0.000001, 0.000002),
    },
}


@dataclass
class ModelCost:
    """Cost breakdown for a specific model."""

    model: str
    provider: str
    prompt_tokens: int
    completion_tokens: int
    prompt_cost_usd: float
    completion_cost_usd: float
    call_count: int

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def total_cost_usd(self) -> float:
        return self.prompt_cost_usd + self.completion_cost_usd


@dataclass
class SessionCost:
    """Complete cost breakdown for a session."""

    total_cost_usd: float
    prompt_cost_usd: float
    completion_cost_usd: float
    total_tokens: int
    prompt_tokens: int
    completion_tokens: int
    by_model: list[ModelCost]
    by_turn: list[float]
    missing_pricing: list[str]  # Models without pricing info

    def summary(self) -> str:
        """Human-readable cost summary."""
        lines = [
            f"Total Cost: ${self.total_cost_usd:.6f}",
            f"  Prompt: ${self.prompt_cost_usd:.6f} ({self.prompt_tokens:,} tokens)",
            f"  Completion: ${self.completion_cost_usd:.6f} ({self.completion_tokens:,} tokens)",
            f"Total Tokens: {self.total_tokens:,}",
        ]

        if self.by_model:
            lines.append("\nBy Model:")
            for mc in sorted(self.by_model, key=lambda x: x.total_cost_usd, reverse=True):
                lines.append(
                    f"  {mc.model}: ${mc.total_cost_usd:.6f} "
                    f"({mc.total_tokens:,} tokens, {mc.call_count} calls)"
                )

        if self.missing_pricing:
            lines.append(f"\nNo pricing for: {', '.join(self.missing_pricing)}")

        return "\n".join(lines)


def get_model_pricing(
    model: str,
    provider: str,
) -> tuple[float, float] | None:
    """Get pricing for a model.

    Args:
        model: Model name
        provider: Provider name

    Returns:
        Tuple of (prompt_price_per_token, completion_price_per_token)
        or None if not found
    """
    provider_key = provider.strip().lower()
    model_key = model.strip().lower()

    if provider_key in EXTENDED_PRICING:
        if model_key in EXTENDED_PRICING[provider_key]:
            return EXTENDED_PRICING[provider_key][model_key]

        # Try partial match (e.g., "gpt-4o-2024-05-13" matches "gpt-4o")
        for known_model, pricing in EXTENDED_PRICING[provider_key].items():
            if model_key.startswith(known_model) or known_model.startswith(model_key):
                return pricing

    return None


def calculate_call_cost(call: LLMCall) -> tuple[float, float]:
    """Calculate cost for a single LLM call.

    Returns:
        Tuple of (prompt_cost_usd, completion_cost_usd)
    """
    pricing = get_model_pricing(call.model, call.provider)
    if pricing:
        prompt_price, completion_price = pricing
        prompt_cost = call.prompt_tokens * prompt_price
        completion_cost = call.completion_tokens * completion_price
        return prompt_cost, completion_cost

    # Fall back to stored cost if available
    if call.cost_prompt_usd or call.cost_completion_usd:
        return call.cost_prompt_usd, call.cost_completion_usd

    return 0.0, 0.0


def calculate_turn_cost(turn: Turn) -> float:
    """Calculate total cost for a turn."""
    total = 0.0
    for call in turn.llm_calls:
        prompt_cost, completion_cost = calculate_call_cost(call)
        total += prompt_cost + completion_cost
    return total


def calculate_session_cost(session: Session) -> SessionCost:
    """Calculate complete cost breakdown for a session.

    Args:
        session: The session to analyze

    Returns:
        SessionCost with detailed breakdown
    """
    total_prompt_cost = 0.0
    total_completion_cost = 0.0
    total_prompt_tokens = 0
    total_completion_tokens = 0

    # Track by model
    model_costs: dict[str, ModelCost] = {}
    missing_pricing: set[str] = set()

    for call in session.llm_calls:
        prompt_cost, completion_cost = calculate_call_cost(call)

        if prompt_cost == 0.0 and completion_cost == 0.0:
            if call.prompt_tokens > 0 or call.completion_tokens > 0:
                missing_pricing.add(f"{call.provider}/{call.model}")

        total_prompt_cost += prompt_cost
        total_completion_cost += completion_cost
        total_prompt_tokens += call.prompt_tokens
        total_completion_tokens += call.completion_tokens

        # Track by model
        model_key = f"{call.provider}/{call.model}"
        if model_key not in model_costs:
            model_costs[model_key] = ModelCost(
                model=call.model,
                provider=call.provider,
                prompt_tokens=0,
                completion_tokens=0,
                prompt_cost_usd=0.0,
                completion_cost_usd=0.0,
                call_count=0,
            )

        mc = model_costs[model_key]
        model_costs[model_key] = ModelCost(
            model=mc.model,
            provider=mc.provider,
            prompt_tokens=mc.prompt_tokens + call.prompt_tokens,
            completion_tokens=mc.completion_tokens + call.completion_tokens,
            prompt_cost_usd=mc.prompt_cost_usd + prompt_cost,
            completion_cost_usd=mc.completion_cost_usd + completion_cost,
            call_count=mc.call_count + 1,
        )

    # Calculate per-turn costs
    turn_costs = [calculate_turn_cost(turn) for turn in session.turns]

    return SessionCost(
        total_cost_usd=total_prompt_cost + total_completion_cost,
        prompt_cost_usd=total_prompt_cost,
        completion_cost_usd=total_completion_cost,
        total_tokens=total_prompt_tokens + total_completion_tokens,
        prompt_tokens=total_prompt_tokens,
        completion_tokens=total_completion_tokens,
        by_model=list(model_costs.values()),
        by_turn=turn_costs,
        missing_pricing=list(missing_pricing),
    )


def estimate_session_cost(
    prompt_tokens: int,
    completion_tokens: int,
    model: str,
    provider: str,
) -> float:
    """Quick estimate of session cost.

    Args:
        prompt_tokens: Total prompt tokens
        completion_tokens: Total completion tokens
        model: Model name
        provider: Provider name

    Returns:
        Estimated cost in USD
    """
    pricing = get_model_pricing(model, provider)
    if pricing:
        prompt_price, completion_price = pricing
        return (prompt_tokens * prompt_price) + (completion_tokens * completion_price)
    return 0.0
