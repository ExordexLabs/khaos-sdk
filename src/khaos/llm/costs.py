"""Pricing tables and estimators for common LLM providers.

Pricing is stored as (input_price_per_token, output_price_per_token) in USD.
Updated January 2026 with latest model pricing.

Sources:
- OpenAI: https://openai.com/api/pricing/
- Anthropic: https://www.anthropic.com/pricing
- Google: https://ai.google.dev/gemini-api/docs/pricing
- Mistral: https://mistral.ai/pricing
- Cohere: https://cohere.com/pricing
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from collections.abc import Mapping

# Cache discount rates by provider
# These reflect the actual billing discounts for cached/repeated prompts
CACHE_DISCOUNTS = {
    "openai": {
        "cached_read": 0.50,  # Cached tokens are 50% of regular input price
    },
    "anthropic": {
        "cache_read": 0.10,   # Cache read is 90% discount (10% of regular price)
        "cache_write": 1.25,  # Cache creation is 25% premium
    },
    "google": {
        "cached_read": 0.25,  # ~75% discount for cached content
    },
}

def _per_million(input_price: float, output_price: float) -> tuple[float, float]:
    """Convert per-million-token pricing to per-token pricing."""
    return (input_price / 1_000_000, output_price / 1_000_000)

DEFAULT_PRICING: dict[str, dict[str, tuple[float, float]]] = {
    # OpenAI Models (January 2026)
    # https://openai.com/api/pricing/
    "openai": {
        # GPT-5 series (latest)
        "gpt-5": _per_million(1.25, 10.00),
        "gpt-5.1": _per_million(1.25, 10.00),
        "gpt-5.2": _per_million(1.75, 14.00),
        "gpt-5-mini": _per_million(0.25, 2.00),
        "gpt-5-nano": _per_million(0.05, 0.40),
        # GPT-4.1 series
        "gpt-4.1": _per_million(2.00, 8.00),
        "gpt-4.1-mini": _per_million(0.40, 1.60),
        "gpt-4.1-nano": _per_million(0.10, 0.40),
        # GPT-4o series
        "gpt-4o": _per_million(2.50, 10.00),
        "gpt-4o-mini": _per_million(0.15, 0.60),
        "gpt-4o-audio-preview": _per_million(2.50, 10.00),
        # GPT-4 Turbo / GPT-4 legacy
        "gpt-4-turbo": _per_million(10.00, 30.00),
        "gpt-4-turbo-preview": _per_million(10.00, 30.00),
        "gpt-4": _per_million(30.00, 60.00),
        # GPT-3.5 legacy
        "gpt-3.5-turbo": _per_million(0.50, 1.50),
        "gpt-3.5-turbo-instruct": _per_million(1.50, 2.00),
        # o1/o3 reasoning models
        "o1": _per_million(15.00, 60.00),
        "o1-mini": _per_million(3.00, 12.00),
        "o1-preview": _per_million(15.00, 60.00),
        "o3-mini": _per_million(1.10, 4.40),
    },

    # Anthropic Claude Models (January 2026)
    # https://www.anthropic.com/pricing
    "anthropic": {
        # Claude 4.5 series (latest)
        "claude-opus-4-5-20250514": _per_million(5.00, 25.00),
        "claude-sonnet-4-5-20250514": _per_million(3.00, 15.00),
        "claude-haiku-4-5-20250514": _per_million(1.00, 5.00),
        # Aliases for latest
        "claude-4.5-opus": _per_million(5.00, 25.00),
        "claude-4.5-sonnet": _per_million(3.00, 15.00),
        "claude-4.5-haiku": _per_million(1.00, 5.00),
        # Claude 4 series
        "claude-opus-4-20250514": _per_million(15.00, 75.00),
        "claude-sonnet-4-20250514": _per_million(3.00, 15.00),
        "claude-4-opus": _per_million(15.00, 75.00),
        "claude-4-sonnet": _per_million(3.00, 15.00),
        # Claude 3.5 series
        "claude-3-5-sonnet-20241022": _per_million(3.00, 15.00),
        "claude-3-5-haiku-20241022": _per_million(1.00, 5.00),
        "claude-3.5-sonnet": _per_million(3.00, 15.00),
        "claude-3.5-haiku": _per_million(1.00, 5.00),
        # Claude 3 series (legacy)
        "claude-3-opus": _per_million(15.00, 75.00),
        "claude-3-sonnet": _per_million(3.00, 15.00),
        "claude-3-haiku": _per_million(0.25, 1.25),
    },

    # Google Gemini Models (January 2026)
    # https://ai.google.dev/gemini-api/docs/pricing
    "google": {
        # Gemini 3 series (latest)
        "gemini-3-pro": _per_million(2.00, 12.00),
        "gemini-3-flash": _per_million(0.50, 3.00),
        # Gemini 2.5 series
        "gemini-2.5-pro": _per_million(1.25, 5.00),
        "gemini-2.5-flash": _per_million(0.15, 0.60),
        "gemini-2.5-flash-lite": _per_million(0.075, 0.30),
        # Gemini 2.0 series
        "gemini-2.0-pro": _per_million(1.25, 5.00),
        "gemini-2.0-flash": _per_million(0.10, 0.40),
        "gemini-2.0-flash-lite": _per_million(0.075, 0.30),
        # Gemini 1.5 series (legacy)
        "gemini-1.5-pro": _per_million(1.25, 5.00),
        "gemini-1.5-flash": _per_million(0.075, 0.30),
        "gemini-1.5-flash-8b": _per_million(0.0375, 0.15),
        # Gemini 1.0 (legacy)
        "gemini-1.0-pro": _per_million(0.50, 1.50),
    },

    # Mistral AI Models (January 2026)
    # https://mistral.ai/pricing
    "mistral": {
        # Mistral Large
        "mistral-large-latest": _per_million(2.00, 6.00),
        "mistral-large-2411": _per_million(2.00, 6.00),
        "mistral-large": _per_million(2.00, 6.00),
        # Mistral Medium
        "mistral-medium-latest": _per_million(0.40, 2.00),
        "mistral-medium-3": _per_million(0.40, 2.00),
        "mistral-medium": _per_million(0.40, 2.00),
        # Mistral Small
        "mistral-small-latest": _per_million(0.10, 0.30),
        "mistral-small-3": _per_million(0.03, 0.11),
        "mistral-small": _per_million(0.10, 0.30),
        # Specialized models
        "mistral-nemo": _per_million(0.02, 0.06),
        "codestral-latest": _per_million(0.30, 0.90),
        "codestral": _per_million(0.30, 0.90),
        "devstral-2": _per_million(0.40, 2.00),
        "devstral-small-2": _per_million(0.10, 0.30),
        # Pixtral (vision)
        "pixtral-large-latest": _per_million(2.00, 6.00),
        "pixtral-12b": _per_million(0.15, 0.15),
        # Ministral
        "ministral-8b-latest": _per_million(0.10, 0.10),
        "ministral-3b-latest": _per_million(0.04, 0.04),
    },

    # Cohere Models (January 2026)
    # https://cohere.com/pricing
    "cohere": {
        # Command A (latest)
        "command-a": _per_million(2.50, 10.00),
        "command-a-03-2025": _per_million(2.50, 10.00),
        # Command R+ series
        "command-r-plus": _per_million(2.50, 10.00),
        "command-r-plus-08-2024": _per_million(2.50, 10.00),
        "command-r-plus-04-2024": _per_million(3.00, 15.00),
        # Command R series
        "command-r": _per_million(0.15, 0.60),
        "command-r-08-2024": _per_million(0.15, 0.60),
        "command-r-03-2024": _per_million(0.50, 1.50),
        # Command R7B (smallest/fastest)
        "command-r7b-12-2024": _per_million(0.0375, 0.15),
        # Legacy Command
        "command": _per_million(1.00, 2.00),
        "command-light": _per_million(0.30, 0.60),
    },
}

@dataclass(frozen=True)
class CostEstimate:
    prompt_cost_usd: float
    completion_cost_usd: float
    # Cache-aware breakdown
    uncached_prompt_tokens: int = 0
    cached_prompt_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total_cost_usd(self) -> float:
        return self.prompt_cost_usd + self.completion_cost_usd

class PricingNotFound(Exception):
    """Raised when we cannot find pricing info for a provider/model pair."""

PricingTable = Mapping[str, Mapping[str, tuple[float, float]]]

def _provider_key(provider: str) -> str:
    return (provider or "unknown").strip().lower()

def _model_key(model: str) -> str:
    """Normalize model key for lookup.

    Handles common variations like:
    - 'gpt-4o' vs 'gpt4o'
    - 'claude-3-opus-20240229' -> 'claude-3-opus'
    - Case insensitivity
    """
    key = (model or "unknown").strip().lower()
    # Remove date suffixes for some models (e.g., claude-3-opus-20240229 -> claude-3-opus)
    # But preserve version-specific suffixes like -08-2024 for Cohere
    return key

def _find_model_price(
    provider_prices: Mapping[str, tuple[float, float]],
    model_key: str,
) -> tuple[float, float] | None:
    """Find price for a model, trying exact match then prefix match."""
    # Exact match
    if model_key in provider_prices:
        return provider_prices[model_key]

    # Try prefix match for versioned models (e.g., gpt-4o-2024-08-06 -> gpt-4o)
    for known_model in sorted(provider_prices.keys(), key=len, reverse=True):
        if model_key.startswith(known_model):
            return provider_prices[known_model]

    return None

def estimate_cost(
    *,
    provider: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    cached_tokens: int = 0,
    cache_read_tokens: int = 0,
    cache_creation_tokens: int = 0,
    pricing_overrides: PricingTable | None = None,
) -> CostEstimate:
    """Estimate USD cost for a call given token counts.

    Pricing is specified in USD per-token. `pricing_overrides` matches the
    DEFAULT_PRICING structure (provider -> model -> (prompt, completion)).

    Cache-aware pricing:
    - cached_tokens: OpenAI-style cached prompt tokens (50% discount)
    - cache_read_tokens: Anthropic cache read tokens (90% discount)
    - cache_creation_tokens: Anthropic cache write tokens (25% premium)

    The total prompt_tokens should include all input tokens. The cached/cache_read
    tokens are subtracted from prompt_tokens to get the uncached portion.
    """

    tokens_in = max(0, int(prompt_tokens or 0))
    tokens_out = max(0, int(completion_tokens or 0))
    cached = max(0, int(cached_tokens or 0))
    cache_read = max(0, int(cache_read_tokens or 0))
    cache_write = max(0, int(cache_creation_tokens or 0))

    provider_key = _provider_key(provider)
    model_key = _model_key(model)

    # Check overrides first
    table = pricing_overrides or {}
    prompt_price = completion_price = None

    if provider_key in table:
        prices = _find_model_price(table[provider_key], model_key)
        if prices:
            prompt_price, completion_price = prices

    # Fall back to defaults
    if prompt_price is None and provider_key in DEFAULT_PRICING:
        prices = _find_model_price(DEFAULT_PRICING[provider_key], model_key)
        if prices:
            prompt_price, completion_price = prices

    if prompt_price is None or completion_price is None:
        raise PricingNotFound(f"No pricing entry for provider={provider}, model={model}")

    # Get cache discount rates for this provider
    discounts = CACHE_DISCOUNTS.get(provider_key, {})

    # Calculate prompt cost with cache awareness
    # For OpenAI: cached tokens are 50% of regular price
    # For Anthropic: cache_read is 10% of regular, cache_write is 125% of regular
    if provider_key == "openai" and cached > 0:
        # OpenAI style: prompt_tokens includes cached, we discount the cached portion
        uncached_tokens = max(0, tokens_in - cached)
        cached_discount = discounts.get("cached_read", 0.50)
        prompt_cost = (uncached_tokens * float(prompt_price)) + (cached * float(prompt_price) * cached_discount)
    elif provider_key == "anthropic" and (cache_read > 0 or cache_write > 0):
        # Anthropic style: separate counts for cache read/write
        # prompt_tokens is total, subtract cache_read and cache_write to get regular
        uncached_tokens = max(0, tokens_in - cache_read - cache_write)
        read_discount = discounts.get("cache_read", 0.10)
        write_premium = discounts.get("cache_write", 1.25)
        prompt_cost = (
            (uncached_tokens * float(prompt_price)) +
            (cache_read * float(prompt_price) * read_discount) +
            (cache_write * float(prompt_price) * write_premium)
        )
        cached = cache_read  # For the return value
    elif provider_key == "google" and cached > 0:
        # Google style: similar to OpenAI
        uncached_tokens = max(0, tokens_in - cached)
        cached_discount = discounts.get("cached_read", 0.25)
        prompt_cost = (uncached_tokens * float(prompt_price)) + (cached * float(prompt_price) * cached_discount)
    else:
        # No caching or unknown provider - charge full price
        uncached_tokens = tokens_in
        prompt_cost = tokens_in * float(prompt_price)

    completion_cost = tokens_out * float(completion_price)

    return CostEstimate(
        prompt_cost_usd=round(prompt_cost, 10),
        completion_cost_usd=round(completion_cost, 10),
        uncached_prompt_tokens=uncached_tokens,
        cached_prompt_tokens=cached,
        cache_write_tokens=cache_write,
    )

def load_pricing_overrides(raw: str | None) -> PricingTable:
    if not raw:
        return {}
    import json

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - config error
        raise ValueError("Invalid JSON for LLM pricing overrides") from exc

    overrides: dict[str, dict[str, tuple[float, float]]] = {}
    for provider, models in parsed.items():
        if not isinstance(models, Mapping):
            continue
        provider_key = _provider_key(provider)
        overrides[provider_key] = {}
        for model_name, pricing in models.items():
            if isinstance(pricing, Mapping):
                prompt_price = float(pricing.get("prompt", 0.0))
                completion_price = float(pricing.get("completion", 0.0))
            elif isinstance(pricing, (list, tuple)) and len(pricing) == 2:
                prompt_price = float(pricing[0])
                completion_price = float(pricing[1])
            else:
                continue
            overrides[provider_key][_model_key(model_name)] = (prompt_price, completion_price)
    return overrides
