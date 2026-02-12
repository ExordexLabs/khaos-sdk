"""Sampling configuration for production telemetry.

Provides configurable sampling strategies to reduce overhead
in high-traffic production environments.
"""

from __future__ import annotations

import hashlib
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from collections.abc import Callable

class SamplingStrategy(Enum):
    """Available sampling strategies."""

    # Random sampling - simple probability-based
    RANDOM = "random"

    # Consistent hashing - same request ID always sampled or not
    CONSISTENT = "consistent"

    # Rate limiting - sample N requests per second
    RATE_LIMITED = "rate_limited"

    # Always sample specific paths/patterns
    PRIORITY = "priority"

    # Adaptive - adjust based on system load
    ADAPTIVE = "adaptive"

    # Always sample (no sampling)
    ALWAYS = "always"

    # Never sample
    NEVER = "never"

@dataclass
class SamplingConfig:
    """Configuration for request sampling."""

    # Primary strategy
    strategy: SamplingStrategy = SamplingStrategy.RANDOM

    # Base sample rate (0.0 to 1.0)
    sample_rate: float = 1.0

    # For rate-limited: max samples per second
    rate_limit_per_second: float = 100.0

    # For priority: paths to always sample
    priority_paths: list[str] = field(default_factory=list)

    # For priority: patterns to always sample (regex)
    priority_patterns: list[str] = field(default_factory=list)

    # For adaptive: min/max sample rates
    adaptive_min_rate: float = 0.01
    adaptive_max_rate: float = 1.0

    # For consistent: hash seed
    consistent_seed: int = 42

    # Whether to sample error responses
    always_sample_errors: bool = True

    # Whether to sample slow requests
    always_sample_slow_requests: bool = True
    slow_request_threshold_ms: float = 5000.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize config."""
        return {
            "strategy": self.strategy.value,
            "sample_rate": self.sample_rate,
            "rate_limit_per_second": self.rate_limit_per_second,
            "priority_paths": self.priority_paths,
            "priority_patterns": self.priority_patterns,
            "adaptive_min_rate": self.adaptive_min_rate,
            "adaptive_max_rate": self.adaptive_max_rate,
            "always_sample_errors": self.always_sample_errors,
            "always_sample_slow_requests": self.always_sample_slow_requests,
            "slow_request_threshold_ms": self.slow_request_threshold_ms,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SamplingConfig":
        """Parse config from dict."""
        strategy_str = data.get("strategy", "random")
        try:
            strategy = SamplingStrategy(strategy_str)
        except ValueError:
            strategy = SamplingStrategy.RANDOM

        return cls(
            strategy=strategy,
            sample_rate=data.get("sample_rate", 1.0),
            rate_limit_per_second=data.get("rate_limit_per_second", 100.0),
            priority_paths=data.get("priority_paths", []),
            priority_patterns=data.get("priority_patterns", []),
            adaptive_min_rate=data.get("adaptive_min_rate", 0.01),
            adaptive_max_rate=data.get("adaptive_max_rate", 1.0),
            always_sample_errors=data.get("always_sample_errors", True),
            always_sample_slow_requests=data.get("always_sample_slow_requests", True),
            slow_request_threshold_ms=data.get("slow_request_threshold_ms", 5000.0),
        )

class Sampler:
    """Request sampler implementation."""

    def __init__(self, config: SamplingConfig):
        self.config = config
        self._rng = random.Random()
        self._rate_limit_tokens = config.rate_limit_per_second
        self._rate_limit_last_refill = time.monotonic()
        self._current_load = 0.5  # For adaptive sampling

    def should_sample(
        self,
        request_id: str | None = None,
        path: str | None = None,
        method: str | None = None,
    ) -> bool:
        """Determine if a request should be sampled.

        Args:
            request_id: Unique request identifier
            path: Request path
            method: HTTP method

        Returns:
            True if request should be sampled
        """
        if self.config.strategy == SamplingStrategy.ALWAYS:
            return True

        if self.config.strategy == SamplingStrategy.NEVER:
            return False

        # Check priority paths first
        if path and self._is_priority_path(path):
            return True

        # Apply strategy
        if self.config.strategy == SamplingStrategy.RANDOM:
            return self._random_sample()

        if self.config.strategy == SamplingStrategy.CONSISTENT:
            return self._consistent_sample(request_id or "")

        if self.config.strategy == SamplingStrategy.RATE_LIMITED:
            return self._rate_limited_sample()

        if self.config.strategy == SamplingStrategy.ADAPTIVE:
            return self._adaptive_sample()

        return self._random_sample()

    def should_sample_response(
        self,
        status_code: int | None = None,
        duration_ms: float | None = None,
        already_sampled: bool = False,
    ) -> bool:
        """Check if response should be sampled based on outcome.

        Called after request completes to override initial sampling decision.

        Args:
            status_code: HTTP status code
            duration_ms: Request duration
            already_sampled: Whether request was already sampled

        Returns:
            True if should be sampled
        """
        if already_sampled:
            return True

        # Always sample errors
        if self.config.always_sample_errors and status_code:
            if status_code >= 400:
                return True

        # Always sample slow requests
        if self.config.always_sample_slow_requests and duration_ms:
            if duration_ms >= self.config.slow_request_threshold_ms:
                return True

        return False

    def update_load(self, load: float) -> None:
        """Update system load for adaptive sampling.

        Args:
            load: Current load (0.0 to 1.0)
        """
        self._current_load = max(0.0, min(1.0, load))

    def _is_priority_path(self, path: str) -> bool:
        """Check if path is a priority path."""
        import re

        # Exact match
        if path in self.config.priority_paths:
            return True

        # Pattern match
        for pattern in self.config.priority_patterns:
            try:
                if re.match(pattern, path):
                    return True
            except re.error:
                continue

        return False

    def _random_sample(self) -> bool:
        """Random sampling."""
        return self._rng.random() < self.config.sample_rate

    def _consistent_sample(self, request_id: str) -> bool:
        """Consistent hashing sampling."""
        # Hash request ID with seed
        h = hashlib.md5(
            f"{self.config.consistent_seed}:{request_id}".encode()
        ).hexdigest()

        # Convert first 8 hex chars to float between 0 and 1
        hash_value = int(h[:8], 16) / 0xFFFFFFFF

        return hash_value < self.config.sample_rate

    def _rate_limited_sample(self) -> bool:
        """Token bucket rate limiting."""
        now = time.monotonic()
        elapsed = now - self._rate_limit_last_refill

        # Refill tokens
        self._rate_limit_tokens = min(
            self.config.rate_limit_per_second,
            self._rate_limit_tokens + elapsed * self.config.rate_limit_per_second
        )
        self._rate_limit_last_refill = now

        # Try to consume a token
        if self._rate_limit_tokens >= 1.0:
            self._rate_limit_tokens -= 1.0
            return True

        return False

    def _adaptive_sample(self) -> bool:
        """Adaptive sampling based on load."""
        # Linear interpolation between min and max rate
        # High load = lower sample rate
        rate = self.config.adaptive_max_rate - (
            self._current_load *
            (self.config.adaptive_max_rate - self.config.adaptive_min_rate)
        )

        return self._rng.random() < rate

# Global sampler instance
_sampler: Sampler | None = None

def get_sampler() -> Sampler | None:
    """Get the global sampler instance."""
    return _sampler

def set_sampler(sampler: Sampler | None) -> None:
    """Set the global sampler instance."""
    global _sampler
    _sampler = sampler

def configure_sampling(config: SamplingConfig) -> Sampler:
    """Configure global sampling.

    Args:
        config: Sampling configuration

    Returns:
        Configured sampler
    """
    sampler = Sampler(config)
    set_sampler(sampler)
    return sampler

def should_sample_request(
    request_id: str | None = None,
    path: str | None = None,
    method: str | None = None,
) -> bool:
    """Check if a request should be sampled using global sampler.

    Args:
        request_id: Unique request identifier
        path: Request path
        method: HTTP method

    Returns:
        True if request should be sampled
    """
    sampler = get_sampler()
    if sampler is None:
        return True  # Sample everything by default

    return sampler.should_sample(request_id, path, method)
