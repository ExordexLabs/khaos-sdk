"""Cost model utilities for estimating LLM spend when providers do not return prices."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

@dataclass(frozen=True, slots=True)
class CostRate:
    provider: str
    model: str
    prompt_usd_per_1k: float
    completion_usd_per_1k: float
    currency: str = "USD"
    source: str | None = None
    last_verified: str | None = None
    confidence: str | None = None

def _default_cost_table_path() -> Path:
    """Locate the bundled cost table (config/cost_models.yaml).

    Path: sdk/config/cost_models.yaml relative to sdk/src/khaos/costs.py
    """
    module_file = Path(__file__).resolve()
    # costs.py -> khaos -> src -> sdk -> config/cost_models.yaml
    sdk_root = module_file.parent.parent.parent
    return sdk_root / "config" / "cost_models.yaml"

def _load_yaml_table(path: Path) -> list[CostRate]:
    data = yaml.safe_load(path.read_text()) or []
    entries: list[CostRate] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        try:
            entries.append(
                CostRate(
                    provider=str(row.get("provider", "")).lower(),
                    model=str(row.get("model", "")).lower(),
                    prompt_usd_per_1k=float(row.get("prompt_usd_per_1k")),
                    completion_usd_per_1k=float(row.get("completion_usd_per_1k")),
                    currency=row.get("currency", "USD"),
                    source=row.get("source"),
                    last_verified=row.get("last_verified"),
                    confidence=row.get("confidence"),
                )
            )
        except (TypeError, ValueError):
            continue
    return entries

@lru_cache(maxsize=1)
def load_cost_table(path: str | Path | None = None) -> tuple[CostRate, ...]:
    """Load the rate table, honoring env/override paths."""

    env_override = Path(os.environ["KHAOS_COST_TABLE"]).expanduser() if (path is None and "KHAOS_COST_TABLE" in os.environ) else None
    if path is not None:
        env_override = Path(str(path)).expanduser()
    user_override = Path.home() / ".khaos" / "cost_models.yaml"
    config_path = (
        env_override
        or (user_override if user_override.exists() else None)
        or _default_cost_table_path()
    )
    resolved = Path(config_path).expanduser()
    if not resolved.exists():
        return tuple()
    return tuple(_load_yaml_table(resolved))

def _find_matching_rate(
    provider_norm: str,
    model_norm: str,
    rates: Iterable[CostRate],
) -> CostRate | None:
    """Find a matching rate, supporting dated model versions.

    Model names like 'gpt-5-mini-2025-08-07' should match 'gpt-5-mini'.
    We try exact match first, then progressively strip date suffixes.
    """
    rates_list = list(rates)

    # 1. Exact match
    for rate in rates_list:
        if rate.provider == provider_norm and rate.model == model_norm:
            return rate

    # 2. Strip date suffix patterns (e.g., -2025-08-07, -20250807, -2025)
    import re
    # Match patterns like -YYYY-MM-DD, -YYYYMMDD, -YYYY at the end
    date_patterns = [
        r"-\d{4}-\d{2}-\d{2}$",  # -2025-08-07
        r"-\d{8}$",              # -20250807
        r"-\d{4}$",              # -2025
        r":\d{4}-\d{2}-\d{2}$",  # :2025-08-07 (some providers use colons)
    ]
    stripped_model = model_norm
    for pattern in date_patterns:
        stripped_model = re.sub(pattern, "", stripped_model)
        if stripped_model != model_norm:
            break

    if stripped_model != model_norm:
        for rate in rates_list:
            if rate.provider == provider_norm and rate.model == stripped_model:
                return rate

    # 3. Try prefix matching (model_norm starts with rate.model)
    for rate in rates_list:
        if rate.provider == provider_norm and model_norm.startswith(rate.model):
            return rate

    return None

def estimate_cost_usd(
    *,
    provider: str | None,
    model: str | None,
    prompt_tokens: float,
    completion_tokens: float,
    table: Iterable[CostRate] | None = None,
) -> tuple[float | None, str]:
    """Estimate cost when providers do not return pricing.

    Returns (cost_usd, source_flag) where source_flag is 'estimated' or 'unknown'.
    """

    provider_norm = (provider or "").lower().strip()
    model_norm = (model or "").lower().strip()
    rates = table if table is not None else load_cost_table()
    if not provider_norm or not model_norm:
        return None, "unknown"

    match = _find_matching_rate(provider_norm, model_norm, rates)
    if match is None:
        return None, "unknown"

    total_prompt = max(0.0, prompt_tokens)
    total_completion = max(0.0, completion_tokens)
    prompt_cost = (total_prompt / 1000.0) * match.prompt_usd_per_1k
    completion_cost = (total_completion / 1000.0) * match.completion_usd_per_1k
    return prompt_cost + completion_cost, "estimated"
