"""Helpers for multi-run reliability scoring."""

from __future__ import annotations
from collections.abc import Iterable, Mapping, Sequence

from dataclasses import dataclass
from math import inf
from statistics import mean, pstdev

@dataclass(frozen=True, slots=True)
class ReliabilityMetricStats:
    """Describes variability for a single metric across runs."""

    mean: float
    stdev: float
    minimum: float
    maximum: float
    count: int
    consistency: float

@dataclass(frozen=True, slots=True)
class ReliabilityResult:
    runs: int
    similarities: tuple[float, ...]
    average_similarity: float
    min_similarity: float
    pass_rate: float
    verdict: str
    consistency_score: float
    metric_stats: dict[str, ReliabilityMetricStats]
    worst_metric: str | None

def _calc_consistency(values: Sequence[float]) -> tuple[float, ReliabilityMetricStats]:
    """Return consistency score and stats for a metric."""

    if not values:
        stats = ReliabilityMetricStats(mean=0.0, stdev=0.0, minimum=0.0, maximum=0.0, count=0, consistency=0.0)
        return 0.0, stats

    values_float = tuple(float(v) for v in values)
    avg = mean(values_float)
    if len(values_float) > 1:
        stdev_val = pstdev(values_float)
    else:
        stdev_val = 0.0
    if avg == 0:
        consistency = 1.0 if stdev_val == 0 else 0.0
    else:
        consistency = max(0.0, 1.0 - (stdev_val / abs(avg)))
    stats = ReliabilityMetricStats(
        mean=avg,
        stdev=stdev_val,
        minimum=min(values_float),
        maximum=max(values_float),
        count=len(values_float),
        consistency=consistency,
    )
    return consistency, stats

def _collect_metric_consistency(metrics: Mapping[str, Iterable[float | None]] | None) -> dict[str, ReliabilityMetricStats]:
    stats: dict[str, ReliabilityMetricStats] = {}
    if not metrics:
        return stats
    for name, series in metrics.items():
        filtered = [float(v) for v in series if v is not None]
        _, stat = _calc_consistency(filtered)
        stats[name] = stat
    return stats

def compute_reliability(
    similarities: Iterable[float],
    threshold: float,
    metrics: Mapping[str, Iterable[float | None]] | None = None,
    weights: Mapping[str, float] | None = None,
) -> ReliabilityResult:
    sims = tuple(float(s) for s in similarities)
    if not sims:
        return ReliabilityResult(
            runs=0,
            similarities=(),
            average_similarity=0.0,
            min_similarity=0.0,
            pass_rate=0.0,
            verdict="fail",
            consistency_score=0.0,
            metric_stats={},
            worst_metric=None,
        )

    avg = mean(sims)
    min_sim = min(sims)
    pass_rate = sum(1 for s in sims if s >= threshold) / len(sims)
    similarity_consistency, _ = _calc_consistency(sims)

    metric_stats = _collect_metric_consistency(metrics)
    default_weights = {
        "goal": 0.35,
        "resilience": 0.25,
        "latency_p95": 0.2,
        "cost": 0.2,
    }
    weight_map = {**default_weights, **(weights or {})}
    total_weight = 0.0
    weighted_sum = similarity_consistency  # baseline functional similarity weight of 1
    total_weight += 1.0
    for name, stat in metric_stats.items():
        weight = weight_map.get(name, 0.1)
        weighted_sum += stat.consistency * weight
        total_weight += weight
    overall_consistency = weighted_sum / total_weight if total_weight else 0.0

    worst_metric = None
    worst_consistency = inf
    for name, stat in metric_stats.items():
        if stat.consistency < worst_consistency:
            worst_consistency = stat.consistency
            worst_metric = name

    verdict = "pass" if avg >= threshold else "fail"
    return ReliabilityResult(
        runs=len(sims),
        similarities=sims,
        average_similarity=avg,
        min_similarity=min_sim,
        pass_rate=pass_rate,
        verdict=verdict,
        consistency_score=overall_consistency,
        metric_stats=metric_stats,
        worst_metric=worst_metric,
    )
