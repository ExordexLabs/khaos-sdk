"""Output consistency evaluator for baseline behavior analysis.

This module calculates consistency metrics across multiple baseline runs
to understand how deterministic/predictable an agent's behavior is.

For agent behavior intelligence, high consistency indicates:
- Reliable, predictable responses
- Stable tool usage patterns
- Consistent decision making

Low consistency may indicate:
- Non-deterministic behavior (may be intentional for creative tasks)
- Temperature/sampling variance effects
- Unstable behavior that warrants investigation
"""

from __future__ import annotations

import difflib
import json
import math
import re
import statistics
from collections import Counter
from dataclasses import dataclass
from typing import Any

from khaos.packs.contract import OutputConsistencyMetrics


@dataclass(slots=True)
class RunOutput:
    """Single run output for consistency comparison."""

    run_index: int
    input_id: str
    output_text: str
    output_length: int
    tool_calls: list[str]  # List of tool names called
    tool_args: list[dict[str, Any]]  # Arguments for each tool call
    success: bool
    goal_met: bool | None


class OutputConsistencyEvaluator:
    """Evaluate output consistency across multiple baseline runs.

    This evaluator compares outputs from multiple runs of the same inputs
    to measure how consistent/deterministic the agent's behavior is.
    """

    SIMILARITY_THRESHOLD = 0.85  # Below this is considered divergent
    HIGH_CONSISTENCY_THRESHOLD = 0.9
    MODERATE_CONSISTENCY_THRESHOLD = 0.6

    def __init__(self) -> None:
        pass

    def evaluate(self, run_outputs: list[list[RunOutput]]) -> OutputConsistencyMetrics:
        """Evaluate consistency across multiple baseline runs.

        Args:
            run_outputs: List of runs, each containing a list of RunOutput for each input.
                         Index 0 is first run, index 1 is second run, etc.
                         Each run should have outputs for the same inputs in the same order.

        Returns:
            OutputConsistencyMetrics with computed consistency scores.
        """
        if len(run_outputs) < 2:
            # Need at least 2 runs to compare
            return OutputConsistencyMetrics.perfect()

        # Collect all pairwise comparisons
        content_similarities: list[float] = []
        semantic_similarities: list[float] = []
        result_consistencies: list[float] = []
        tool_call_consistencies: list[float] = []
        tool_args_similarities: list[float] = []
        all_lengths: list[int] = []
        divergent_count = 0
        pairs_compared = 0

        # Compare each pair of runs
        for i in range(len(run_outputs)):
            for j in range(i + 1, len(run_outputs)):
                run_a = run_outputs[i]
                run_b = run_outputs[j]

                # Compare outputs for each input
                for output_a, output_b in self._align_outputs(run_a, run_b):
                    pairs_compared += 1

                    # Content similarity (character-level)
                    content_sim = self._text_similarity(output_a.output_text, output_b.output_text)
                    content_similarities.append(content_sim)

                    # Semantic similarity (word-level TF-IDF)
                    semantic_sim = self._semantic_similarity(output_a.output_text, output_b.output_text)
                    semantic_similarities.append(semantic_sim)

                    if content_sim < self.SIMILARITY_THRESHOLD:
                        divergent_count += 1

                    # Result consistency (same success/goal status)
                    result_sim = self._result_similarity(output_a, output_b)
                    result_consistencies.append(result_sim)

                    # Tool call consistency
                    tool_sim = self._tool_call_similarity(output_a.tool_calls, output_b.tool_calls)
                    tool_call_consistencies.append(tool_sim)

                    # Tool args similarity
                    args_sim = self._tool_args_similarity(output_a.tool_args, output_b.tool_args)
                    tool_args_similarities.append(args_sim)

                    # Collect lengths for variance calculation
                    all_lengths.append(output_a.output_length)
                    all_lengths.append(output_b.output_length)

        # Calculate aggregate metrics
        content_similarity = statistics.mean(content_similarities) if content_similarities else 1.0
        semantic_similarity = statistics.mean(semantic_similarities) if semantic_similarities else 1.0
        result_consistency = statistics.mean(result_consistencies) if result_consistencies else 1.0
        tool_call_consistency = statistics.mean(tool_call_consistencies) if tool_call_consistencies else 1.0
        tool_args_similarity = statistics.mean(tool_args_similarities) if tool_args_similarities else 1.0

        # Length statistics
        length_mean = statistics.mean(all_lengths) if all_lengths else 0.0
        length_std = statistics.stdev(all_lengths) if len(all_lengths) > 1 else 0.0
        length_variance = (length_std / length_mean) if length_mean > 0 else 0.0

        # Calculate overall score (weighted)
        overall_score = self._calculate_overall_score(
            content_similarity=content_similarity,
            semantic_similarity=semantic_similarity,
            result_consistency=result_consistency,
            tool_call_consistency=tool_call_consistency,
            tool_args_similarity=tool_args_similarity,
            length_variance=length_variance,
        )

        return OutputConsistencyMetrics(
            content_similarity=content_similarity,
            semantic_similarity=semantic_similarity,
            result_consistency=result_consistency,
            length_variance=length_variance,
            length_mean=length_mean,
            length_std=length_std,
            tool_call_consistency=tool_call_consistency,
            tool_args_similarity=tool_args_similarity,
            overall_score=overall_score,
            samples_compared=pairs_compared,
            divergent_outputs=divergent_count,
        )

    def evaluate_from_input_results(
        self,
        input_results: list[dict[str, Any]],
        num_runs: int,
    ) -> OutputConsistencyMetrics:
        """Evaluate consistency from InputResult dictionaries.

        Args:
            input_results: List of InputResult.to_dict() outputs
            num_runs: Number of baseline runs executed

        Returns:
            OutputConsistencyMetrics
        """
        if num_runs < 2:
            return OutputConsistencyMetrics.perfect()

        # Group results by input_id and run_index
        by_input: dict[str, list[RunOutput]] = {}

        for result in input_results:
            if result.get("phase") != "baseline":
                continue

            input_id = result.get("input_id", "")
            run_index = result.get("run_index", 0)

            output = RunOutput(
                run_index=run_index,
                input_id=input_id,
                output_text=result.get("response_preview", ""),
                output_length=len(result.get("response_preview", "")),
                tool_calls=self._extract_tool_calls(result),
                tool_args=self._extract_tool_args(result),
                success=result.get("success", False),
                goal_met=result.get("goal_met"),
            )

            if input_id not in by_input:
                by_input[input_id] = []
            by_input[input_id].append(output)

        # Reorganize into runs
        runs: list[list[RunOutput]] = [[] for _ in range(num_runs)]
        for input_id, outputs in by_input.items():
            for output in outputs:
                if output.run_index < num_runs:
                    runs[output.run_index].append(output)

        return self.evaluate(runs)

    def _align_outputs(
        self,
        run_a: list[RunOutput],
        run_b: list[RunOutput],
    ) -> list[tuple[RunOutput, RunOutput]]:
        """Align outputs from two runs by input_id."""
        by_id_a = {o.input_id: o for o in run_a}
        by_id_b = {o.input_id: o for o in run_b}

        aligned: list[tuple[RunOutput, RunOutput]] = []
        for input_id in by_id_a:
            if input_id in by_id_b:
                aligned.append((by_id_a[input_id], by_id_b[input_id]))

        return aligned

    def _text_similarity(self, text_a: str, text_b: str) -> float:
        """Calculate text similarity using SequenceMatcher."""
        if not text_a and not text_b:
            return 1.0
        if not text_a or not text_b:
            return 0.0

        matcher = difflib.SequenceMatcher(a=text_a, b=text_b, autojunk=False)
        return matcher.ratio()

    def _semantic_similarity(self, text_a: str, text_b: str) -> float:
        """Calculate semantic similarity using word-level analysis.

        This measures meaning preservation rather than exact character overlap.
        Uses multiple signals:
        1. Word overlap (Jaccard on word sets)
        2. N-gram overlap (bigrams capture word relationships)
        3. Normalized term frequency cosine similarity

        This approach is lightweight (no external dependencies) while still
        capturing semantic relationships better than character-level diff.
        """
        if not text_a and not text_b:
            return 1.0
        if not text_a or not text_b:
            return 0.0

        # Tokenize: extract words, normalize to lowercase
        def tokenize(text: str) -> list[str]:
            # Extract alphanumeric words, lowercase
            return re.findall(r'\b[a-zA-Z0-9]+\b', text.lower())

        tokens_a = tokenize(text_a)
        tokens_b = tokenize(text_b)

        if not tokens_a and not tokens_b:
            return 1.0
        if not tokens_a or not tokens_b:
            return 0.0

        # 1. Word-level Jaccard similarity
        set_a = set(tokens_a)
        set_b = set(tokens_b)
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        word_jaccard = intersection / union if union > 0 else 0.0

        # 2. Bigram overlap (captures word relationships/ordering)
        def get_bigrams(tokens: list[str]) -> set[tuple[str, str]]:
            return {(tokens[i], tokens[i + 1]) for i in range(len(tokens) - 1)} if len(tokens) > 1 else set()

        bigrams_a = get_bigrams(tokens_a)
        bigrams_b = get_bigrams(tokens_b)
        if bigrams_a or bigrams_b:
            bigram_intersection = len(bigrams_a & bigrams_b)
            bigram_union = len(bigrams_a | bigrams_b)
            bigram_jaccard = bigram_intersection / bigram_union if bigram_union > 0 else 0.0
        else:
            bigram_jaccard = word_jaccard  # Fall back to word-level for very short texts

        # 3. Term frequency cosine similarity (weighted by frequency)
        tf_a = Counter(tokens_a)
        tf_b = Counter(tokens_b)
        all_terms = set(tf_a.keys()) | set(tf_b.keys())

        # Normalize by document length
        len_a = sum(tf_a.values())
        len_b = sum(tf_b.values())

        dot_product = sum(
            (tf_a.get(term, 0) / len_a) * (tf_b.get(term, 0) / len_b)
            for term in all_terms
        )
        magnitude_a = math.sqrt(sum((c / len_a) ** 2 for c in tf_a.values()))
        magnitude_b = math.sqrt(sum((c / len_b) ** 2 for c in tf_b.values()))

        if magnitude_a > 0 and magnitude_b > 0:
            cosine_sim = dot_product / (magnitude_a * magnitude_b)
        else:
            cosine_sim = 0.0

        # Combine signals:
        # - 40% word overlap (basic meaning coverage)
        # - 30% bigram overlap (captures phrase structure)
        # - 30% cosine similarity (weighted term importance)
        return 0.40 * word_jaccard + 0.30 * bigram_jaccard + 0.30 * cosine_sim

    def _result_similarity(self, output_a: RunOutput, output_b: RunOutput) -> float:
        """Calculate result similarity (success/goal status match)."""
        score = 0.0
        total = 0.0

        # Success match
        total += 1.0
        if output_a.success == output_b.success:
            score += 1.0

        # Goal met match (if both have goal info)
        if output_a.goal_met is not None and output_b.goal_met is not None:
            total += 1.0
            if output_a.goal_met == output_b.goal_met:
                score += 1.0

        return score / total if total > 0 else 1.0

    def _tool_call_similarity(self, tools_a: list[str], tools_b: list[str]) -> float:
        """Calculate tool call sequence similarity."""
        if not tools_a and not tools_b:
            return 1.0
        if not tools_a or not tools_b:
            return 0.0

        # Use SequenceMatcher for order-aware comparison
        matcher = difflib.SequenceMatcher(a=tools_a, b=tools_b, autojunk=False)
        return matcher.ratio()

    def _tool_args_similarity(
        self,
        args_a: list[dict[str, Any]],
        args_b: list[dict[str, Any]],
    ) -> float:
        """Calculate tool arguments similarity."""
        if not args_a and not args_b:
            return 1.0
        if not args_a or not args_b:
            return 0.0

        # Convert to JSON strings for comparison
        str_a = [json.dumps(a, sort_keys=True) for a in args_a]
        str_b = [json.dumps(b, sort_keys=True) for b in args_b]

        # Compare pairwise
        min_len = min(len(str_a), len(str_b))
        if min_len == 0:
            return 0.0

        similarities = []
        for i in range(min_len):
            sim = self._text_similarity(str_a[i], str_b[i])
            similarities.append(sim)

        # Penalize for different number of tool calls
        length_penalty = min_len / max(len(str_a), len(str_b))

        return statistics.mean(similarities) * length_penalty if similarities else 0.0

    def _calculate_overall_score(
        self,
        content_similarity: float,
        semantic_similarity: float,
        result_consistency: float,
        tool_call_consistency: float,
        tool_args_similarity: float,
        length_variance: float,
    ) -> float:
        """Calculate weighted overall consistency score.

        Weights:
        - Content similarity: 30% (textual match)
        - Semantic similarity: 20% (meaning preservation)
        - Result consistency: 25% (same outcomes)
        - Tool consistency: 15% (same tool usage)
        - Tool args: 10% (similar arguments)

        Length variance acts as a penalty.
        """
        base_score = (
            content_similarity * 0.30 +
            semantic_similarity * 0.20 +
            result_consistency * 0.25 +
            tool_call_consistency * 0.15 +
            tool_args_similarity * 0.10
        )

        # Apply length variance penalty (high variance = less consistent)
        # CV > 0.5 gets penalized
        variance_penalty = max(0, min(length_variance - 0.5, 0.5)) * 0.2

        return max(0.0, min(1.0, base_score - variance_penalty))

    def _extract_tool_calls(self, result: dict[str, Any]) -> list[str]:
        """Extract tool call names from result."""
        # Try multi-turn format first
        turns = result.get("turns", [])
        if turns:
            tools = []
            for turn in turns:
                # Look for tool calls in turn metadata
                if turn.get("tool"):
                    tools.append(turn["tool"])
            return tools

        # Fall back to check_errors for tool validation
        return []

    def _extract_tool_args(self, result: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract tool arguments from result."""
        # Placeholder - would extract from detailed trace data
        return []


def calculate_consistency_from_traces(
    traces: list[list[dict[str, Any]]],
) -> OutputConsistencyMetrics:
    """Convenience function to calculate consistency from raw trace data.

    Args:
        traces: List of traces, one per baseline run. Each trace is a list of events.

    Returns:
        OutputConsistencyMetrics
    """
    if len(traces) < 2:
        return OutputConsistencyMetrics.perfect()

    # Extract outputs from traces
    runs: list[list[RunOutput]] = []

    for run_idx, trace in enumerate(traces):
        outputs: list[RunOutput] = []
        output_idx = 0

        for event in trace:
            if event.get("event") == "transport.receive":
                payload = event.get("payload", {})
                content = ""
                if isinstance(payload, dict):
                    content = payload.get("content", "") or payload.get("text", "") or ""
                elif isinstance(payload, str):
                    content = payload

                # Extract tool calls from event
                tool_calls: list[str] = []
                tool_args: list[dict[str, Any]] = []
                meta = event.get("meta", {})
                if meta.get("tool"):
                    tool_calls.append(meta["tool"])
                    if meta.get("args"):
                        tool_args.append(meta["args"])

                outputs.append(RunOutput(
                    run_index=run_idx,
                    input_id=f"output_{output_idx}",
                    output_text=content,
                    output_length=len(content),
                    tool_calls=tool_calls,
                    tool_args=tool_args,
                    success=True,  # Default
                    goal_met=None,
                ))
                output_idx += 1

        runs.append(outputs)

    evaluator = OutputConsistencyEvaluator()
    return evaluator.evaluate(runs)
