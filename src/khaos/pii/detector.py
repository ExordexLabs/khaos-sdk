"""PII detection with scanning and reporting capabilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .patterns import (
    PII_PATTERNS,
    PIICategory,
    PIIPattern,
    RiskLevel,
    get_patterns_by_category,
    get_patterns_by_risk,
)


@dataclass
class PIIMatch:
    """A single PII match in text."""

    pattern_name: str
    category: PIICategory
    risk_level: RiskLevel
    matched_text: str
    start: int
    end: int
    line_number: int = 0
    context: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "pattern": self.pattern_name,
            "category": self.category.value,
            "risk": self.risk_level.value,
            "matched": self.matched_text,
            "start": self.start,
            "end": self.end,
            "line": self.line_number,
            "context": self.context,
        }


@dataclass
class PIIScanResult:
    """Results from a PII scan."""

    matches: list[PIIMatch]
    text_length: int
    has_pii: bool
    risk_summary: dict[str, int] = field(default_factory=dict)
    category_summary: dict[str, int] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        """Count of critical risk matches."""
        return sum(1 for m in self.matches if m.risk_level == RiskLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high risk matches."""
        return sum(1 for m in self.matches if m.risk_level == RiskLevel.HIGH)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "has_pii": self.has_pii,
            "match_count": len(self.matches),
            "text_length": self.text_length,
            "risk_summary": self.risk_summary,
            "category_summary": self.category_summary,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "matches": [m.to_dict() for m in self.matches],
        }


class PIIDetector:
    """Configurable PII detector with scanning and reporting."""

    def __init__(
        self,
        categories: list[PIICategory] | None = None,
        min_risk_level: RiskLevel = RiskLevel.LOW,
        include_context: bool = True,
        context_chars: int = 20,
        custom_patterns: list[PIIPattern] | None = None,
    ):
        """Initialize the detector.

        Args:
            categories: Categories to scan for (all if None)
            min_risk_level: Minimum risk level to report
            include_context: Whether to include surrounding context
            context_chars: Characters of context to include
            custom_patterns: Additional custom patterns to include
        """
        self.categories = categories
        self.min_risk_level = min_risk_level
        self.include_context = include_context
        self.context_chars = context_chars

        # Build pattern list
        patterns = list(PII_PATTERNS)
        if custom_patterns:
            patterns.extend(custom_patterns)

        # Filter by category
        if categories:
            patterns = [p for p in patterns if p.category in categories]

        # Filter by risk level
        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        min_index = risk_order.index(min_risk_level)
        patterns = [p for p in patterns if risk_order.index(p.risk_level) >= min_index]

        self.patterns = patterns

    def scan(self, text: str) -> PIIScanResult:
        """Scan text for PII.

        Args:
            text: Text to scan

        Returns:
            PIIScanResult with all matches and summary
        """
        matches: list[PIIMatch] = []

        # Pre-compute line numbers
        line_starts = [0]
        for i, char in enumerate(text):
            if char == "\n":
                line_starts.append(i + 1)

        def get_line_number(pos: int) -> int:
            for i, start in enumerate(line_starts):
                if start > pos:
                    return i
            return len(line_starts)

        # Find all matches
        for pattern in self.patterns:
            for start, end, matched in pattern.match(text):
                context = ""
                if self.include_context:
                    ctx_start = max(0, start - self.context_chars)
                    ctx_end = min(len(text), end + self.context_chars)
                    context = text[ctx_start:ctx_end]
                    if ctx_start > 0:
                        context = "..." + context
                    if ctx_end < len(text):
                        context = context + "..."

                matches.append(
                    PIIMatch(
                        pattern_name=pattern.name,
                        category=pattern.category,
                        risk_level=pattern.risk_level,
                        matched_text=matched,
                        start=start,
                        end=end,
                        line_number=get_line_number(start),
                        context=context,
                    )
                )

        # Sort by position
        matches.sort(key=lambda m: m.start)

        # Build summaries
        risk_summary: dict[str, int] = {}
        category_summary: dict[str, int] = {}

        for match in matches:
            risk_name = match.risk_level.value
            risk_summary[risk_name] = risk_summary.get(risk_name, 0) + 1

            cat_name = match.category.value
            category_summary[cat_name] = category_summary.get(cat_name, 0) + 1

        return PIIScanResult(
            matches=matches,
            text_length=len(text),
            has_pii=len(matches) > 0,
            risk_summary=risk_summary,
            category_summary=category_summary,
        )

    def scan_multiple(self, texts: dict[str, str]) -> dict[str, PIIScanResult]:
        """Scan multiple texts.

        Args:
            texts: Dictionary of name -> text

        Returns:
            Dictionary of name -> PIIScanResult
        """
        return {name: self.scan(text) for name, text in texts.items()}

    def quick_check(self, text: str) -> bool:
        """Quick check if text contains any PII (faster than full scan)."""
        return any(pattern.pattern.search(text) for pattern in self.patterns)

    def mask_text(
        self,
        text: str,
        mask_style: str = "label",
    ) -> str:
        """Mask PII in text.

        Args:
            text: Text to mask
            mask_style: "label", "char", or "partial"

        Returns:
            Masked text
        """
        result = text

        # Get all matches
        matches = []
        for pattern in self.patterns:
            for start, end, matched in pattern.match(text):
                matches.append((start, end, matched, pattern))

        # Sort by position (reverse to maintain indices)
        matches.sort(key=lambda x: -x[0])

        for start, end, matched, pattern in matches:
            if mask_style == "label":
                replacement = f"<<{pattern.name.upper()}>>"
            elif mask_style == "char":
                replacement = pattern.mask_char * len(matched)
            elif mask_style == "partial":
                if len(matched) > 4:
                    replacement = matched[0] + pattern.mask_char * (len(matched) - 2) + matched[-1]
                else:
                    replacement = pattern.mask_char * len(matched)
            else:
                replacement = f"[{pattern.name}]"

            result = result[:start] + replacement + result[end:]

        return result


# Convenience instances
DEFAULT_DETECTOR = PIIDetector()
AUTH_DETECTOR = PIIDetector(categories=[PIICategory.AUTHENTICATION], min_risk_level=RiskLevel.HIGH)
FINANCIAL_DETECTOR = PIIDetector(categories=[PIICategory.FINANCIAL])
CRITICAL_DETECTOR = PIIDetector(min_risk_level=RiskLevel.CRITICAL)


__all__ = [
    "PIIMatch",
    "PIIScanResult",
    "PIIDetector",
    "DEFAULT_DETECTOR",
    "AUTH_DETECTOR",
    "FINANCIAL_DETECTOR",
    "CRITICAL_DETECTOR",
]
