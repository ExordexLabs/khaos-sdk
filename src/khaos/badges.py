"""Status badge generation for CI/CD integration.

Generates SVG badges showing:
- Reliability scores
- Test status (passing/failing)
- Coverage percentages
- Security ratings
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class BadgeStyle(Enum):
    """Badge visual styles."""
    FLAT = "flat"
    FLAT_SQUARE = "flat-square"
    PLASTIC = "plastic"
    FOR_THE_BADGE = "for-the-badge"


class BadgeColor(Enum):
    """Predefined badge colors."""
    BRIGHTGREEN = "#4c1"
    GREEN = "#97CA00"
    YELLOWGREEN = "#a4a61d"
    YELLOW = "#dfb317"
    ORANGE = "#fe7d37"
    RED = "#e05d44"
    BLUE = "#007ec6"
    LIGHTGREY = "#9f9f9f"
    GREY = "#555"
    CRITICAL = "#b60205"


@dataclass
class Badge:
    """SVG badge data."""
    label: str
    message: str
    color: str
    label_color: str = "#555"
    style: BadgeStyle = BadgeStyle.FLAT

    def to_svg(self) -> str:
        """Generate SVG badge markup."""
        # Calculate widths based on text length
        label_width = len(self.label) * 6.5 + 10
        message_width = len(self.message) * 6.5 + 10
        total_width = label_width + message_width

        if self.style == BadgeStyle.FLAT:
            return self._flat_svg(label_width, message_width, total_width)
        elif self.style == BadgeStyle.FLAT_SQUARE:
            return self._flat_square_svg(label_width, message_width, total_width)
        elif self.style == BadgeStyle.PLASTIC:
            return self._plastic_svg(label_width, message_width, total_width)
        else:
            return self._flat_svg(label_width, message_width, total_width)

    def _flat_svg(self, lw: float, mw: float, tw: float) -> str:
        """Generate flat style badge."""
        return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{tw}" height="20" role="img">
  <title>{self.label}: {self.message}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{tw}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{lw}" height="20" fill="{self.label_color}"/>
    <rect x="{lw}" width="{mw}" height="20" fill="{self.color}"/>
    <rect width="{tw}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{lw/2}" y="15" fill="#010101" fill-opacity=".3">{self.label}</text>
    <text x="{lw/2}" y="14">{self.label}</text>
    <text x="{lw + mw/2}" y="15" fill="#010101" fill-opacity=".3">{self.message}</text>
    <text x="{lw + mw/2}" y="14">{self.message}</text>
  </g>
</svg>'''

    def _flat_square_svg(self, lw: float, mw: float, tw: float) -> str:
        """Generate flat-square style badge."""
        return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{tw}" height="20" role="img">
  <title>{self.label}: {self.message}</title>
  <g shape-rendering="crispEdges">
    <rect width="{lw}" height="20" fill="{self.label_color}"/>
    <rect x="{lw}" width="{mw}" height="20" fill="{self.color}"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{lw/2}" y="14">{self.label}</text>
    <text x="{lw + mw/2}" y="14">{self.message}</text>
  </g>
</svg>'''

    def _plastic_svg(self, lw: float, mw: float, tw: float) -> str:
        """Generate plastic style badge."""
        return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{tw}" height="18" role="img">
  <title>{self.label}: {self.message}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".7"/>
    <stop offset=".1" stop-color="#aaa" stop-opacity=".1"/>
    <stop offset=".9" stop-opacity=".3"/>
    <stop offset="1" stop-opacity=".5"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{tw}" height="18" rx="4" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{lw}" height="18" fill="{self.label_color}"/>
    <rect x="{lw}" width="{mw}" height="18" fill="{self.color}"/>
    <rect width="{tw}" height="18" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{lw/2}" y="13">{self.label}</text>
    <text x="{lw + mw/2}" y="13">{self.message}</text>
  </g>
</svg>'''

    def to_markdown(self, alt: str = "") -> str:
        """Generate markdown image reference."""
        alt_text = alt or f"{self.label}: {self.message}"
        return f"![{alt_text}](badge.svg)"

    def to_html(self, alt: str = "") -> str:
        """Generate HTML img tag."""
        alt_text = alt or f"{self.label}: {self.message}"
        return f'<img src="badge.svg" alt="{alt_text}">'


def get_reliability_color(score: float) -> str:
    """Get color based on reliability score.

    Args:
        score: Reliability score (0.0 to 1.0)

    Returns:
        Hex color code
    """
    if score >= 0.95:
        return BadgeColor.BRIGHTGREEN.value
    elif score >= 0.85:
        return BadgeColor.GREEN.value
    elif score >= 0.75:
        return BadgeColor.YELLOWGREEN.value
    elif score >= 0.60:
        return BadgeColor.YELLOW.value
    elif score >= 0.40:
        return BadgeColor.ORANGE.value
    else:
        return BadgeColor.RED.value


def get_status_color(passed: bool) -> str:
    """Get color based on pass/fail status.

    Args:
        passed: Whether tests passed

    Returns:
        Hex color code
    """
    return BadgeColor.BRIGHTGREEN.value if passed else BadgeColor.RED.value


def reliability_badge(
    score: float,
    *,
    style: BadgeStyle = BadgeStyle.FLAT,
    label: str = "reliability",
) -> Badge:
    """Create a reliability score badge.

    Args:
        score: Reliability score (0.0 to 1.0)
        style: Badge visual style
        label: Label text

    Returns:
        Badge instance
    """
    percentage = int(score * 100)
    return Badge(
        label=label,
        message=f"{percentage}%",
        color=get_reliability_color(score),
        style=style,
    )


def status_badge(
    passed: bool,
    *,
    style: BadgeStyle = BadgeStyle.FLAT,
    label: str = "khaos",
) -> Badge:
    """Create a pass/fail status badge.

    Args:
        passed: Whether tests passed
        style: Badge visual style
        label: Label text

    Returns:
        Badge instance
    """
    return Badge(
        label=label,
        message="passing" if passed else "failing",
        color=get_status_color(passed),
        style=style,
    )


def security_badge(
    rating: str,
    *,
    style: BadgeStyle = BadgeStyle.FLAT,
    label: str = "security",
) -> Badge:
    """Create a security rating badge.

    Args:
        rating: Security rating (A, B, C, D, F)
        style: Badge visual style
        label: Label text

    Returns:
        Badge instance
    """
    colors = {
        "A": BadgeColor.BRIGHTGREEN.value,
        "B": BadgeColor.GREEN.value,
        "C": BadgeColor.YELLOW.value,
        "D": BadgeColor.ORANGE.value,
        "F": BadgeColor.RED.value,
    }
    return Badge(
        label=label,
        message=rating.upper(),
        color=colors.get(rating.upper(), BadgeColor.GREY.value),
        style=style,
    )


def coverage_badge(
    coverage: float,
    *,
    style: BadgeStyle = BadgeStyle.FLAT,
    label: str = "coverage",
) -> Badge:
    """Create a coverage percentage badge.

    Args:
        coverage: Coverage percentage (0.0 to 100.0)
        style: Badge visual style
        label: Label text

    Returns:
        Badge instance
    """
    # Normalize to 0-1 range for color calculation
    normalized = coverage / 100.0 if coverage > 1 else coverage
    return Badge(
        label=label,
        message=f"{int(coverage if coverage > 1 else coverage * 100)}%",
        color=get_reliability_color(normalized),
        style=style,
    )


def custom_badge(
    label: str,
    message: str,
    color: str = BadgeColor.BLUE.value,
    *,
    style: BadgeStyle = BadgeStyle.FLAT,
) -> Badge:
    """Create a custom badge.

    Args:
        label: Label text
        message: Message text
        color: Hex color code
        style: Badge visual style

    Returns:
        Badge instance
    """
    return Badge(
        label=label,
        message=message,
        color=color,
        style=style,
    )


def generate_badges_from_results(
    results: dict[str, Any],
    output_dir: str = ".",
    *,
    style: BadgeStyle = BadgeStyle.FLAT,
) -> dict[str, str]:
    """Generate all badges from test results.

    Args:
        results: Khaos test results dictionary
        output_dir: Directory to write badge SVGs
        style: Badge visual style

    Returns:
        Dictionary mapping badge names to file paths
    """
    from pathlib import Path

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    badges = {}

    # Reliability badge
    reliability = results.get("reliability_score", 0.0)
    badge = reliability_badge(reliability, style=style)
    path = output_path / "khaos-reliability.svg"
    path.write_text(badge.to_svg())
    badges["reliability"] = str(path)

    # Status badge
    passed = results.get("passed_runs", 0) == results.get("total_runs", 1)
    badge = status_badge(passed, style=style)
    path = output_path / "khaos-status.svg"
    path.write_text(badge.to_svg())
    badges["status"] = str(path)

    # Security badge if available
    security_rating = results.get("security_rating")
    if security_rating:
        badge = security_badge(security_rating, style=style)
        path = output_path / "khaos-security.svg"
        path.write_text(badge.to_svg())
        badges["security"] = str(path)

    return badges


def shields_io_url(
    label: str,
    message: str,
    color: str,
    *,
    style: str = "flat",
) -> str:
    """Generate shields.io badge URL.

    For when you prefer to use shields.io instead of local SVGs.

    Args:
        label: Label text
        message: Message text
        color: Color name or hex code
        style: Badge style

    Returns:
        shields.io URL
    """
    import urllib.parse

    # Escape special characters
    label = urllib.parse.quote(label.replace("-", "--").replace("_", "__"))
    message = urllib.parse.quote(message.replace("-", "--").replace("_", "__"))

    # Remove # from hex colors
    if color.startswith("#"):
        color = color[1:]

    return f"https://img.shields.io/badge/{label}-{message}-{color}?style={style}"


def reliability_shields_url(score: float, *, style: str = "flat") -> str:
    """Generate shields.io URL for reliability badge.

    Args:
        score: Reliability score (0.0 to 1.0)
        style: Badge style

    Returns:
        shields.io URL
    """
    percentage = int(score * 100)
    color = get_reliability_color(score)[1:]  # Remove #
    return f"https://img.shields.io/badge/reliability-{percentage}%25-{color}?style={style}"
