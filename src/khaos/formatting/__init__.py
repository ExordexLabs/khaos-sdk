"""Shared formatting helpers used by both the SDK and CLI.

This module exists so non-CLI code (e.g. `khaos.observe`) can format output
without importing `khaos.cli` (which registers CLI commands at import time).
"""

from .common import format_ratio, format_rate, print_key_rates
from .footer import print_run_footer

__all__ = [
    "format_ratio",
    "format_rate",
    "print_key_rates",
    "print_run_footer",
]

