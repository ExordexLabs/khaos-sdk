"""Logging configuration helpers for Khaos."""

from __future__ import annotations

import logging


from rich.logging import RichHandler
from .ui import console


def configure(verbose: bool = False) -> logging.Logger:
    """Return a configured logger for CLI + runtime usage."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)]
    )
    return logging.getLogger("khaos")
