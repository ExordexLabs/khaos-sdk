"""CLI command modules.

Core commands:
- run: Execute agent with full evaluation (security + resilience)
- discover: Scan and register @khaosagent decorated agents
- compare: Compare two agent runs
- gate: CI/CD gate check with thresholds
- sync: Sync results to cloud dashboard
- scenarios: Browse and manage test scenarios
"""

from .run import run
from .discover import discover
from .compare import compare
from .gate import gate
from .sync import sync
from .scenarios import scenarios_app

__all__ = [
    "run",
    "discover",
    "compare",
    "gate",
    "sync",
    "scenarios_app",
]
