"""Transport registry utilities for dynamic adapter selection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Callable

from .base import AgentTransport

TransportBuilder = Callable[["TransportContext", dict[str, Any]], AgentTransport]

@dataclass
class TransportContext:
    """Context shared with transport builders."""

    run_id: str
    target: str
    python_path: str
    working_dir: Path
    env: dict[str, str]
    stderr_path: Path | None
    llm_event_path: Path | None = None
    llm_content_mode: str | None = None

class TransportRegistry:
    """Simple registry that maps names to builder functions."""

    def __init__(self) -> None:
        self._builders: dict[str, TransportBuilder] = {}

    def register(self, name: str, builder: TransportBuilder) -> None:
        key = name.lower().strip()
        self._builders[key] = builder

    def create(
        self,
        name: str,
        context: TransportContext,
        options: dict[str, Any] | None = None,
    ) -> AgentTransport:
        key = name.lower().strip()
        if key not in self._builders:
            raise ValueError(f"Unknown transport '{name}'. Registered: {', '.join(self._builders)}")
        builder = self._builders[key]
        return builder(context, options or {})

_DEFAULT_REGISTRY = TransportRegistry()

def register_transport(name: str, builder: TransportBuilder) -> None:
    _DEFAULT_REGISTRY.register(name, builder)

def get_transport_registry() -> TransportRegistry:
    return _DEFAULT_REGISTRY

def create_transport(
    name: str,
    context: TransportContext,
    options: dict[str, Any] | None = None,
) -> AgentTransport:
    return _DEFAULT_REGISTRY.create(name, context, options)
