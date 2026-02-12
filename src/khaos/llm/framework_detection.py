"""Framework auto-detection for Khaos LLM shim.

Detects which AI framework is being used by an agent and provides
framework-specific configuration hints.

The key insight: Khaos patches at the SDK level (OpenAI/Anthropic),
so all frameworks using these SDKs are automatically supported.
Framework detection is primarily for:
1. Better logging/debugging
2. Framework-specific telemetry enrichment
3. Compatibility reporting
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Framework(Enum):
    """Supported AI frameworks."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LANGCHAIN = "langchain"
    CREWAI = "crewai"
    AUTOGEN = "autogen"
    LLAMAINDEX = "llamaindex"
    INSTRUCTOR = "instructor"
    UNKNOWN = "unknown"


@dataclass
class FrameworkInfo:
    """Information about a detected framework."""

    name: Framework
    version: str | None
    sdk: str | None  # Underlying SDK (openai, anthropic)
    compatible: bool
    notes: str | None = None


@dataclass
class DetectionResult:
    """Result of framework detection."""

    primary: Framework
    frameworks: list[FrameworkInfo] = field(default_factory=list)
    sdk_used: list[str] = field(default_factory=list)

    @property
    def is_compatible(self) -> bool:
        """Check if all detected frameworks are compatible."""
        return all(f.compatible for f in self.frameworks)

    def summary(self) -> str:
        """Get a human-readable summary."""
        if not self.frameworks:
            return "No AI frameworks detected"

        names = [f.name.value for f in self.frameworks]
        return f"Detected: {', '.join(names)} (SDKs: {', '.join(self.sdk_used)})"


def _get_module_version(module_name: str) -> str | None:
    """Get version of an imported module."""
    try:
        mod = sys.modules.get(module_name)
        if mod:
            return getattr(mod, "__version__", None)
    except Exception:
        pass
    return None


def _is_module_imported(module_name: str) -> bool:
    """Check if a module is imported."""
    # Check direct import
    if module_name in sys.modules:
        return True
    # Check submodule imports
    prefix = f"{module_name}."
    return any(k.startswith(prefix) for k in sys.modules)


def detect_openai() -> FrameworkInfo | None:
    """Detect OpenAI SDK."""
    if not _is_module_imported("openai"):
        return None

    return FrameworkInfo(
        name=Framework.OPENAI,
        version=_get_module_version("openai"),
        sdk="openai",
        compatible=True,
        notes="Direct OpenAI SDK usage",
    )


def detect_anthropic() -> FrameworkInfo | None:
    """Detect Anthropic SDK."""
    if not _is_module_imported("anthropic"):
        return None

    return FrameworkInfo(
        name=Framework.ANTHROPIC,
        version=_get_module_version("anthropic"),
        sdk="anthropic",
        compatible=True,
        notes="Direct Anthropic SDK usage",
    )


def detect_langchain() -> FrameworkInfo | None:
    """Detect LangChain framework."""
    if not any(
        _is_module_imported(m)
        for m in ["langchain", "langchain_core", "langchain_openai", "langchain_anthropic"]
    ):
        return None

    # Determine which SDK LangChain is using
    sdk = None
    if _is_module_imported("langchain_openai"):
        sdk = "openai"
    elif _is_module_imported("langchain_anthropic"):
        sdk = "anthropic"

    return FrameworkInfo(
        name=Framework.LANGCHAIN,
        version=_get_module_version("langchain"),
        sdk=sdk,
        compatible=True,
        notes="LangChain uses OpenAI/Anthropic SDK - fully compatible",
    )


def detect_crewai() -> FrameworkInfo | None:
    """Detect CrewAI framework."""
    if not _is_module_imported("crewai"):
        return None

    return FrameworkInfo(
        name=Framework.CREWAI,
        version=_get_module_version("crewai"),
        sdk="openai",  # CrewAI primarily uses OpenAI
        compatible=True,
        notes="CrewAI uses OpenAI SDK for agent LLM calls",
    )


def detect_autogen() -> FrameworkInfo | None:
    """Detect Microsoft AutoGen framework."""
    if not any(
        _is_module_imported(m)
        for m in ["autogen", "autogen_core", "autogen_agentchat"]
    ):
        return None

    return FrameworkInfo(
        name=Framework.AUTOGEN,
        version=_get_module_version("autogen"),
        sdk="openai",  # AutoGen uses OpenAI SDK
        compatible=True,
        notes="AutoGen uses OpenAI SDK for agent conversations",
    )


def detect_llamaindex() -> FrameworkInfo | None:
    """Detect LlamaIndex framework."""
    if not any(
        _is_module_imported(m)
        for m in ["llama_index", "llama_index.core", "llama_index.llms"]
    ):
        return None

    # Determine which SDK LlamaIndex is using
    sdk = None
    if _is_module_imported("llama_index.llms.openai"):
        sdk = "openai"
    elif _is_module_imported("llama_index.llms.anthropic"):
        sdk = "anthropic"

    return FrameworkInfo(
        name=Framework.LLAMAINDEX,
        version=_get_module_version("llama_index"),
        sdk=sdk,
        compatible=True,
        notes="LlamaIndex uses OpenAI/Anthropic SDK for LLM calls",
    )


def detect_instructor() -> FrameworkInfo | None:
    """Detect Instructor library."""
    if not _is_module_imported("instructor"):
        return None

    return FrameworkInfo(
        name=Framework.INSTRUCTOR,
        version=_get_module_version("instructor"),
        sdk="openai",  # Instructor wraps OpenAI client
        compatible=True,
        notes="Instructor wraps OpenAI client - fully compatible",
    )


def detect_frameworks() -> DetectionResult:
    """Detect all frameworks in use.

    Returns:
        DetectionResult with all detected frameworks and SDKs
    """
    detectors = [
        detect_openai,
        detect_anthropic,
        detect_langchain,
        detect_crewai,
        detect_autogen,
        detect_llamaindex,
        detect_instructor,
    ]

    frameworks = []
    sdk_used = set()

    for detector in detectors:
        info = detector()
        if info:
            frameworks.append(info)
            if info.sdk:
                sdk_used.add(info.sdk)

    # Determine primary framework (prefer higher-level frameworks)
    primary = Framework.UNKNOWN
    priority = [
        Framework.LANGCHAIN,
        Framework.CREWAI,
        Framework.AUTOGEN,
        Framework.LLAMAINDEX,
        Framework.INSTRUCTOR,
        Framework.OPENAI,
        Framework.ANTHROPIC,
    ]

    detected_names = {f.name for f in frameworks}
    for fw in priority:
        if fw in detected_names:
            primary = fw
            break

    return DetectionResult(
        primary=primary,
        frameworks=frameworks,
        sdk_used=sorted(sdk_used),
    )


def get_framework_metadata() -> dict[str, Any]:
    """Get framework detection result as metadata dict.

    Useful for enriching telemetry with framework context.
    """
    result = detect_frameworks()

    return {
        "primary_framework": result.primary.value,
        "frameworks": [
            {
                "name": f.name.value,
                "version": f.version,
                "sdk": f.sdk,
                "compatible": f.compatible,
            }
            for f in result.frameworks
        ],
        "sdk_used": result.sdk_used,
        "compatible": result.is_compatible,
    }


# Compatibility matrix for documentation
COMPATIBILITY_MATRIX = {
    "langchain": {
        "supported": True,
        "min_version": "0.1.0",
        "notes": "Uses OpenAI/Anthropic SDK - automatic telemetry capture",
        "tested_with": ["0.1.x", "0.2.x"],
    },
    "crewai": {
        "supported": True,
        "min_version": "0.1.0",
        "notes": "Multi-agent orchestration captured via OpenAI SDK patching",
        "tested_with": ["0.1.x"],
    },
    "autogen": {
        "supported": True,
        "min_version": "0.2.0",
        "notes": "Agent conversations captured via OpenAI SDK patching",
        "tested_with": ["0.2.x", "0.4.x"],
    },
    "llamaindex": {
        "supported": True,
        "min_version": "0.10.0",
        "notes": "RAG pipelines captured via OpenAI/Anthropic SDK patching",
        "tested_with": ["0.10.x", "0.11.x"],
    },
    "instructor": {
        "supported": True,
        "min_version": "0.3.0",
        "notes": "Structured outputs captured including tool calls",
        "tested_with": ["0.3.x", "1.x"],
    },
    "openai": {
        "supported": True,
        "min_version": "1.0.0",
        "notes": "Direct SDK patching for chat completions (sync and async)",
        "tested_with": ["1.0.x", "1.x"],
    },
    "anthropic": {
        "supported": True,
        "min_version": "0.18.0",
        "notes": "Direct SDK patching for messages (sync and async)",
        "tested_with": ["0.18.x", "0.x"],
    },
}


def get_compatibility_matrix() -> dict[str, dict[str, Any]]:
    """Get the full compatibility matrix."""
    return COMPATIBILITY_MATRIX.copy()
