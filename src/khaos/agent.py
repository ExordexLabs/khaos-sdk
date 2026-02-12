"""Agent discovery utilities and the public @khaosagent decorator."""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from .state import get_state_dir

# Backward-compatible constant (evaluated at import); dynamic helpers below honor KHAOS_STATE_DIR/HOME at call time.
STATE_DIR = get_state_dir()

def _get_registry_path() -> Path:
    """Resolve the agent registry file path from environment or default."""
    env_path = os.environ.get("KHAOS_AGENT_REGISTRY")
    if env_path:
        return Path(env_path).expanduser()
    return Path.home() / ".khaos" / "agents.json"

class AgentCategory(str, Enum):
    """Canonical agent taxonomy supported by discovery."""

    LLM_INFERENCE = "llm_inference"
    TOOL_AGENT = "tool_agent"
    ORCHESTRATED = "orchestrated"
    WORKFLOW = "workflow"
    MULTIMODAL = "multimodal"
    CUSTOM = "custom"

class AgentCapability(str, Enum):
    """Capability flags surfaced when discovering agents.

    These match the TypeScript AgentCapability type in the dashboard.
    """

    TOOL_CALLING = "tool-calling"
    MCP = "mcp"
    ORCHESTRATION = "orchestration"
    WORKFLOW = "workflow"
    MULTIMODAL_IO = "multimodal-io"
    STATEFUL = "stateful"
    STREAMING = "streaming"
    CUSTOM_RUNTIME = "custom-runtime"

@dataclass(frozen=True)
class DetectionSignal:
    """Documented heuristic describing how we detect an agent class."""

    id: str
    category: AgentCategory
    description: str
    imports: tuple[str, ...] = ()
    file_globs: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()

CATEGORY_DETECTION_MATRIX: dict[AgentCategory, tuple[DetectionSignal, ...]] = {
    AgentCategory.LLM_INFERENCE: (
        DetectionSignal(
            id="openai-api",
            category=AgentCategory.LLM_INFERENCE,
            description="OpenAI client usage (chat/completions/responses)",
            imports=("openai",),
            keywords=("client.chat.completions", "client.responses.create", "OpenAI("),
        ),
        DetectionSignal(
            id="anthropic-api",
            category=AgentCategory.LLM_INFERENCE,
            description="Anthropic Messages API",
            imports=("anthropic",),
            keywords=("messages.create", "claude"),
        ),
        DetectionSignal(
            id="local-llm-server",
            category=AgentCategory.LLM_INFERENCE,
            description="Local inference endpoints such as vLLM/Ollama",
            keywords=("/v1/completions", "ollama", "LMStudio"),
        ),
    ),
    AgentCategory.TOOL_AGENT: (
        DetectionSignal(
            id="function-calling",
            category=AgentCategory.TOOL_AGENT,
            description="LLM function/tool calling via JSON schema",
            keywords=("tool_calls", "function_call", "tools=", "functions="),
        ),
        DetectionSignal(
            id="mcp-schema",
            category=AgentCategory.TOOL_AGENT,
            description="MCP server/host configuration",
            imports=("mcp",),
            keywords=("MCP_SERVER", "KHAOS_MCP_PROXY_SERVER"),
        ),
    ),
    AgentCategory.ORCHESTRATED: (
        DetectionSignal(
            id="langgraph",
            category=AgentCategory.ORCHESTRATED,
            description="LangGraph graph definitions",
            imports=("langgraph",),
            keywords=("StateGraph", "Workflow"),
        ),
        DetectionSignal(
            id="crewai",
            category=AgentCategory.ORCHESTRATED,
            description="CrewAI crew/task orchestration",
            imports=("crewai",),
            keywords=("Crew(", "Agent(", "Task("),
        ),
        DetectionSignal(
            id="autogen",
            category=AgentCategory.ORCHESTRATED,
            description="AutoGen agent ecosystems",
            imports=("autogen",),
            keywords=("AssistantAgent", "UserProxyAgent"),
        ),
    ),
    AgentCategory.WORKFLOW: (
        DetectionSignal(
            id="airflow-dag",
            category=AgentCategory.WORKFLOW,
            description="Airflow DAGs with LLM/tool nodes",
            imports=("airflow",),
            keywords=("DAG(", "@dag"),
        ),
        DetectionSignal(
            id="prefect-flow",
            category=AgentCategory.WORKFLOW,
            description="Prefect flows calling LLMs/tools",
            imports=("prefect",),
            keywords=("@flow", "Flow("),
        ),
        DetectionSignal(
            id="dagster-job",
            category=AgentCategory.WORKFLOW,
            description="Dagster job definitions with agent nodes",
            imports=("dagster",),
            keywords=("@job", "GraphDefinition"),
        ),
    ),
    AgentCategory.MULTIMODAL: (
        DetectionSignal(
            id="vision-model",
            category=AgentCategory.MULTIMODAL,
            description="Multimodal calls (images/audio/video)",
            keywords=("gpt-4o", "vision", "audio", "image_url", "multimodal"),
        ),
        DetectionSignal(
            id="media-preprocess",
            category=AgentCategory.MULTIMODAL,
            description="Local media preprocessing for agents",
            imports=("PIL", "cv2", "pydub"),
        ),
    ),
    AgentCategory.CUSTOM: (
        DetectionSignal(
            id="khaos-decorator",
            category=AgentCategory.CUSTOM,
            description="@khaosagent decorator on custom runtimes",
            keywords=("@khaosagent", "__khaos_agent_config__"),
        ),
        DetectionSignal(
            id="custom-runner",
            category=AgentCategory.CUSTOM,
            description="User-defined state machines or runner classes",
            keywords=("AgentRunner", "StateMachine", "OrdoAgent"),
        ),
    ),
}

def iter_detection_signals(
    category: AgentCategory | None = None,
) -> list[DetectionSignal]:
    """Return detection heuristics for the requested category."""

    if category is not None:
        return list(CATEGORY_DETECTION_MATRIX.get(category, ()))
    signals: list[DetectionSignal] = []
    for entries in CATEGORY_DETECTION_MATRIX.values():
        signals.extend(entries)
    return signals

@dataclass(slots=True)
class AgentMetadata:
    """Normalized metadata describing an agent entrypoint."""

    name: str
    version: str
    code_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)
    entrypoint: str = ""  # File path to the agent
    function_name: str = ""  # Function/class name for multi-agent files
    description: str = ""  # Human-readable description
    framework: str | None = None
    discovered_at: str | None = None
    last_run_at: str | None = None
    category: AgentCategory | None = None
    capabilities: list[str] = field(default_factory=list)
    detection_source: str | None = None
    confidence: float | None = None
    signals: list[str] = field(default_factory=list)
    # Tool and security metadata (for playground and dashboard)
    tools: list[dict[str, Any]] = field(default_factory=list)
    security_mode: str = "agent_input"  # "agent_input" | "llm"
    mcp_servers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "code_hash": self.code_hash,
            "metadata": self.metadata,
            "entrypoint": self.entrypoint,
            "function_name": self.function_name,
            "description": self.description,
            "framework": self.framework,
            "discovered_at": self.discovered_at,
            "last_run_at": self.last_run_at,
            "category": self.category.value if isinstance(self.category, AgentCategory) else self.category,
            "capabilities": list(self.capabilities),
            "detection_source": self.detection_source,
            "confidence": self.confidence,
            "signals": list(self.signals),
            "tools": list(self.tools),
            "security_mode": self.security_mode,
            "mcp_servers": list(self.mcp_servers),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AgentMetadata":
        category_value = payload.get("category")
        category: AgentCategory | None
        if category_value in AgentCategory._value2member_map_:
            category = AgentCategory(category_value)
        else:
            category = None
        return cls(
            name=str(payload.get("name", "agent")),
            version=str(payload.get("version", "0.0.0")),
            code_hash=str(payload.get("code_hash", "")),
            metadata=dict(payload.get("metadata", {})),
            entrypoint=str(payload.get("entrypoint", "")),
            function_name=str(payload.get("function_name", "")),
            description=str(payload.get("description", "")),
            framework=payload.get("framework"),
            discovered_at=payload.get("discovered_at"),
            last_run_at=payload.get("last_run_at"),
            category=category,
            capabilities=[str(cap) for cap in payload.get("capabilities", [])],
            detection_source=payload.get("detection_source"),
            confidence=payload.get("confidence"),
            signals=[str(sig) for sig in payload.get("signals", [])],
            tools=list(payload.get("tools", [])),
            security_mode=str(payload.get("security_mode", "agent_input")),
            mcp_servers=[str(s) for s in payload.get("mcp_servers", [])],
        )

# ---------------------------------------------------------------------------
# Decorator - re-export from agent_sdk for backwards compatibility
# ---------------------------------------------------------------------------

# Import the unified decorator from agent_sdk
from .agent_sdk import khaosagent as _unified_khaosagent

# Re-export the unified decorator - this is now the canonical import location
# Both `from khaos.agent import khaosagent` and `from khaos import khaosagent` work
khaosagent = _unified_khaosagent

# ---------------------------------------------------------------------------
# Discovery & registry helpers
# ---------------------------------------------------------------------------

def discover_agent_metadata(entrypoint: Path) -> AgentMetadata:
    """Return metadata for the supplied entrypoint, honoring decorators/fallbacks."""

    entrypoint = entrypoint.expanduser().resolve()
    if not entrypoint.exists():
        raise FileNotFoundError(entrypoint)

    decorator_config = _parse_decorator(entrypoint)
    metadata = _build_metadata_from_config(decorator_config)
    category_value = metadata.pop("category", None)
    category = _coerce_category(category_value)
    capabilities_value = metadata.pop("capabilities", None)
    capabilities = _coerce_capabilities(capabilities_value)
    code_hash = calculate_code_hash(entrypoint)
    name = metadata.pop("name", None) or _slugify(entrypoint.stem)
    version = metadata.pop("version", None) or _detect_version(entrypoint)
    framework = (metadata.pop("framework", None) or "").strip().lower() or None

    # Extract tool, security, and MCP metadata
    tools = metadata.pop("tools", [])
    if not isinstance(tools, list):
        tools = []
    security_mode = str(metadata.pop("security_mode", "agent_input"))
    mcp_servers = metadata.pop("mcp_servers", [])
    if not isinstance(mcp_servers, list):
        mcp_servers = []

    sanitized_meta = _sanitize_metadata(metadata)
    strict_contract = sanitized_meta.pop("strict_contract", None)
    if strict_contract is None:
        # Alias for convenience: allow `contract=True` in decorator metadata.
        strict_contract = sanitized_meta.pop("contract", None)
    now = _iso_timestamp()

    existing = _lookup_agent(name, version, code_hash)
    discovered_at = existing.discovered_at if existing else now
    last_run_at = existing.last_run_at if existing else None

    agent = AgentMetadata(
        name=name,
        version=version,
        code_hash=code_hash,
        metadata=sanitized_meta,
        entrypoint=str(entrypoint),
        framework=framework,
        discovered_at=discovered_at,
        last_run_at=last_run_at,
        category=category,
        capabilities=capabilities,
        tools=tools,
        security_mode=security_mode,
        mcp_servers=mcp_servers,
    )
    if strict_contract is not None:
        agent.metadata["strict_contract"] = bool(strict_contract)
    return agent

def record_agent_run(agent: AgentMetadata) -> AgentMetadata:
    """Persist/refresh agent metadata after a successful run."""

    now = _iso_timestamp()
    if not agent.discovered_at:
        agent.discovered_at = now
    agent.last_run_at = now
    _upsert_agent(agent)
    return agent

def register_discovered_agent(agent: AgentMetadata) -> AgentMetadata:
    """Persist metadata for a discovered agent without marking a run."""

    if not agent.discovered_at:
        agent.discovered_at = _iso_timestamp()
    _upsert_agent(agent)
    return agent

def list_local_agents() -> list[AgentMetadata]:
    return [_to_agent(entry) for entry in _load_registry().get("agents", [])]

def load_registry_discovery_rules() -> dict[str, list[str]]:
    registry = _load_registry()
    discovery = registry.get("discovery") or {}
    rules: dict[str, list[str]] = {}
    include = discovery.get("include")
    if isinstance(include, list):
        rules["include"] = [str(item) for item in include]
    exclude = discovery.get("exclude_dirs")
    if isinstance(exclude, list):
        rules["exclude_dirs"] = [str(item) for item in exclude]
    return rules

def update_registry_discovery_rules(rules: dict[str, list[str]]) -> None:
    registry = _load_registry()
    registry["discovery"] = {
        "include": [str(item) for item in rules.get("include", [])],
        "exclude_dirs": [str(item) for item in rules.get("exclude_dirs", [])],
    }
    _save_registry(registry)

def find_agent_record(name: str, version: str | None = None) -> list[AgentMetadata]:
    matches: list[AgentMetadata] = []
    for agent in list_local_agents():
        if agent.name != name:
            continue
        if version is not None and agent.version != version:
            continue
        matches.append(agent)
    return matches

def find_agent_by_name(name: str) -> list[AgentMetadata]:
    """Find all registered agents matching name (any version).

    This is the primary lookup function for `khaos run <name>`.
    Returns all agents with the given name, sorted by most recent first.
    """
    matches = find_agent_record(name)
    # Sort by discovered_at descending (most recent first)
    return sorted(
        matches,
        key=lambda a: a.discovered_at or "",
        reverse=True,
    )

def discover_agents_in_file(file_path: Path) -> list[AgentMetadata]:
    """Discover ALL @khaosagent decorated functions/classes in a file.

    Supports multi-agent files where multiple decorators exist.
    Returns one AgentMetadata per decorated entity.
    """
    file_path = file_path.expanduser().resolve()
    if not file_path.exists():
        raise FileNotFoundError(file_path)

    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []

    agents: list[AgentMetadata] = []

    class _MultiAgentVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            config = self._extract_decorator_config(node.decorator_list)
            if config is not None:
                agents.append(self._build_agent(node.name, config))
            self.generic_visit(node)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            config = self._extract_decorator_config(node.decorator_list)
            if config is not None:
                agents.append(self._build_agent(node.name, config))
            self.generic_visit(node)

        def _extract_decorator_config(self, decorators: list[ast.expr]) -> dict[str, Any] | None:
            for decorator in decorators:
                if not isinstance(decorator, ast.Call):
                    # Handle @khaosagent without parens
                    if _is_khaosagent_call(decorator):
                        return {}
                    continue
                if not _is_khaosagent_call(decorator.func):
                    continue
                config: dict[str, Any] = {}
                for keyword in decorator.keywords:
                    if keyword.arg is None:
                        continue
                    try:
                        value = ast.literal_eval(keyword.value)
                    except Exception:
                        continue
                    config[keyword.arg] = value
                return config
            return None

        def _build_agent(self, func_name: str, config: dict[str, Any]) -> AgentMetadata:
            metadata = _build_metadata_from_config(config)
            category_value = metadata.pop("category", None)
            category = _coerce_category(category_value)
            capabilities_value = metadata.pop("capabilities", None)
            capabilities = _coerce_capabilities(capabilities_value)
            code_hash = calculate_code_hash(file_path)
            name = metadata.pop("name", None) or _slugify(func_name)
            version = metadata.pop("version", None) or _detect_version(file_path)
            description = metadata.pop("description", "") or ""
            framework = (metadata.pop("framework", None) or "").strip().lower() or None

            sanitized_meta = _sanitize_metadata(metadata)
            now = _iso_timestamp()

            existing = _lookup_agent(name, version, code_hash)
            discovered_at = existing.discovered_at if existing else now
            last_run_at = existing.last_run_at if existing else None

            return AgentMetadata(
                name=name,
                version=version,
                code_hash=code_hash,
                metadata=sanitized_meta,
                entrypoint=str(file_path),
                function_name=func_name,
                description=description,
                framework=framework,
                discovered_at=discovered_at,
                last_run_at=last_run_at,
                category=category,
                capabilities=capabilities,
            )

    visitor = _MultiAgentVisitor()
    visitor.visit(tree)
    return agents

def calculate_code_hash(entrypoint: Path) -> str:
    """Generate a stable hash for the entrypoint, ignoring comments/docstrings."""

    try:
        source = entrypoint.read_text(encoding="utf-8")
    except OSError:
        return ""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ""

    _strip_docstrings(tree)
    try:
        normalized = ast.unparse(tree)
    except AttributeError:  # pragma: no cover - defensive
        normalized = source

    lines = [line.strip() for line in normalized.splitlines() if line.strip()]
    canonical = "\n".join(lines)
    return _hash_string(canonical)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash_string(payload: str) -> str:
    import hashlib

    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def _strip_docstrings(node: ast.AST) -> None:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            if child.body and isinstance(child.body[0], ast.Expr):
                value = child.body[0].value
                if isinstance(value, (ast.Str, ast.Constant)) and isinstance(getattr(value, "value", None), str):
                    child.body = child.body[1:]
        _strip_docstrings(child)

def _parse_decorator(entrypoint: Path) -> dict[str, Any] | None:
    try:
        tree = ast.parse(entrypoint.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return None

    class _Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.result: dict[str, Any] | None = None

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
            if self.result is None:
                self.result = self._extract(node.decorator_list)
            # Continue walking in case decorators on nested nodes exist
            self.generic_visit(node)

        visit_ClassDef = visit_FunctionDef

        def _extract(self, decorators: Iterable[ast.expr]) -> dict[str, Any] | None:
            for decorator in decorators:
                if not isinstance(decorator, ast.Call):
                    continue
                if not _is_khaosagent_call(decorator.func):
                    continue
                config: dict[str, Any] = {}
                for keyword in decorator.keywords:
                    if keyword.arg is None:
                        continue
                    try:
                        value = ast.literal_eval(keyword.value)
                    except Exception as exc:
                        raise ValueError(
                            f"@khaosagent argument '{keyword.arg}' must be a literal value"
                        ) from exc
                    config[keyword.arg] = value
                return config
            return None

    visitor = _Visitor()
    visitor.visit(tree)
    return visitor.result

def _is_khaosagent_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and node.id == "khaosagent":
        return True
    if isinstance(node, ast.Attribute) and node.attr == "khaosagent":
        if isinstance(node.value, ast.Name) and node.value.id == "khaos":
            return True
    return False

def _build_metadata_from_config(config: dict[str, Any] | None) -> dict[str, Any]:
    if not config:
        return {}
    merged = dict(config)
    inner_metadata = merged.pop("metadata", None)
    if isinstance(inner_metadata, dict):
        merged.update(inner_metadata)
    return merged

def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-")
    return slug.lower() or "agent"

def _coerce_category(value: Any) -> AgentCategory | None:
    if value is None:
        return None
    if isinstance(value, AgentCategory):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower().replace(" ", "-")
        if normalized in AgentCategory._value2member_map_:
            return AgentCategory(normalized)
    return None

def _coerce_capabilities(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = [value]
    elif isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    else:
        raw_items = [value]
    capabilities: list[str] = []
    for item in raw_items:
        if isinstance(item, AgentCapability):
            capabilities.append(item.value)
        elif isinstance(item, str):
            normalized = item.strip()
            if not normalized:
                continue
            lower = normalized.lower()
            if lower in AgentCapability._value2member_map_:
                capabilities.append(AgentCapability(lower).value)
            else:
                capabilities.append(normalized)
    return capabilities

def _detect_version(entrypoint: Path) -> str:
    git_dir = entrypoint.parent
    tag = _run_git(git_dir, ["describe", "--tags", "--exact-match", "HEAD"])
    if tag:
        return tag
    commit = _run_git(git_dir, ["rev-parse", "--short", "HEAD"])
    if commit:
        return commit
    return "0.0.0-dev"

def _run_git(directory: Path, args: list[str]) -> str | None:
    command = ["git", "-C", str(directory)] + args
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    output = result.stdout.strip()
    return output or None

def _sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    def _coerce(value: Any) -> Any:
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, dict):
            return {str(k): _coerce(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [_coerce(item) for item in value]
        return str(value)

    return {str(key): _coerce(val) for key, val in metadata.items()}

def _lookup_agent(name: str, version: str, code_hash: str) -> AgentMetadata | None:
    key = (name, version, code_hash)
    for entry in _load_registry().get("agents", []):
        if (entry.get("name"), entry.get("version"), entry.get("code_hash")) == key:
            return AgentMetadata.from_dict(entry)
    return None

def _upsert_agent(agent: AgentMetadata) -> None:
    registry = _load_registry()
    agents = registry.setdefault("agents", [])
    key = (agent.name, agent.version, agent.code_hash)
    updated = False
    for index, entry in enumerate(agents):
        existing_key = (entry.get("name"), entry.get("version"), entry.get("code_hash"))
        if existing_key == key:
            agents[index] = agent.to_dict()
            updated = True
            break
    if not updated:
        agents.append(agent.to_dict())
    _save_registry(registry)

def _load_registry() -> dict[str, Any]:
    path = _get_registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        return {"agents": [], "discovery": {}}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("agents", [])
    data.setdefault("discovery", {})
    return data

def _save_registry(payload: dict[str, Any]) -> None:
    path = _get_registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

def _to_agent(entry: dict[str, Any]) -> AgentMetadata:
    return AgentMetadata.from_dict(entry)

def _iso_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()

__all__ = [
    "AgentCategory",
    "AgentCapability",
    "AgentMetadata",
    "DetectionSignal",
    "iter_detection_signals",
    "discover_agent_metadata",
    "discover_agents_in_file",
    "record_agent_run",
    "register_discovered_agent",
    "list_local_agents",
    "find_agent_record",
    "find_agent_by_name",
    "calculate_code_hash",
    "khaosagent",
    "STATE_DIR",
    "load_registry_discovery_rules",
    "update_registry_discovery_rules",
]
