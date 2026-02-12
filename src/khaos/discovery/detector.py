"""Entry point detector using AST analysis.

Detects agent entry points without importing user code.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .patterns import (
    CALLABLE_PATTERNS,
    DetectionPattern,
    PatternType,
    get_all_patterns,
    get_patterns_by_type,
)


class EntryPointType(Enum):
    """Type of detected entry point."""

    DECORATED_FUNCTION = "decorated_function"
    DECORATED_ASYNC_FUNCTION = "decorated_async_function"
    DECORATED_CLASS = "decorated_class"
    FUNCTION = "function"
    ASYNC_FUNCTION = "async_function"
    CLASS = "class"
    CLASS_INSTANCE = "class_instance"  # Variable assigned to class instantiation
    METHOD = "method"


@dataclass
class AgentEntryPoint:
    """A detected agent entry point."""

    name: str
    entry_type: EntryPointType
    line_number: int
    priority: int  # Higher = more confident match

    # For classes
    class_name: str | None = None
    invoke_method: str | None = None

    # Matched pattern
    pattern: DetectionPattern | None = None

    # Additional context
    is_async: bool = False
    decorators: list[str] = field(default_factory=list)
    framework: str | None = None
    signature_params: int = 0  # Number of parameters

    def __repr__(self) -> str:
        parts = [f"{self.entry_type.value}:{self.name}"]
        if self.class_name:
            parts.append(f"class={self.class_name}")
        if self.invoke_method:
            parts.append(f"invoke={self.invoke_method}")
        if self.framework:
            parts.append(f"framework={self.framework}")
        return f"AgentEntryPoint({', '.join(parts)}, priority={self.priority})"


class EntryPointDetector(ast.NodeVisitor):
    """AST visitor that detects agent entry points."""

    def __init__(self, source: str, patterns: list[DetectionPattern]):
        self.source = source
        self.patterns = patterns
        self.entry_points: list[AgentEntryPoint] = []
        self.imports: set[str] = set()
        self.class_bases: dict[str, list[str]] = {}  # class_name -> base class names
        self.variables: dict[str, str] = {}  # var_name -> assigned class/call

    def detect(self) -> list[AgentEntryPoint]:
        """Run detection and return found entry points."""
        try:
            tree = ast.parse(self.source)
        except SyntaxError:
            return []

        # First pass: collect imports and class info
        self._collect_metadata(tree)

        # Second pass: detect entry points
        self.visit(tree)

        # Sort by priority
        self.entry_points.sort(key=lambda e: -e.priority)
        return self.entry_points

    def _collect_metadata(self, tree: ast.AST) -> None:
        """Collect imports and class definitions."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.imports.add(node.module.split(".")[0])
            elif isinstance(node, ast.ClassDef):
                bases = []
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        bases.append(base.id)
                    elif isinstance(base, ast.Attribute):
                        bases.append(base.attr)
                self.class_bases[node.name] = bases
            elif isinstance(node, ast.Assign):
                self._track_assignment(node)

    def _track_assignment(self, node: ast.Assign) -> None:
        """Track variable assignments for framework detection."""
        if len(node.targets) != 1:
            return
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            return

        var_name = target.id
        class_name = None
        lineno = node.lineno

        # Track what's being assigned
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name):
                class_name = node.value.func.id
            elif isinstance(node.value.func, ast.Attribute):
                class_name = node.value.func.attr

        if class_name:
            self.variables[var_name] = class_name

            # Check for framework patterns
            self._check_variable_pattern(var_name, class_name, lineno)

    def _check_variable_pattern(self, var_name: str, class_name: str, lineno: int) -> None:
        """Check if a variable assignment matches a framework pattern."""
        # Known framework class instantiations
        framework_classes = {
            # CrewAI
            "Crew": ("crewai", "kickoff", 85),
            # LangGraph
            "StateGraph": ("langgraph", "compile", 80),
            "Graph": ("langgraph", "compile", 75),
            # AutoGen
            "AssistantAgent": ("autogen", "initiate_chat", 80),
            "UserProxyAgent": ("autogen", "initiate_chat", 80),
            "ConversableAgent": ("autogen", "initiate_chat", 75),
            # LlamaIndex
            "QueryEngine": ("llamaindex", "query", 80),
            "ChatEngine": ("llamaindex", "chat", 80),
            "VectorStoreIndex": ("llamaindex", "as_query_engine", 75),
        }

        if class_name in framework_classes:
            framework, invoke_method, priority = framework_classes[class_name]

            # Check if framework is imported
            framework_imports = {
                "crewai": ("crewai",),
                "langgraph": ("langgraph",),
                "autogen": ("autogen", "pyautogen"),
                "llamaindex": ("llama_index", "llamaindex"),
            }

            required_imports = framework_imports.get(framework, ())
            if any(imp in self.imports for imp in required_imports):
                self.entry_points.append(
                    AgentEntryPoint(
                        name=var_name,
                        entry_type=EntryPointType.CLASS_INSTANCE,
                        line_number=lineno,
                        priority=priority,
                        class_name=class_name,
                        invoke_method=invoke_method,
                        framework=framework,
                    )
                )

    def _get_decorator_names(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> list[str]:
        """Extract decorator names from a node."""
        names = []
        for deco in node.decorator_list:
            if isinstance(deco, ast.Name):
                names.append(deco.id)
            elif isinstance(deco, ast.Attribute):
                # e.g., @khaos.khaos_agent
                names.append(deco.attr)
                if isinstance(deco.value, ast.Name):
                    names.append(f"{deco.value.id}.{deco.attr}")
            elif isinstance(deco, ast.Call):
                # e.g., @khaos_agent(name="foo")
                if isinstance(deco.func, ast.Name):
                    names.append(deco.func.id)
                elif isinstance(deco.func, ast.Attribute):
                    names.append(deco.func.attr)
        return names

    def _count_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
        """Count function parameters (excluding self)."""
        params = len(node.args.args)
        if params > 0 and node.args.args[0].arg == "self":
            params -= 1
        return params

    def _match_decorator_pattern(
        self,
        decorators: list[str],
        is_async: bool,
    ) -> DetectionPattern | None:
        """Check if decorators match any pattern."""
        for pattern in get_patterns_by_type(PatternType.DECORATOR):
            for deco in decorators:
                if deco in pattern.match_decorators:
                    return pattern
        return None

    def _match_function_pattern(
        self,
        name: str,
        is_async: bool,
    ) -> DetectionPattern | None:
        """Check if function name matches any pattern."""
        pattern_type = PatternType.ASYNC_FUNCTION if is_async else PatternType.FUNCTION
        for pattern in get_patterns_by_type(pattern_type):
            if name in pattern.match_names:
                return pattern

        # Also check non-async patterns for async functions
        if is_async:
            for pattern in get_patterns_by_type(PatternType.FUNCTION):
                if name in pattern.match_names:
                    return pattern

        return None

    def _match_class_pattern(
        self,
        name: str,
        bases: list[str],
    ) -> DetectionPattern | None:
        """Check if class matches any pattern."""
        # Check framework patterns
        for pattern in get_patterns_by_type(PatternType.CLASS):
            # Check by base class
            if pattern.match_base_classes:
                for base in bases:
                    if base in pattern.match_base_classes:
                        # Verify imports if required
                        if pattern.match_imports:
                            if any(imp in self.imports for imp in pattern.match_imports):
                                return pattern
                        else:
                            return pattern

            # Check by class name
            if pattern.match_names and name in pattern.match_names:
                return pattern

        return None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit a function definition."""
        self._process_function(node, is_async=False)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit an async function definition."""
        self._process_function(node, is_async=True)
        self.generic_visit(node)

    def _process_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        is_async: bool,
    ) -> None:
        """Process a function/async function definition."""
        decorators = self._get_decorator_names(node)

        # Check for decorator match (highest priority)
        deco_pattern = self._match_decorator_pattern(decorators, is_async)
        if deco_pattern:
            entry_type = (
                EntryPointType.DECORATED_ASYNC_FUNCTION
                if is_async
                else EntryPointType.DECORATED_FUNCTION
            )
            self.entry_points.append(
                AgentEntryPoint(
                    name=node.name,
                    entry_type=entry_type,
                    line_number=node.lineno,
                    priority=deco_pattern.priority,
                    is_async=is_async,
                    decorators=decorators,
                    pattern=deco_pattern,
                    signature_params=self._count_params(node),
                )
            )
            return

        # Check for function name match
        func_pattern = self._match_function_pattern(node.name, is_async)
        if func_pattern:
            entry_type = (
                EntryPointType.ASYNC_FUNCTION if is_async else EntryPointType.FUNCTION
            )
            self.entry_points.append(
                AgentEntryPoint(
                    name=node.name,
                    entry_type=entry_type,
                    line_number=node.lineno,
                    priority=func_pattern.priority,
                    is_async=is_async,
                    decorators=decorators,
                    pattern=func_pattern,
                    signature_params=self._count_params(node),
                )
            )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class definition."""
        decorators = self._get_decorator_names(node)
        bases = self.class_bases.get(node.name, [])

        # Check for decorator match
        deco_pattern = self._match_decorator_pattern(decorators, is_async=False)
        if deco_pattern:
            invoke_method = self._find_invoke_method(node)
            self.entry_points.append(
                AgentEntryPoint(
                    name=node.name,
                    entry_type=EntryPointType.DECORATED_CLASS,
                    line_number=node.lineno,
                    priority=deco_pattern.priority,
                    class_name=node.name,
                    invoke_method=invoke_method,
                    decorators=decorators,
                    pattern=deco_pattern,
                )
            )
            self.generic_visit(node)
            return

        # Check for class pattern match
        class_pattern = self._match_class_pattern(node.name, bases)
        if class_pattern:
            invoke_method = class_pattern.invoke_method or self._find_invoke_method(node)
            self.entry_points.append(
                AgentEntryPoint(
                    name=node.name,
                    entry_type=EntryPointType.CLASS,
                    line_number=node.lineno,
                    priority=class_pattern.priority,
                    class_name=node.name,
                    invoke_method=invoke_method,
                    decorators=decorators,
                    pattern=class_pattern,
                    framework=class_pattern.framework,
                )
            )

        # Also check for callable methods on generic classes
        invoke_method = self._find_invoke_method(node)
        if invoke_method and not class_pattern:
            # Lower priority for generic classes with invoke methods
            self.entry_points.append(
                AgentEntryPoint(
                    name=node.name,
                    entry_type=EntryPointType.CLASS,
                    line_number=node.lineno,
                    priority=20,  # Low priority
                    class_name=node.name,
                    invoke_method=invoke_method,
                    decorators=decorators,
                )
            )

        self.generic_visit(node)

    def _find_invoke_method(self, node: ast.ClassDef) -> str | None:
        """Find the best invoke method on a class."""
        methods: set[str] = set()

        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.add(item.name)

        # Check for callable patterns in priority order
        for method_name in CALLABLE_PATTERNS:
            if method_name in methods:
                return method_name

        return None


def detect_entry_points(
    source: str | Path,
    patterns: list[DetectionPattern] | None = None,
) -> list[AgentEntryPoint]:
    """Detect agent entry points in source code.

    Args:
        source: Python source code string or path to file
        patterns: Optional custom patterns (defaults to all registered)

    Returns:
        List of detected entry points, sorted by priority (highest first)
    """
    if isinstance(source, Path):
        try:
            source = source.read_text(encoding="utf-8")
        except OSError:
            return []

    if patterns is None:
        patterns = get_all_patterns()

    detector = EntryPointDetector(source, patterns)
    return detector.detect()


def select_best_entry_point(
    entry_points: list[AgentEntryPoint],
) -> AgentEntryPoint | None:
    """Select the best entry point from detected candidates.

    Priority order:
    1. Decorated functions/classes (explicit user intent)
    2. Framework-specific patterns
    3. Common function name patterns
    4. Generic class patterns
    """
    if not entry_points:
        return None

    # Already sorted by priority
    return entry_points[0]


