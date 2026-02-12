"""Test discovery, execution engine, and result collection."""

from __future__ import annotations

import concurrent.futures
import importlib
import importlib.util
import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Callable

from khaos.testing.client import AgentTestClient, AgentResponse


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredTest:
    """A single ``@khaostest``-decorated function found during discovery."""

    name: str
    module_path: Path
    fn: Callable[..., Any]
    config: Any  # KhaosTestConfig
    mode: str  # "imperative" | "declarative"


@dataclass
class TestResult:
    """Outcome of executing a single test."""

    name: str
    agent: str
    passed: bool
    duration_ms: float
    error: str | None = None
    traceback: str | None = None


@dataclass
class TestSummary:
    """Aggregate results for a test run."""

    results: list[TestResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def duration_ms(self) -> float:
        return sum(r.duration_ms for r in self.results)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

_DEFAULT_TEST_PATTERNS = ("test_*.py", "*_test.py")
_DEFAULT_TEST_DIRS = ("tests", "test")


def discover_tests(paths: list[Path] | None = None) -> list[DiscoveredTest]:
    """Find all ``@khaostest``-decorated functions.

    If *paths* is ``None``, searches default directories (``tests/``,
    ``test/``) and any ``test_*.py`` files in the current directory.
    """
    if paths is None:
        paths = _default_search_paths()

    candidates: list[Path] = []
    for p in paths:
        if p.is_file() and p.suffix == ".py":
            candidates.append(p)
        elif p.is_dir():
            for pattern in _DEFAULT_TEST_PATTERNS:
                candidates.extend(p.rglob(pattern))

    tests: list[DiscoveredTest] = []
    for filepath in sorted(set(candidates)):
        tests.extend(_extract_tests_from_file(filepath))
    return tests


def _default_search_paths() -> list[Path]:
    cwd = Path.cwd()
    paths: list[Path] = []
    for dirname in _DEFAULT_TEST_DIRS:
        candidate = cwd / dirname
        if candidate.is_dir():
            paths.append(candidate)
    # Also include test_*.py at repo root
    for pattern in _DEFAULT_TEST_PATTERNS:
        paths.extend(cwd.glob(pattern))
    return paths


def _extract_tests_from_file(filepath: Path) -> list[DiscoveredTest]:
    """Import a file and return all @khaostest-decorated functions."""
    module_name = f"_khaos_test_{filepath.stem}_{id(filepath)}"
    spec = importlib.util.spec_from_file_location(module_name, filepath)
    if spec is None or spec.loader is None:
        return []
    module = importlib.util.module_from_spec(spec)
    # Ensure the module's parent directory is on sys.path so relative
    # imports from the test file work.
    parent = str(filepath.parent)
    added = parent not in sys.path
    if added:
        sys.path.insert(0, parent)
    try:
        spec.loader.exec_module(module)
    except Exception:
        return []
    finally:
        if added and parent in sys.path:
            sys.path.remove(parent)

    tests: list[DiscoveredTest] = []
    for attr_name in dir(module):
        obj = getattr(module, attr_name, None)
        if callable(obj) and getattr(obj, "__khaos_test__", False):
            tests.append(
                DiscoveredTest(
                    name=attr_name,
                    module_path=filepath,
                    fn=obj,
                    config=obj.__khaos_test_config__,
                    mode=getattr(obj, "__khaos_test_mode__", "declarative"),
                )
            )
    return tests


# ---------------------------------------------------------------------------
# Agent resolution
# ---------------------------------------------------------------------------

def resolve_agent(name: str) -> Callable[..., Any] | None:
    """Find an ``@khaosagent``-decorated function by its registered name.

    Uses :func:`khaos.agent_discovery.scan_agents` on the current working
    directory, then imports the matching module and returns the decorated
    callable.
    """
    from khaos.agent_discovery import scan_agents

    discovered = scan_agents(Path.cwd())
    for agent in discovered:
        if agent.metadata.name == name:
            return _import_agent_callable(agent.entrypoint, name)
    return None


def _import_agent_callable(entrypoint: Path, name: str) -> Callable[..., Any] | None:
    """Import *entrypoint* and find the function with ``__khaos_name__ == name``."""
    module_name = f"_khaos_agent_{entrypoint.stem}_{id(entrypoint)}"
    spec = importlib.util.spec_from_file_location(module_name, entrypoint)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    parent = str(entrypoint.parent)
    added = parent not in sys.path
    if added:
        sys.path.insert(0, parent)
    try:
        spec.loader.exec_module(module)
    except Exception:
        return None
    finally:
        if added and parent in sys.path:
            sys.path.remove(parent)

    for attr_name in dir(module):
        obj = getattr(module, attr_name, None)
        if callable(obj) and getattr(obj, "__khaos_name__", None) == name:
            return obj
    return None


# ---------------------------------------------------------------------------
# Fault / attack resolution
# ---------------------------------------------------------------------------

def resolve_faults(fault_specs: list[str | dict[str, Any]]) -> list[dict[str, Any]]:
    """Resolve fault specifications to concrete config dicts.

    Strings are looked up in the built-in fault registry; dicts pass through.
    """
    from khaos.engine.fault_registry import is_known_fault_type

    resolved: list[dict[str, Any]] = []
    for spec in fault_specs:
        if isinstance(spec, str):
            if not is_known_fault_type(spec):
                raise ValueError(f"Unknown fault type: {spec!r}")
            resolved.append({"type": spec})
        elif isinstance(spec, dict):
            ft = spec.get("type")
            if ft and not is_known_fault_type(str(ft)):
                raise ValueError(f"Unknown fault type: {ft!r}")
            resolved.append(spec)
        else:
            raise TypeError(f"Invalid fault spec: {spec!r}")
    return resolved


def resolve_attacks(
    attack_specs: list[str | dict[str, Any]],
) -> list[Any]:
    """Resolve attack specifications to :class:`SecurityAttack` objects.

    Strings are matched against tier names, categories, or individual IDs in
    the attack registry.  Dicts are treated as custom attack definitions.
    """
    from khaos.evaluator.attack_registry import get_attack_registry
    from khaos.security.models import (
        AttackTier,
        AttackType,
        SecurityAttack,
    )

    registry = get_attack_registry()
    result: list[SecurityAttack] = []

    for spec in attack_specs:
        if isinstance(spec, dict):
            result.append(
                SecurityAttack(
                    attack_id=spec.get("name", "custom"),
                    name=spec.get("name", "Custom Attack"),
                    attack_type=AttackType(spec.get("type", "prompt_injection")),
                    payload=spec.get("payload", ""),
                    injection_vector=spec.get("injection_vector", "direct"),
                    expected_behavior=spec.get("expected_behavior", "Should be blocked"),
                    metadata={"severity": spec.get("severity", "medium")},
                )
            )
            continue

        if not isinstance(spec, str):
            raise TypeError(f"Invalid attack spec: {spec!r}")

        # Try tier name
        spec_lower = spec.lower()
        try:
            tier = AttackTier(spec_lower)
            for meta in registry.by_tier(tier):
                result.append(_attack_from_meta(meta))
            continue
        except ValueError:
            pass

        # Try category
        by_cat = registry.by_category(spec_lower)
        if by_cat:
            for meta in by_cat:
                result.append(_attack_from_meta(meta))
            continue

        # Try individual ID / search
        meta = registry.get(spec)
        if meta is not None:
            result.append(_attack_from_meta(meta))
            continue

        # Fuzzy search as last resort
        matches = registry.search(spec)
        if matches:
            for m in matches:
                result.append(_attack_from_meta(m))
            continue

        raise ValueError(f"Unknown attack spec: {spec!r}")

    return result


def _attack_from_meta(meta: Any) -> Any:
    """Build a minimal SecurityAttack from an AttackMetadata object."""
    from khaos.security.models import AttackType, SecurityAttack

    return SecurityAttack(
        attack_id=meta.attack_id,
        name=meta.name,
        attack_type=AttackType(meta.attack_type),
        payload="",
        injection_vector=meta.injection_vector,
        expected_behavior=meta.description,
        metadata={"severity": meta.severity},
    )


# ---------------------------------------------------------------------------
# Shim activation
# ---------------------------------------------------------------------------

def activate_shims(config: Any) -> dict[str, str]:
    """Set environment variables so the auto-wrap shim picks up faults.

    Returns a dict of *env vars that were set* so the caller can restore them.
    """
    saved: dict[str, str] = {}

    if config.faults:
        import json as _json

        saved["KHAOS_AUTO_WRAP"] = os.environ.get("KHAOS_AUTO_WRAP", "")
        saved["KHAOS_FAULTS"] = os.environ.get("KHAOS_FAULTS", "")
        os.environ["KHAOS_AUTO_WRAP"] = "1"
        os.environ["KHAOS_FAULTS"] = _json.dumps(
            resolve_faults(config.faults),
        )

    return saved


def deactivate_shims(saved: dict[str, str]) -> None:
    """Restore environment variables saved by :func:`activate_shims`."""
    for key, value in saved.items():
        if value:
            os.environ[key] = value
        else:
            os.environ.pop(key, None)


# ---------------------------------------------------------------------------
# Execution engine
# ---------------------------------------------------------------------------

def run_tests(
    tests: list[DiscoveredTest],
    *,
    verbose: bool = False,
    fail_fast: bool = False,
    timeout_ms: int = 30_000,
    on_result: Callable[[DiscoveredTest, TestResult], None] | None = None,
) -> TestSummary:
    """Execute all discovered tests and collect results.

    Args:
        on_result: Optional callback fired after each test completes,
            receiving the test and its result. Used by the CLI for live
            progress updates.
    """
    summary = TestSummary()

    for test in tests:
        effective_timeout = test.config.timeout_ms or timeout_ms
        result = _run_single_test(test, verbose=verbose, timeout_ms=effective_timeout)
        summary.results.append(result)
        if on_result is not None:
            on_result(test, result)
        if fail_fast and not result.passed:
            break

    return summary


class _TestTimeoutError(Exception):
    """Raised when a test exceeds its timeout."""


def _run_single_test(
    test: DiscoveredTest,
    *,
    verbose: bool = False,
    timeout_ms: int = 30_000,
) -> TestResult:
    config = test.config
    agent_name = config.agent

    # Resolve agent
    agent_fn = resolve_agent(agent_name) if agent_name else None

    # Activate shims
    saved = activate_shims(config)

    start = time.perf_counter()
    try:
        _execute_with_timeout(test, agent_fn, timeout_ms)

        # Check min_score (declarative mode with attacks)
        if config.min_score is not None:
            _check_min_score(test, agent_fn, config.min_score)

        elapsed = (time.perf_counter() - start) * 1000
        return TestResult(
            name=test.name,
            agent=agent_name,
            passed=True,
            duration_ms=elapsed,
        )
    except AssertionError as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return TestResult(
            name=test.name,
            agent=agent_name,
            passed=False,
            duration_ms=elapsed,
            error=str(exc) or "Assertion failed",
            traceback=traceback.format_exc() if verbose else None,
        )
    except _TestTimeoutError:
        elapsed = (time.perf_counter() - start) * 1000
        return TestResult(
            name=test.name,
            agent=agent_name,
            passed=False,
            duration_ms=elapsed,
            error=f"Test timed out after {timeout_ms}ms",
        )
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return TestResult(
            name=test.name,
            agent=agent_name,
            passed=False,
            duration_ms=elapsed,
            error=f"{type(exc).__name__}: {exc}",
            traceback=traceback.format_exc() if verbose else None,
        )
    finally:
        deactivate_shims(saved)


def _execute_with_timeout(
    test: DiscoveredTest,
    agent_fn: Callable[..., Any] | None,
    timeout_ms: int,
) -> None:
    """Run the test body with a thread-based timeout."""

    def _target() -> None:
        if test.mode == "imperative":
            if agent_fn is None:
                raise RuntimeError(
                    f"Agent {test.config.agent!r} not found. "
                    "Run `khaos discover` to register agents."
                )
            client = AgentTestClient(agent_fn, test.config)
            test.fn(agent=client)
        else:
            _run_declarative(test, agent_fn)

    timeout_s = timeout_ms / 1000.0
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = pool.submit(_target)
    try:
        future.result(timeout=timeout_s)
    except concurrent.futures.TimeoutError:
        pool.shutdown(wait=False, cancel_futures=True)
        raise _TestTimeoutError() from None
    else:
        pool.shutdown(wait=False)


def _check_min_score(
    test: DiscoveredTest,
    agent_fn: Callable[..., Any] | None,
    min_score: float,
) -> None:
    """Enforce ``min_score`` by running attacks and computing a block rate."""
    config = test.config
    if not config.attacks or agent_fn is None:
        return

    attacks = resolve_attacks(config.attacks)
    client = AgentTestClient(agent_fn, config)
    blocked = 0
    for attack in attacks:
        resp = client(attack.payload)
        if not resp.success:
            blocked += 1

    score = blocked / len(attacks) if attacks else 1.0
    if score < min_score:
        raise AssertionError(
            f"Score {score:.0%} below min_score {min_score:.0%} "
            f"({blocked}/{len(attacks)} attacks blocked)"
        )


def _run_declarative(test: DiscoveredTest, agent_fn: Callable[..., Any] | None) -> None:
    """Execute a declarative test (no ``agent`` parameter).

    The framework drives the agent with configured inputs, faults, and
    attacks and asserts basic success criteria.
    """
    config = test.config

    if agent_fn is None and not config.attacks:
        raise RuntimeError(
            f"Agent {config.agent!r} not found and no attacks configured. "
            "Run `khaos discover` to register agents."
        )

    # Run inputs through the agent
    if agent_fn is not None:
        client = AgentTestClient(agent_fn, config)
        inputs = config.inputs or ["Hello, how are you?"]
        for inp in inputs:
            prompt = inp if isinstance(inp, str) else inp.get("text", str(inp))
            resp = client(prompt)
            if not resp.success and resp.error:
                raise AssertionError(
                    f"Agent returned error for input {prompt!r}: {resp.error}"
                )

    # Run attacks if configured
    if config.attacks:
        attacks = resolve_attacks(config.attacks)
        if agent_fn is not None:
            client = AgentTestClient(agent_fn, config)
            for attack in attacks:
                resp = client(attack.payload)
                if config.expect_blocked is True and resp.success:
                    raise AssertionError(
                        f"Attack {attack.name!r} was not blocked — "
                        f"agent responded with: {resp.text[:200]}"
                    )


def filter_tests(
    tests: list[DiscoveredTest],
    pattern: str,
) -> list[DiscoveredTest]:
    """Filter tests by name or tag pattern (supports ``*`` globs)."""
    if not pattern:
        return tests

    filtered: list[DiscoveredTest] = []
    for t in tests:
        # Match against test name
        if pattern in t.name or fnmatch(t.name, f"*{pattern}*"):
            filtered.append(t)
            continue
        # Match against tags
        tags = getattr(t.config, "tags", [])
        if any(pattern in tag or fnmatch(tag, f"*{pattern}*") for tag in tags):
            filtered.append(t)
    return filtered


__all__ = [
    "DiscoveredTest",
    "TestResult",
    "TestSummary",
    "discover_tests",
    "filter_tests",
    "resolve_agent",
    "resolve_attacks",
    "resolve_faults",
    "run_tests",
]
