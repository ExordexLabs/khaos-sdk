"""Evaluation packs for standardized agent testing.

Packs provide curated scenario collections with:
- Canonical inputs for cross-agent comparison
- Three-phase evaluation: baseline → resilience → security
- Versioned, reproducible test configurations

Quick Start (CLI):
    khaos run agent.py --pack quickstart
    khaos list-packs

Programmatic Usage:
    from khaos.packs import get_builtin_pack, PackRunner

    def my_agent(prompt: str) -> str:
        # Your agent logic here
        return response

    pack = get_builtin_pack("quickstart")
    runner = PackRunner(my_agent, agent_name="my-agent")
    result = runner.run_pack(pack)

    print(f"Overall Score: {result.report.overall_score}")
    print(result.report.to_json())

Available Packs:
    - baseline: Pure observation (~1 min)
    - quickstart: Fast dev iteration (~2 min)
    - full-eval: Production readiness (~10-15 min)
    - security: Deep security testing (~5-8 min)

See docs/evaluation-packs.md for complete documentation.
"""

from .schema import (
    Pack,
    PackPhase,
    PackInput,
    PackMessage,  # Multi-turn message
    GoalCriteria,
    PackExpectation,  # Alias for GoalCriteria (backwards compat)
    FaultConfig,
    PhaseType,
    Difficulty,
    load_pack,
    get_builtin_pack,
    list_builtin_packs,
)
from .runner import (
    PackRunner,
    PhaseResult,
    EvaluationResult,
    run_pack,
    TurnResult,
    RunResult,
    MultiTurnInvoker,
    AgentInvoker,
)
from .contract import (
    EvaluationReport,
    BaselineMetrics,
    ResilienceMetrics,
    SecurityMetrics,
    FaultCoverage,
    AgentInfo,
    InputResult,
    TurnResultDetail,
)
from .smart_generator import (
    PackIntent,
    SmartPackConfig,
    generate_smart_pack,
    get_pack_preview,
    format_preview_for_display,
)

__all__ = [
    # Schema
    "Pack",
    "PackPhase",
    "PackInput",
    "PackMessage",
    "GoalCriteria",
    "PackExpectation",  # Alias for backwards compatibility
    "FaultConfig",
    "PhaseType",
    "Difficulty",
    "load_pack",
    "get_builtin_pack",
    "list_builtin_packs",
    # Runner
    "PackRunner",
    "PhaseResult",
    "EvaluationResult",
    "run_pack",
    "TurnResult",
    "RunResult",
    "MultiTurnInvoker",
    "AgentInvoker",
    # Contract
    "EvaluationReport",
    "BaselineMetrics",
    "ResilienceMetrics",
    "SecurityMetrics",
    "FaultCoverage",
    "AgentInfo",
    "InputResult",
    "TurnResultDetail",
    # Smart Generator
    "PackIntent",
    "SmartPackConfig",
    "generate_smart_pack",
    "get_pack_preview",
    "format_preview_for_display",
]
