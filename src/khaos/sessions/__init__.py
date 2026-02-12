"""Session & Trace Model for Khaos.

Provides rich, conversation-aware telemetry with:
- Session grouping of LLM calls
- Turn boundary detection
- Message history tracking
- Cost calculation
- OpenTelemetry-compatible export

Example usage:
    from khaos.sessions import Session, SessionCollector

    # Collect events into a session
    collector = SessionCollector()
    session = collector.from_events(events)

    # Get session metrics
    print(f"Total cost: ${session.total_cost_usd:.4f}")
    print(f"Turns: {session.turn_count}")

    # Export to OpenTelemetry format
    from khaos.sessions.otlp import to_otlp_traces
    traces = to_otlp_traces(session)
"""

from khaos.sessions.models import (
    LLMCall,
    Message,
    Session,
    SessionMetrics,
    Turn,
)
from khaos.sessions.collector import (
    SessionCollector,
    collect_session,
)
from khaos.sessions.costs import (
    calculate_session_cost,
    get_model_pricing,
)

__all__ = [
    # Models
    "Session",
    "SessionMetrics",
    "Turn",
    "LLMCall",
    "Message",
    # Collector
    "SessionCollector",
    "collect_session",
    # Costs
    "calculate_session_cost",
    "get_model_pricing",
]
