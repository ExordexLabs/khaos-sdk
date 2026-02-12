#!/usr/bin/env python3
"""Minimal decorator-based agent example for first-time users.

This file intentionally does NOT implement stdin/stdout protocol. Khaos will detect the
`@khaos_agent` handler and run it via `khaos.agent_runner` automatically.
"""

from __future__ import annotations

from khaos import khaos_agent


@khaos_agent
def handle(message: dict) -> dict:
    name = message.get("name", "unknown")
    payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
    # Always return a stable envelope payload so the Release suite can run deterministically.
    return {"status": "ok", "event": name, "observed": sorted(payload.keys())}

