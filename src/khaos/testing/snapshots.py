from __future__ import annotations

import difflib
import json
from pathlib import Path

from khaos.testing.client import AgentResponse

__all__ = ["assert_response_matches_snapshot", "SNAPSHOT_DIR"]

SNAPSHOT_DIR = Path(".khaos_snapshots")


def assert_response_matches_snapshot(
    response: AgentResponse,
    snapshot_id: str,
    *,
    update: bool = False,
    tolerance: float = 0.0,
) -> None:
    snapshot_path = SNAPSHOT_DIR / f"{snapshot_id}.json"

    current = {
        "success": response.success,
        "text": response.text,
        "error": response.error,
    }

    if not snapshot_path.exists() or update:
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text(json.dumps(current, indent=2) + "\n")
        return

    stored = json.loads(snapshot_path.read_text())

    if stored["success"] != current["success"]:
        raise AssertionError(
            f"Snapshot '{snapshot_id}' mismatch on 'success': "
            f"expected {stored['success']}, got {current['success']}"
        )

    if stored["error"] != current["error"]:
        raise AssertionError(
            f"Snapshot '{snapshot_id}' mismatch on 'error': "
            f"expected {stored['error']!r}, got {current['error']!r}"
        )

    stored_text = stored["text"]
    actual_text = current["text"]

    if tolerance > 0.0:
        ratio = difflib.SequenceMatcher(None, stored_text, actual_text).ratio()
        if ratio < (1.0 - tolerance):
            raise AssertionError(
                f"Snapshot '{snapshot_id}' text similarity {ratio:.4f} "
                f"is below threshold {1.0 - tolerance:.4f}\n"
                f"Expected:\n{stored_text}\n\nActual:\n{actual_text}"
            )
    else:
        if stored_text != actual_text:
            diff = "\n".join(
                difflib.unified_diff(
                    stored_text.splitlines(),
                    actual_text.splitlines(),
                    fromfile="expected",
                    tofile="actual",
                    lineterm="",
                )
            )
            raise AssertionError(
                f"Snapshot '{snapshot_id}' text mismatch:\n{diff}"
            )
