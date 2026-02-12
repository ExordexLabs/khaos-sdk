#!/usr/bin/env python3
"""Minimal agent used for smoke tests.

Reads JSON messages from stdin and echoes them back with a simple payload.
"""

from __future__ import annotations

import json
import sys


def main() -> None:
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response = {
                "name": "agent-error",
                "payload": {"error": "invalid json"},
            }
        else:
            response = {
                "name": "agent-response",
                "payload": {
                    "event": message.get("name", "unknown"),
                    "payload": message.get("payload", {}),
                },
            }
        print(json.dumps(response))
        sys.stdout.flush()


if __name__ == "__main__":
    main()
