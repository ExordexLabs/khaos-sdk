"""Background telemetry collection.

Provides non-blocking event emission to avoid impacting
request latency in production environments.
"""

from __future__ import annotations

import asyncio
import atexit
import json
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Callable

from khaos.server.instrumentation import RequestContext

@dataclass
class CollectorConfig:
    """Configuration for background collector."""

    # Maximum events to buffer before dropping
    max_buffer_size: int = 10000

    # Batch size for sending events
    batch_size: int = 100

    # Flush interval in seconds
    flush_interval_seconds: float = 5.0

    # API endpoint for telemetry
    api_endpoint: str | None = None

    # API token for authentication
    api_token: str | None = None

    # Project ID for telemetry
    project_id: str | None = None

    # Local file for buffering (if API unavailable)
    buffer_file: str | None = None

    # Whether to log dropped events
    log_drops: bool = True

    # Maximum retries for failed sends
    max_retries: int = 3

    # Retry backoff in seconds
    retry_backoff_seconds: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize config."""
        return {
            "max_buffer_size": self.max_buffer_size,
            "batch_size": self.batch_size,
            "flush_interval_seconds": self.flush_interval_seconds,
            "api_endpoint": self.api_endpoint,
            "project_id": self.project_id,
            "buffer_file": self.buffer_file,
            "log_drops": self.log_drops,
            "max_retries": self.max_retries,
            "retry_backoff_seconds": self.retry_backoff_seconds,
        }

class BackgroundCollector:
    """Non-blocking telemetry collector.

    Uses a background thread to batch and send events
    without blocking the main request handling.
    """

    def __init__(self, config: CollectorConfig):
        self.config = config
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(
            maxsize=config.max_buffer_size
        )
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._started = False
        self._dropped_count = 0
        self._sent_count = 0
        self._error_count = 0

    def start(self) -> None:
        """Start the background collector thread."""
        if self._started:
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._started = True

        # Register shutdown hook
        atexit.register(self.stop)

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the collector and flush remaining events."""
        if not self._started:
            return

        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

        # Final flush
        self._flush_remaining()
        self._started = False

    def emit(self, event: dict[str, Any]) -> bool:
        """Emit an event to the collector.

        Non-blocking - drops events if buffer is full.

        Args:
            event: Event data to emit

        Returns:
            True if event was queued, False if dropped
        """
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            self._dropped_count += 1
            if self.config.log_drops:
                import logging
                logging.getLogger("khaos.collector").warning(
                    f"Event dropped (buffer full), total dropped: {self._dropped_count}"
                )
            return False

    def emit_request(self, ctx: RequestContext) -> bool:
        """Emit a request context as telemetry.

        Args:
            ctx: Request context to emit

        Returns:
            True if queued, False if dropped
        """
        event = {
            "type": "request",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": ctx.to_dict(),
        }
        return self.emit(event)

    def emit_llm_call(self, call_data: dict[str, Any]) -> bool:
        """Emit an LLM call event.

        Args:
            call_data: LLM call data

        Returns:
            True if queued, False if dropped
        """
        event = {
            "type": "llm_call",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": call_data,
        }
        return self.emit(event)

    def emit_error(self, error: Exception, context: str = "") -> bool:
        """Emit an error event.

        Args:
            error: Exception to emit
            context: Additional context

        Returns:
            True if queued, False if dropped
        """
        event = {
            "type": "error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "error_type": type(error).__name__,
                "message": str(error),
                "context": context,
            },
        }
        return self.emit(event)

    def get_stats(self) -> dict[str, Any]:
        """Get collector statistics."""
        return {
            "queued": self._queue.qsize(),
            "sent": self._sent_count,
            "dropped": self._dropped_count,
            "errors": self._error_count,
            "running": self._started,
        }

    def _run_loop(self) -> None:
        """Background thread main loop."""
        batch: list[dict[str, Any]] = []
        last_flush = time.monotonic()

        while not self._stop_event.is_set():
            try:
                # Collect events with timeout
                try:
                    event = self._queue.get(timeout=0.1)
                    batch.append(event)
                except queue.Empty:
                    pass

                # Check if we should flush
                now = time.monotonic()
                should_flush = (
                    len(batch) >= self.config.batch_size or
                    (now - last_flush) >= self.config.flush_interval_seconds
                )

                if should_flush and batch:
                    self._send_batch(batch)
                    batch = []
                    last_flush = now

            except Exception as e:
                self._error_count += 1
                import logging
                logging.getLogger("khaos.collector").error(
                    f"Collector loop error: {e}"
                )

    def _flush_remaining(self) -> None:
        """Flush any remaining events in the queue."""
        batch: list[dict[str, Any]] = []
        while True:
            try:
                event = self._queue.get_nowait()
                batch.append(event)
            except queue.Empty:
                break

        if batch:
            self._send_batch(batch)

    def _send_batch(self, batch: list[dict[str, Any]]) -> None:
        """Send a batch of events."""
        if not batch:
            return

        # Try API first
        if self.config.api_endpoint:
            success = self._send_to_api(batch)
            if success:
                self._sent_count += len(batch)
                return

        # Fall back to local file
        if self.config.buffer_file:
            self._write_to_file(batch)
            self._sent_count += len(batch)
            return

        # No destination configured - just count as sent
        self._sent_count += len(batch)

    def _send_to_api(self, batch: list[dict[str, Any]]) -> bool:
        """Send batch to API endpoint."""
        if not self.config.api_endpoint:
            return False

        import urllib.request
        import urllib.error

        payload = {
            "events": batch,
            "project_id": self.config.project_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        headers = {
            "Content-Type": "application/json",
        }
        if self.config.api_token:
            headers["Authorization"] = f"Bearer {self.config.api_token}"

        data = json.dumps(payload).encode("utf-8")

        for attempt in range(self.config.max_retries):
            try:
                req = urllib.request.Request(
                    self.config.api_endpoint,
                    data=data,
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.status == 200:
                        return True
            except (urllib.error.URLError, urllib.error.HTTPError) as e:
                if attempt < self.config.max_retries - 1:
                    time.sleep(
                        self.config.retry_backoff_seconds * (attempt + 1)
                    )
                else:
                    self._error_count += 1
                    import logging
                    logging.getLogger("khaos.collector").error(
                        f"Failed to send to API after {self.config.max_retries} attempts: {e}"
                    )

        return False

    def _write_to_file(self, batch: list[dict[str, Any]]) -> None:
        """Write batch to local file."""
        if not self.config.buffer_file:
            return

        path = Path(self.config.buffer_file)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("a") as f:
            for event in batch:
                f.write(json.dumps(event) + "\n")

# Global collector instance
_collector: BackgroundCollector | None = None

def get_collector() -> BackgroundCollector | None:
    """Get the global collector instance."""
    return _collector

def set_collector(collector: BackgroundCollector | None) -> None:
    """Set the global collector instance."""
    global _collector
    _collector = collector

def configure_collector(config: CollectorConfig) -> BackgroundCollector:
    """Configure and start the global collector.

    Args:
        config: Collector configuration

    Returns:
        Configured and started collector
    """
    collector = BackgroundCollector(config)
    collector.start()
    set_collector(collector)
    return collector

def emit_event(event: dict[str, Any]) -> bool:
    """Emit an event using the global collector.

    Args:
        event: Event to emit

    Returns:
        True if queued, False if dropped or no collector
    """
    collector = get_collector()
    if collector is None:
        return False
    return collector.emit(event)

def flush_events(timeout: float = 5.0) -> None:
    """Flush all pending events.

    Args:
        timeout: Maximum time to wait
    """
    collector = get_collector()
    if collector:
        collector.stop(timeout)
        collector.start()  # Restart for future events
