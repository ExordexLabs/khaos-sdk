"""Sidecar mode for container deployments.

Provides a standalone telemetry collection process that can
run alongside the main application in K8s/Docker environments.

Deployment patterns:
1. K8s sidecar container
2. Docker Compose service
3. Standalone process

The sidecar:
- Receives telemetry via local socket/file
- Batches and forwards to the Khaos API
- Handles retries and buffering
- Provides health endpoints
"""

from __future__ import annotations

import json
import os
import signal
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from khaos.server.collector import CollectorConfig, BackgroundCollector

_DEFAULT_SOCKET_PATH = "/tmp/khaos.sock"


@dataclass
class SidecarConfig:
    """Configuration for sidecar mode."""

    # Unix socket path for local communication
    socket_path: str = os.environ.get("KHAOS_SOCKET_PATH", _DEFAULT_SOCKET_PATH)

    # TCP port for local communication (alternative to socket)
    tcp_port: int | None = None

    # Health check port
    health_port: int = 9090

    # Collector configuration
    collector: CollectorConfig = field(default_factory=CollectorConfig)

    # Process management
    pid_file: str | None = None

    # Logging
    log_file: str | None = None
    log_level: str = "INFO"

    def to_dict(self) -> dict[str, Any]:
        """Serialize config."""
        return {
            "socket_path": self.socket_path,
            "tcp_port": self.tcp_port,
            "health_port": self.health_port,
            "collector": self.collector.to_dict() if self.collector else {},
            "pid_file": self.pid_file,
            "log_file": self.log_file,
            "log_level": self.log_level,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SidecarConfig":
        """Parse config from dict."""
        collector_data = data.get("collector", {})
        collector = CollectorConfig(
            api_endpoint=collector_data.get("api_endpoint"),
            api_token=collector_data.get("api_token"),
            project_id=collector_data.get("project_id"),
            buffer_file=collector_data.get("buffer_file"),
        )

        return cls(
            socket_path=data.get("socket_path", os.environ.get("KHAOS_SOCKET_PATH", _DEFAULT_SOCKET_PATH)),
            tcp_port=data.get("tcp_port"),
            health_port=data.get("health_port", 9090),
            collector=collector,
            pid_file=data.get("pid_file"),
            log_file=data.get("log_file"),
            log_level=data.get("log_level", "INFO"),
        )

    @classmethod
    def from_env(cls) -> "SidecarConfig":
        """Create config from environment variables."""
        return cls(
            socket_path=os.environ.get("KHAOS_SOCKET_PATH", _DEFAULT_SOCKET_PATH),
            tcp_port=int(os.getenv("KHAOS_TCP_PORT", "0")) or None,
            health_port=int(os.getenv("KHAOS_HEALTH_PORT", "9090")),
            collector=CollectorConfig(
                api_endpoint=os.getenv("KHAOS_API_ENDPOINT"),
                api_token=os.getenv("KHAOS_API_TOKEN"),
                project_id=os.getenv("KHAOS_PROJECT_ID"),
                buffer_file=os.getenv("KHAOS_BUFFER_FILE"),
            ),
            pid_file=os.getenv("KHAOS_PID_FILE"),
            log_file=os.getenv("KHAOS_LOG_FILE"),
            log_level=os.getenv("KHAOS_LOG_LEVEL", "INFO"),
        )


class SidecarProcess:
    """Sidecar process implementation."""

    def __init__(self, config: SidecarConfig):
        self.config = config
        self.collector: BackgroundCollector | None = None
        self._socket: socket.socket | None = None
        self._health_socket: socket.socket | None = None
        self._running = False
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        """Start the sidecar process."""
        import logging

        # Configure logging
        log_handlers: list[logging.Handler] = [logging.StreamHandler()]
        if self.config.log_file:
            log_handlers.append(
                logging.FileHandler(self.config.log_file)
            )

        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=log_handlers,
        )

        logger = logging.getLogger("khaos.sidecar")
        logger.info("Starting Khaos sidecar...")

        # Write PID file
        if self.config.pid_file:
            Path(self.config.pid_file).write_text(str(os.getpid()))

        # Start collector
        self.collector = BackgroundCollector(self.config.collector)
        self.collector.start()
        logger.info("Collector started")

        # Start event listener
        self._running = True
        self._start_event_listener()
        logger.info(f"Event listener started on {self.config.socket_path}")

        # Start health server
        self._start_health_server()
        logger.info(f"Health server started on port {self.config.health_port}")

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        logger.info("Sidecar ready")

    def stop(self) -> None:
        """Stop the sidecar process."""
        import logging
        logger = logging.getLogger("khaos.sidecar")
        logger.info("Stopping sidecar...")

        self._running = False

        # Close sockets
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass

        if self._health_socket:
            try:
                self._health_socket.close()
            except Exception:
                pass

        # Remove socket file
        socket_path = Path(self.config.socket_path)
        if socket_path.exists():
            socket_path.unlink()

        # Stop collector
        if self.collector:
            self.collector.stop()

        # Remove PID file
        if self.config.pid_file:
            pid_path = Path(self.config.pid_file)
            if pid_path.exists():
                pid_path.unlink()

        # Wait for threads
        for thread in self._threads:
            thread.join(timeout=5.0)

        logger.info("Sidecar stopped")

    def run_forever(self) -> None:
        """Run the sidecar until stopped."""
        while self._running:
            time.sleep(1.0)

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Handle shutdown signals."""
        import logging
        logging.getLogger("khaos.sidecar").info(f"Received signal {signum}")
        self.stop()
        sys.exit(0)

    def _start_event_listener(self) -> None:
        """Start the event listener thread."""
        # Remove existing socket
        socket_path = Path(self.config.socket_path)
        if socket_path.exists():
            socket_path.unlink()

        # Create Unix socket
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(self.config.socket_path)
        self._socket.listen(5)
        self._socket.settimeout(1.0)

        # Start listener thread
        thread = threading.Thread(target=self._event_listener_loop, daemon=True)
        thread.start()
        self._threads.append(thread)

    def _event_listener_loop(self) -> None:
        """Event listener main loop."""
        import logging
        logger = logging.getLogger("khaos.sidecar.listener")

        while self._running:
            try:
                conn, _ = self._socket.accept()
                # Handle connection in a thread
                thread = threading.Thread(
                    target=self._handle_connection,
                    args=(conn,),
                    daemon=True,
                )
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.error(f"Listener error: {e}")

    def _handle_connection(self, conn: socket.socket) -> None:
        """Handle a client connection."""
        import logging
        logger = logging.getLogger("khaos.sidecar.handler")

        try:
            conn.settimeout(30.0)
            buffer = b""

            while self._running:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break

                    buffer += data

                    # Process complete messages (newline-delimited JSON)
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if line:
                            try:
                                event = json.loads(line.decode("utf-8"))
                                if self.collector:
                                    self.collector.emit(event)
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON: {e}")

                except socket.timeout:
                    continue

        except Exception as e:
            logger.error(f"Connection handler error: {e}")
        finally:
            conn.close()

    def _start_health_server(self) -> None:
        """Start the health check HTTP server."""
        from http.server import HTTPServer, BaseHTTPRequestHandler

        sidecar = self

        class HealthHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass  # Suppress access logs

            def do_GET(self) -> None:
                if self.path == "/health" or self.path == "/healthz":
                    self._send_health()
                elif self.path == "/ready" or self.path == "/readyz":
                    self._send_ready()
                elif self.path == "/metrics":
                    self._send_metrics()
                else:
                    self.send_error(404)

            def _send_health(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response = {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}
                self.wfile.write(json.dumps(response).encode())

            def _send_ready(self) -> None:
                ready = sidecar.collector is not None and sidecar._running
                status = 200 if ready else 503
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response = {"ready": ready, "timestamp": datetime.now(timezone.utc).isoformat()}
                self.wfile.write(json.dumps(response).encode())

            def _send_metrics(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                stats = sidecar.collector.get_stats() if sidecar.collector else {}
                response = {
                    "collector": stats,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self.wfile.write(json.dumps(response).encode())

        # Run server in thread
        def run_server() -> None:
            server = HTTPServer(("0.0.0.0", self.config.health_port), HealthHandler)
            server.timeout = 1.0
            while self._running:
                server.handle_request()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        self._threads.append(thread)


# Global sidecar instance
_sidecar: SidecarProcess | None = None


def start_sidecar(config: SidecarConfig | None = None) -> SidecarProcess:
    """Start the sidecar process.

    Args:
        config: Sidecar configuration (uses env vars if None)

    Returns:
        Running sidecar process
    """
    global _sidecar

    if _sidecar is not None:
        raise RuntimeError("Sidecar already running")

    if config is None:
        config = SidecarConfig.from_env()

    _sidecar = SidecarProcess(config)
    _sidecar.start()
    return _sidecar


def stop_sidecar() -> None:
    """Stop the global sidecar process."""
    global _sidecar

    if _sidecar is not None:
        _sidecar.stop()
        _sidecar = None


def is_sidecar_running() -> bool:
    """Check if sidecar is running."""
    return _sidecar is not None and _sidecar._running


def send_to_sidecar(
    event: dict[str, Any],
    socket_path: str = os.environ.get("KHAOS_SOCKET_PATH", _DEFAULT_SOCKET_PATH),
) -> bool:
    """Send an event to the sidecar via Unix socket.

    Args:
        event: Event to send
        socket_path: Path to sidecar socket

    Returns:
        True if sent successfully
    """
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(socket_path)
        sock.sendall(json.dumps(event).encode() + b"\n")
        sock.close()
        return True
    except Exception:
        return False


def main() -> None:
    """Main entry point for sidecar process."""
    config = SidecarConfig.from_env()
    sidecar = start_sidecar(config)
    sidecar.run_forever()


if __name__ == "__main__":
    main()
